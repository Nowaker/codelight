from __future__ import annotations

import json
import math
import os
import tempfile
import threading
import time
from typing import NotRequired, TypedDict
from codelight_core.boot_epoch import BootIdentityUnavailable, boot_identity
from codelight_core.power_diagnostics import parse_scope_diagnostics

from codelight_core.power_authority import (
    AuthorityState,
    PowerAuthoritySnapshot,
    ProviderAuthority,
)


DEFAULT_MAX_AGE = 45.0


class PowerStatus(PowerAuthoritySnapshot):
    observedAt: float
    bootId: NotRequired[str]


def unavailable_status(reason: str) -> PowerStatus:
    return {
        "state": "unknown",
        "reason": reason,
        "providers": {},
        "observedAt": 0.0,
    }


class PowerStatusPublisher:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        try:
            self._boot_id = boot_identity()
        except BootIdentityUnavailable:
            self._boot_id = ""

    def publish(
        self,
        snapshot: PowerAuthoritySnapshot,
        *,
        observed_at: float | None = None,
    ) -> None:
        payload: PowerStatus = {
            **snapshot,
            "bootId": self._boot_id,
            "observedAt": time.time() if observed_at is None else observed_at,
        }
        directory = os.path.dirname(self._path)
        os.makedirs(directory, exist_ok=True)
        with self._lock:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                prefix=".power-status.",
                delete=False,
            ) as stream:
                json.dump(payload, stream, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
                temporary_path = stream.name
            os.replace(temporary_path, self._path)


def _parse_state(value: object) -> AuthorityState | None:
    match value:
        case "active":
            return "active"
        case "idle":
            return "idle"
        case "unknown":
            return "unknown"
        case _:
            return None


def _aggregate_state(
    providers: dict[str, ProviderAuthority],
) -> AuthorityState:
    states = {provider["state"] for provider in providers.values()}
    if "active" in states:
        return "active"
    if "unknown" in states or not providers:
        return "unknown"
    return "idle"


def read_power_status(
    path: str,
    *,
    now: float | None = None,
    max_age: float = DEFAULT_MAX_AGE,
) -> PowerStatus:
    try:
        with open(path, encoding="utf-8") as stream:
            data = json.load(stream)
    except FileNotFoundError:
        return unavailable_status("status-file-missing")
    except (OSError, json.JSONDecodeError):
        return unavailable_status("status-file-unreadable")

    if not isinstance(data, dict):
        return unavailable_status("status-file-invalid")
    state = _parse_state(data.get("state"))
    reason_value = data.get("reason")
    if state is None or not isinstance(reason_value, str) or not reason_value:
        return unavailable_status("status-file-invalid")
    observed_value = data.get("observedAt")
    if (
        isinstance(observed_value, bool)
        or not isinstance(observed_value, (int, float))
        or not math.isfinite(observed_value)
    ):
        return unavailable_status("status-file-invalid")
    observed_at = float(observed_value)
    current_time = time.time() if now is None else now
    if observed_at > current_time:
        return unavailable_status("status-file-future")
    if observed_at <= 0 or current_time - observed_at > max_age:
        return unavailable_status("status-file-stale")
    providers_value = data.get("providers")
    if not isinstance(providers_value, dict):
        return unavailable_status("status-file-invalid")
    providers: dict[str, ProviderAuthority] = {}
    for agent_id, provider_value in providers_value.items():
        if not agent_id or not isinstance(agent_id, str) or not isinstance(provider_value, dict):
            return unavailable_status("status-file-invalid")
        provider_state = _parse_state(provider_value.get("state"))
        active_value = provider_value.get("activeSessions")
        if (
            provider_state is None
            or isinstance(active_value, bool)
            or not isinstance(active_value, int)
            or active_value < 0
            or (provider_state == "active") != (active_value > 0)
        ):
            return unavailable_status("status-file-invalid")
        providers[agent_id] = {
            "state": provider_state,
            "activeSessions": active_value,
        }
        reasons = provider_value.get("reasons")
        if isinstance(reasons, list) and all(isinstance(reason, str) for reason in reasons):
            providers[agent_id]["reasons"] = reasons
    if state != _aggregate_state(providers):
        return unavailable_status("status-file-invalid")
    try:
        current_boot = boot_identity()
    except BootIdentityUnavailable:
        return unavailable_status("boot-identity-unavailable")
    if data.get("bootId") != current_boot:
        return unavailable_status("status-boot-mismatch")
    raw_scopes = data.get("scopes", [])
    scopes = parse_scope_diagnostics(raw_scopes) if isinstance(raw_scopes, list) else None
    if scopes is None:
        return unavailable_status("status-file-invalid")
    return {
        "state": state,
        "reason": reason_value,
        "providers": providers,
        "observedAt": observed_at,
        "bootId": current_boot,
        "scopes": scopes,
    }
