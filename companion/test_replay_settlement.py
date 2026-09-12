import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import codelight
from codelight_core.lifecycle import ProcessIdentity, authority_scope_key, process_generation_key
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState


class ReplaySettlementTests(unittest.TestCase):
    def restored(self, *, silent_producer: bool = False, complete: bool = True) -> CodelightState:
        with tempfile.TemporaryDirectory() as directory:
            store = LifecycleEvidenceStore(str(Path(directory) / "evidence.sqlite3"))
            epoch = store.boot_id
            assert epoch is not None
            identities = tuple(ProcessIdentity(
                pid=pid, ppid=1, started_at=f"generation:{pid}", executable="/bin/opencode",
                command="opencode", boot_id=epoch,
            ) for pid in (100, 200, 300))
            state = CodelightState(default_agent_id="opencode", agent_registry={},
                                   idle_window=60, idle_window_waiting=60)
            state.set_enabled_agents({"opencode"})
            base = time.monotonic_ns() - 1_000_000
            for identity in identities[:2]:
                state.update_provider_snapshot(
                    (), agent_id="opencode", complete=True, observed_at=time.time(),
                    order_token=base, authority_scope=authority_scope_key("opencode", identity, ""),
                    authority_generation=process_generation_key("opencode", identity),
                )
            state.update_provider_snapshot(
                (), agent_id="opencode", complete=False, observed_at=time.time(),
                order_token=base + 10, authority_scope="unresolved:opencode",
            )
            store.invalidate_agent("opencode", base + 10)
            for identity in identities[:2]:
                store.record_snapshot(
                    agent_id="opencode", identity=identity, sessions=(), complete=complete,
                    observed_at=time.time(), order_token=base + 20,
                )
            live = identities if silent_producer else identities[:2]
            with (
                mock.patch.object(codelight, "_state", state),
                mock.patch.object(codelight, "_lifecycle_evidence_store", store),
                mock.patch.object(codelight._agent_process_probe, "identities",
                                  return_value={"opencode": frozenset(live)}),
            ):
                codelight._restore_lifecycle_evidence({"opencode"})
            return state

    def test_recovered_durable_snapshots_retire_unresolved_in_same_restore(self):
        snapshot = self.restored().power_authority_snapshot()
        self.assertEqual(snapshot["state"], "idle")
        self.assertFalse(any(scope["scope"] == "unresolved:opencode" for scope in snapshot.get("scopes", [])))

    def test_unreported_live_producer_keeps_unresolved_unknown(self):
        self.assertEqual(self.restored(silent_producer=True).power_authority_snapshot()["state"], "unknown")

    def test_incomplete_snapshot_keeps_unresolved_unknown(self):
        self.assertEqual(self.restored(complete=False).power_authority_snapshot()["state"], "unknown")
