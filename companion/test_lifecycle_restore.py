import os
import tempfile
import time
import unittest
from unittest import mock

import codelight
from codelight_core.evidence_order import ACTIVE_RANK, evidence_order
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import (
    LifecycleReplay,
    LifecycleEvidenceStore,
    StoredProviderEvidence,
    StoredSessionEvidence,
)
from codelight_core.lifecycle_evidence_invalidation import ScopeWrite
from codelight_core.state import CodelightState


def process(
    pid: int,
    ppid: int,
    executable: str,
    *,
    started_at: str = "darwin:1788076913:123456",
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        ppid=ppid,
        started_at=started_at,
        executable=executable,
        command=executable,
    )


class RestartRestoreTests(unittest.TestCase):
    def state(self):
        state = CodelightState(
            default_agent_id="codex",
            agent_registry={"codex": {"display": "Codex"}},
            idle_window=600,
            idle_window_waiting=30,
            agent_process_states=lambda agent_ids: {
                agent_id: True for agent_id in agent_ids
            },
        )
        state.set_enabled_agents({"codex"})
        return state

    def restore(self, state, provider):
        self.restore_many(state, (provider,))

    def restore_many(self, state, providers):
        live = {
            "codex": frozenset(provider.identity for provider in providers)
        }
        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                return_value=live,
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "replay_inventory",
                return_value=LifecycleReplay(providers, frozenset()),
            ),
        ):
            codelight._restore_lifecycle_evidence({"codex"})

    def test_same_process_completion_restores_idle(self):
        state = self.state()
        provider = StoredProviderEvidence(
            agent_id="codex",
            identity=process(100, 1, "/opt/homebrew/bin/codex"),
            scope_id="",
            observed_at=100.0,
            order_token=time.monotonic_ns(),
            lease_deadline_ns=9_223_372_036_854_775_807,
            sessions=(),
            complete=True,
        )

        self.restore(state, provider)

        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_stale_active_evidence_restores_unknown(self):
        state = self.state()
        provider = StoredProviderEvidence(
            agent_id="codex",
            identity=process(100, 1, "/opt/homebrew/bin/codex"),
            scope_id="",
            observed_at=100.0,
            order_token=1,
            lease_deadline_ns=9_223_372_036_854_775_807,
            sessions=(StoredSessionEvidence(
                session_id="session-1",
                state="working",
                observed_at=0.0,
                order_token=1,
                hook_event="UserPromptSubmit",
            ),),
            complete=True,
        )

        self.restore(state, provider)

        snapshot = state.power_authority_snapshot()
        self.assertEqual(snapshot["state"], "unknown")
        self.assertEqual(snapshot["reason"], "stale-session-evidence")

    def test_older_replay_does_not_overwrite_newer_completion(self):
        state = self.state()
        state.update_session(
            "session-1", "working", agent_id="codex", observed_at=100.0,
            order_token=100)
        state.update_session(
            "session-1", "ended", agent_id="codex", observed_at=200.0,
            order_token=200)

        state.update_session(
            "session-1", "working", agent_id="codex", observed_at=100.0,
            order_token=100)

        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_idle_process_cannot_erase_other_live_process_activity(self):
        state = self.state()
        order = time.monotonic_ns()
        active_identity = process(100, 1, "/opt/homebrew/bin/codex")
        idle_identity = process(
            200,
            1,
            "/opt/homebrew/bin/codex",
            started_at="darwin:1788076914:123456",
        )
        active = StoredProviderEvidence(
            agent_id="codex",
            identity=active_identity,
            scope_id="",
            observed_at=time.time(),
            order_token=order,
            lease_deadline_ns=9_223_372_036_854_775_807,
            sessions=(StoredSessionEvidence(
                session_id="active-session",
                state="working",
                observed_at=time.time(),
                order_token=order,
                hook_event="UserPromptSubmit",
            ),),
            complete=True,
        )
        idle = StoredProviderEvidence(
            agent_id="codex",
            identity=idle_identity,
            scope_id="",
            observed_at=time.time(),
            order_token=order + 1,
            lease_deadline_ns=9_223_372_036_854_775_807,
            sessions=(),
            complete=True,
        )

        self.restore_many(state, (active, idle))

        self.assertEqual(state.power_authority_snapshot()["state"], "active")

    def test_exact_inventory_failure_invalidates_prior_idle(self):
        state = self.state()
        state.update_session("session-1", "ended", agent_id="codex")
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                return_value=None,
            ),
        ):
            codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_exact_absence_clears_unresolved_authority(self):
        state = self.state()
        state.update_session(
            "session-1",
            "idle",
            agent_id="codex",
            authority_scope="unresolved:codex",
            provider_evidence_complete=False,
        )
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                return_value={"codex": frozenset()},
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "replay_inventory",
                return_value=LifecycleReplay((), frozenset()),
            ),
        ):
            codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "idle")

    def test_live_inventory_preserves_newer_unresolved_activity(self):
        state = self.state()
        order = time.monotonic_ns()
        identity = process(100, 1, "/opt/homebrew/bin/codex")
        state.update_session(
            "session-1",
            "working",
            agent_id="codex",
            order_token=order + 1,
            authority_scope="unresolved:codex",
            provider_evidence_complete=False,
        )
        idle = StoredProviderEvidence(
            agent_id="codex",
            identity=identity,
            scope_id="",
            observed_at=time.time(),
            order_token=order,
            lease_deadline_ns=9_223_372_036_854_775_807,
            sessions=(),
            complete=True,
        )

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                return_value={"codex": frozenset({identity})},
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "replay_inventory",
                return_value=LifecycleReplay((idle,), frozenset()),
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "clear_agent_invalidation",
            ) as clear_agent_invalidation,
        ):
            codelight._restore_lifecycle_evidence({"codex"})

        clear_agent_invalidation.assert_not_called()
        self.assertEqual(state.power_authority_snapshot()["state"], "active")

    def test_inventory_scan_does_not_erase_newer_process_activity(self):
        state = self.state()
        inventory_order = time.monotonic_ns()

        def scan_with_concurrent_start(_agent_ids):
            state.update_session(
                "session-new",
                "working",
                agent_id="codex",
                order_token=inventory_order + 1,
                authority_scope="process-new:/repo",
                authority_generation="process-new",
                provider_evidence_complete=True,
                lease_deadline_ns=9_223_372_036_854_775_807,
            )
            return {"codex": frozenset()}

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(
                codelight.time,
                "monotonic_ns",
                return_value=inventory_order,
            ),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                side_effect=scan_with_concurrent_start,
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "replay_inventory",
                return_value=LifecycleReplay((), frozenset()),
            ),
            mock.patch.object(
                codelight._lifecycle_evidence_store,
                "clear_agent_invalidation",
            ),
        ):
            codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "active")

    def test_persisted_event_after_scan_invalidates_empty_inventory(self):
        state = self.state()
        identity = process(200, 1, "/opt/homebrew/bin/codex")
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            store.record(
                agent_id="codex",
                identity=identity,
                session_id="persisted-only",
                state="working",
                observed_at=time.time(),
                order_token=inventory_token + 1,
                operation_id="persisted-after-scan",
                hook_event="UserPromptSubmit",
            )
            with (
                mock.patch.object(codelight, "_state", state),
                mock.patch.object(
                    codelight.time,
                    "monotonic_ns",
                    return_value=inventory_token,
                ),
                mock.patch.object(
                    codelight._agent_process_probe,
                    "identities",
                    return_value={"codex": frozenset()},
                ),
                mock.patch.object(codelight, "_lifecycle_evidence_store", store),
            ):
                codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_sidecar_after_scan_invalidates_empty_inventory(self):
        state = self.state()
        identity = process(200, 1, "/opt/homebrew/bin/codex")
        inventory_token = time.monotonic_ns()
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            store._invalidations.begin_scope_write(
                ScopeWrite(
                    "codex",
                    identity,
                    "",
                    evidence_order(
                        inventory_token + 1,
                        ACTIVE_RANK,
                        "sidecar-after-scan",
                    ),
                )
            )
            with (
                mock.patch.object(codelight, "_state", state),
                mock.patch.object(
                    codelight.time,
                    "monotonic_ns",
                    return_value=inventory_token,
                ),
                mock.patch.object(
                    codelight._agent_process_probe,
                    "identities",
                    return_value={"codex": frozenset()},
                ),
                mock.patch.object(codelight, "_lifecycle_evidence_store", store),
            ):
                codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")

    def test_post_scan_executable_change_invalidates_matched_idle_inventory(self):
        state = self.state()
        inventory_token = time.monotonic_ns()
        old_identity = process(200, 1, "/Applications/VibeTerm")
        new_identity = process(200, 1, "/opt/homebrew/bin/opencode")
        with tempfile.TemporaryDirectory() as tmp:
            store = LifecycleEvidenceStore(os.path.join(tmp, "evidence.sqlite3"))
            store.record_snapshot(
                agent_id="codex",
                identity=old_identity,
                scope_id="/repo-idle",
                sessions=(),
                complete=True,
                observed_at=time.time(),
                order_token=inventory_token - 1,
                operation_id="idle-before-scan",
            )
            store.record(
                agent_id="codex",
                identity=new_identity,
                scope_id="/repo-working",
                session_id="persisted-only",
                state="working",
                observed_at=time.time(),
                order_token=inventory_token + 1,
                operation_id="working-after-scan",
                hook_event="UserPromptSubmit",
            )
            with (
                mock.patch.object(codelight, "_state", state),
                mock.patch.object(
                    codelight.time,
                    "monotonic_ns",
                    return_value=inventory_token,
                ),
                mock.patch.object(
                    codelight._agent_process_probe,
                    "identities",
                    return_value={"codex": frozenset({old_identity})},
                ),
                mock.patch.object(codelight, "_lifecycle_evidence_store", store),
            ):
                codelight._restore_lifecycle_evidence({"codex"})

        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
