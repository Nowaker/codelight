import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import threading
import time
from unittest import mock

import codelight
from codelight_core.lifecycle import ProcessIdentity
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.power_authority import AuthoritySession
from codelight_core.power_status_file import PowerStatusPublisher
from codelight_core.state import CodelightState
from test_opencode_question_activity import QuestionFixture


class RestorePublicationTests(QuestionFixture):
    def publish_during_restore(self, *, inventory_available: bool = True, unreported: bool = False):
        self.session("parent", question=True)
        store = LifecycleEvidenceStore(str(self.path.parent / "authority.sqlite3"))
        epoch = store.boot_id
        assert epoch is not None
        identity = ProcessIdentity(100, 1, "generation", "/bin/opencode", "opencode", epoch)
        store.record_snapshot(
            agent_id="opencode", identity=identity, complete=True,
            sessions=(AuthoritySession("parent", "opencode", "working"),),
            observed_at=time.time(), order_token=time.monotonic_ns(),
        )
        state = CodelightState(default_agent_id="opencode", agent_registry={},
                               idle_window=60, idle_window_waiting=60,
                               activity_resolver=self.resolver.resolve)
        state.set_enabled_agents({"opencode"})
        live = {"opencode": frozenset({identity})}
        path = self.path.parent / "power-status.json"
        entered = threading.Event()
        release = threading.Event()

        def blocked_inventory(_agents):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release inventory")
            if unreported:
                silent = ProcessIdentity(200, 1, "new-generation", "/bin/opencode", "opencode", epoch)
                return {"opencode": frozenset({identity, silent})}
            return live if inventory_available else None

        with (
            mock.patch.object(codelight, "_state", state),
            mock.patch.object(codelight, "_lifecycle_evidence_store", store),
            mock.patch.object(codelight, "_power_status_publisher", PowerStatusPublisher(str(path))),
            mock.patch.object(codelight, "_status_snapshot", return_value={}),
            mock.patch.object(codelight, "_broadcast"),
            mock.patch.object(codelight._agent_process_probe, "identities", return_value=live) as probe,
        ):
            codelight._restore_lifecycle_evidence({"opencode"})
            self.assertEqual(state.power_authority_snapshot()["state"], "idle")
            probe.side_effect = blocked_inventory
            with ThreadPoolExecutor(max_workers=2) as threads:
                restore = threads.submit(codelight._restore_lifecycle_evidence, {"opencode"})
                try:
                    self.assertTrue(entered.wait(5))
                    publish = threads.submit(codelight._push)
                    try:
                        publish.result(timeout=0.2)
                    except TimeoutError:
                        pass
                finally:
                    release.set()
                restore.result(timeout=5)
                publish.result(timeout=5)
        return json.loads(path.read_text())

    def test_concurrent_publisher_never_exposes_pending_coverage(self):
        published = self.publish_during_restore()
        self.assertEqual(published["state"], "idle")
        self.assertEqual(published["reason"], "all-sessions-complete")

    def test_concurrent_publisher_preserves_genuine_inventory_failure(self):
        published = self.publish_during_restore(inventory_available=False)
        self.assertEqual(published["state"], "unknown")

    def test_concurrent_publisher_preserves_unreported_new_generation(self):
        published = self.publish_during_restore(unreported=True)
        self.assertEqual(published["state"], "unknown")

    def test_interrupted_restore_invalidates_old_idle_before_unlocking(self):
        state = CodelightState(default_agent_id="opencode", agent_registry={},
                               idle_window=60, idle_window_waiting=60)
        state.set_enabled_agents({"opencode"})
        state.update_provider_snapshot((), agent_id="opencode", complete=True,
                                       observed_at=time.time())
        state.record_process_inventory("opencode", True)
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")
        with self.assertRaises(RuntimeError):
            with state.authority_restore({"opencode"}):
                raise RuntimeError("interrupted inventory")
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")
