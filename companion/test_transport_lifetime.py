import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import codelight
from codelight_core.lifecycle import _process_rows
from codelight_core.lifecycle_evidence import LifecycleEvidenceStore
from codelight_core.state import CodelightState


class TransportLifetimeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bun"), "requires Bun transport runtime")
    def test_timed_out_working_report_durably_invalidates_previous_idle(self):
        bun = shutil.which("bun")
        assert bun is not None
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            host = home / "opencode"
            host.symlink_to(bun)
            transport = Path(__file__).parent / "codelight_core/agents/resources/codelight_hook.ts"
            entry = home / "host.ts"
            entry.write_text(
                f"import {{ processTransport }} from {json.dumps(str(transport))};\n"
                f"const good = processTransport({json.dumps([sys.executable, codelight.__file__])});\n"
                'good.snapshot({agentId:"opencode",complete:true,sessions:[],eventName:"snapshot",cwd:""});\n'
                'process.stdout.write("idle\\n");\n'
                'await Bun.stdin.text();\n'
                f"const bad = processTransport({json.dumps([sys.executable, '-c', 'import time; time.sleep(30)'])});\n"
                'bad.event({agentId:"opencode",sessionId:"working",state:"working",eventName:"busy",cwd:""});\n'
                'process.stdout.write("failed\\n");\n'
                'setInterval(() => {}, 1000);\n'
            )
            with subprocess.Popen([str(host), str(entry)],
                                  env={**os.environ, "HOME": directory},
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True) as child:
                try:
                    assert child.stdout is not None and child.stdin is not None
                    self.assertEqual(child.stdout.readline(), "idle\n")
                    inventory = _process_rows()
                    assert inventory is not None
                    identity = next(i for i in inventory.identities if i.pid == child.pid)
                    path = home / ".config/codelight/monitor_state/evidence.sqlite3"
                    store = LifecycleEvidenceStore(str(path))
                    self.assertTrue(store.replay({"opencode": frozenset({identity})})[0].complete)
                    child.stdin.close()
                    self.assertEqual(child.stdout.readline(), "failed\n")
                    for _restart in range(2):
                        restarted = LifecycleEvidenceStore(str(path))
                        evidence = restarted.replay({"opencode": frozenset({identity})})
                        self.assertFalse(evidence[0].complete)
                        state = CodelightState(default_agent_id="opencode", agent_registry={},
                                               idle_window=60, idle_window_waiting=60)
                        state.set_enabled_agents({"opencode"})
                        with (
                            mock.patch.object(codelight, "_state", state),
                            mock.patch.object(codelight, "_lifecycle_evidence_store", restarted),
                            mock.patch.object(codelight._agent_process_probe, "identities",
                                              return_value={"opencode": frozenset({identity})}),
                        ):
                            codelight._restore_lifecycle_evidence({"opencode"})
                        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")
                finally:
                    child.kill()
                    child.wait(timeout=5)

    @unittest.skipUnless(shutil.which("bun"), "requires Bun transport runtime")
    def test_immediately_exiting_host_records_identified_snapshot(self):
        bun = shutil.which("bun")
        assert bun is not None
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            host = home / "opencode"
            host.symlink_to(bun)
            transport = Path(__file__).parent / "codelight_core/agents/resources/codelight_hook.ts"
            entry = home / "host.ts"
            entry.write_text(
                f"import {{ processTransport }} from {json.dumps(str(transport))};\n"
                f"const transport = processTransport({json.dumps([sys.executable, codelight.__file__])});\n"
                'transport.snapshot({agentId:"opencode",complete:true,sessions:[],eventName:"snapshot",cwd:""});\n'
                "process.exit(0);\n"
            )
            result = subprocess.run(
                [str(host), str(entry)], env={**os.environ, "HOME": directory},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            databases = list((home / ".config/codelight/monitor_state/evidence.sqlite3.boots").glob("*/evidence.sqlite3"))
            self.assertEqual(len(databases), 1)
            self.assertEqual([path for path in home.rglob("*.taint") if path.is_file()], [])
            with sqlite3.connect(databases[0].as_uri() + "?mode=ro", uri=True) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM agent_invalidations").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT agent_id,complete,snapshot_order_token=order_token FROM provider_evidence"
                ).fetchall(), [("opencode", 1, 1)])
