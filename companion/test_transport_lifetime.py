import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import codelight


class TransportLifetimeTests(unittest.TestCase):
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
            with sqlite3.connect(databases[0].as_uri() + "?mode=ro", uri=True) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM agent_invalidations").fetchone(), (0,))
                self.assertEqual(db.execute(
                    "SELECT agent_id,complete,snapshot_order_token=order_token FROM provider_evidence"
                ).fetchall(), [("opencode", 1, 1)])
