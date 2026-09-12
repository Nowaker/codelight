import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from codelight_core.boot_epoch import BootIdentityUnavailable, BootPersistence


@unittest.skipUnless(shutil.which("bun"), "requires Bun transport runtime")
class TransportBootMetadataTests(unittest.TestCase):
    def check_artifact(self, artifact: str, *, concurrent_writer: bool = False) -> None:
        bun = shutil.which("bun")
        assert bun is not None
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".config/codelight"
            boot = BootPersistence(str(config / "monitor_state/evidence.sqlite3"))
            assert boot.path is not None
            database = Path(boot.path)
            database.parent.mkdir(parents=True)
            if artifact == "database":
                database.touch()
            else:
                Path(str(database) + ".taints").mkdir()
            with self.assertRaises(BootIdentityUnavailable):
                boot.verified_path()
            module = Path(__file__).parent / "codelight_core/agents/resources/codelight_failure.ts"
            entry = home / "failure.ts"
            publication = ""
            if concurrent_writer:
                metadata = json.dumps(str(database.parent / "boot-id"))
                publication = (
                    'import { spyOn } from "bun:test";\n'
                    'import * as fs from "node:fs";\n'
                    'const exists = fs.existsSync; let published = false;\n'
                    'spyOn(fs, "existsSync").mockImplementation(path => {\n'
                    f'  if (path === {metadata} && !published) {{\n'
                    f'    published = true; fs.writeFileSync({metadata}, {json.dumps(boot.epoch)}); return false;\n'
                    '  } return exists(path);\n'
                    '});\n'
                )
            entry.write_text(
                publication
                + f"const {{ invalidateFailedReport }} = await import({json.dumps(str(module))});\n"
                'invalidateFailedReport("opencode");\n'
            )
            result = subprocess.run([bun, str(entry)],
                                    env={**os.environ, "HOME": directory, "CODELIGHT_CONFIG_HOME": str(config)},
                                    capture_output=True, text=True, timeout=10)
            if concurrent_writer:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(boot.verified_path(), str(database))
            else:
                self.assertNotEqual(result.returncode, 0)
                with self.assertRaises(BootIdentityUnavailable):
                    boot.verified_path()

    def test_existing_database_without_boot_metadata_is_not_adopted(self):
        self.check_artifact("database")

    def test_existing_taints_without_boot_metadata_are_not_adopted(self):
        self.check_artifact("taints")

    def test_concurrent_metadata_publication_is_rechecked(self):
        self.check_artifact("database", concurrent_writer=True)
