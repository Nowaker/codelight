import os
import sys
import unittest
from unittest import mock

import codelight
from codelight_core import lifecycle
from codelight_core import process_generation
from codelight_core.lifecycle import (
    AgentProcessProbe,
    ProcessIdentity,
    ProcessInventory,
)


STARTED_AT = "darwin:1788076913:123456"


def process(
    pid: int,
    ppid: int,
    executable: str,
    *,
    started_at: str = STARTED_AT,
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        ppid=ppid,
        started_at=started_at,
        executable=executable,
        command=executable,
    )


class ProcessIdentityTests(unittest.TestCase):
    @mock.patch(
        "codelight_core.lifecycle.process_generation.process_generation",
        return_value=STARTED_AT,
    )
    @mock.patch("codelight_core.lifecycle.subprocess.run")
    def test_process_inventory_uses_high_resolution_generation(self, run, _generation):
        run.return_value.stdout = "100 1 /opt/homebrew/bin/codex\n"

        rows = lifecycle._process_rows()

        self.assertEqual(rows.identities[0].started_at, STARTED_AT)
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")

    @mock.patch(
        "codelight_core.lifecycle.process_generation.process_generation",
        return_value=None,
    )
    @mock.patch("codelight_core.lifecycle.subprocess.run")
    def test_matching_process_without_generation_makes_inventory_unavailable(
        self,
        run,
        _generation,
    ):
        run.return_value.stdout = "100 1 /opt/homebrew/bin/codex\n"
        probe = AgentProcessProbe(
            {"codex": ("codex",)},
            process_rows=lifecycle._process_rows,
        )

        self.assertIsNone(probe.identities({"codex"}))

    def test_nearest_provider_ancestor_uses_exact_process_generation(self):
        codex = process(100, 1, "/opt/homebrew/bin/codex")
        hook = process(200, 100, "/opt/homebrew/bin/python3")
        probe = AgentProcessProbe(
            {"codex": ("codex",)},
            command_lines=lambda: (codex.command, hook.command),
            process_rows=lambda: ProcessInventory((codex, hook), frozenset()),
        )

        self.assertEqual(probe.nearest_ancestor("codex", hook.pid), codex)

    def test_shell_command_text_is_not_a_provider_identity(self):
        wrapper = ProcessIdentity(
            pid=100,
            ppid=1,
            started_at=STARTED_AT,
            executable="/bin/zsh",
            command="zsh -c 'opencode && notify'",
        )
        hook = process(200, 100, "/opt/homebrew/bin/python3")
        probe = AgentProcessProbe(
            {"opencode": ("opencode",)},
            command_lines=lambda: (wrapper.command, hook.command),
            process_rows=lambda: ProcessInventory((wrapper, hook), frozenset()),
        )

        self.assertIsNone(probe.nearest_ancestor("opencode", hook.pid))

    def test_hook_identity_does_not_use_an_unrelated_global_candidate(self):
        unrelated = process(100, 1, "/opt/homebrew/bin/codex")
        with (
            mock.patch.object(
                codelight._agent_process_probe,
                "nearest_ancestor",
                return_value=None,
            ),
            mock.patch.object(
                codelight._agent_process_probe,
                "identities",
                return_value={"codex": frozenset({unrelated})},
            ),
        ):
            identity = codelight._hook_process_identity("codex")

        self.assertIsNone(identity)

    def test_linux_generation_combines_boot_id_and_start_ticks(self):
        stat_fields = ["S", *("0" for _index in range(18)), "4242"]
        files = {
            "/proc/sys/kernel/random/boot_id": "boot-123\n",
            "/proc/77/stat": f"77 (worker with spaces) {' '.join(stat_fields)}",
        }

        generation = process_generation._linux_generation(77, files.__getitem__)

        self.assertEqual(generation, "linux:boot-123:4242")

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS libproc")
    def test_darwin_generation_has_microsecond_process_birth(self):
        generation = process_generation.process_generation(os.getpid())

        self.assertRegex(generation or "", r"^darwin:\d+:\d+$")
        self.assertEqual(generation, process_generation.process_generation(os.getpid()))


if __name__ == "__main__":
    unittest.main()
