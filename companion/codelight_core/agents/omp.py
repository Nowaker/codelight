from __future__ import annotations

import os
from typing import Callable

from codelight_core import invocation
from codelight_core.agents import base
from codelight_core.agents.typescript_adapter import TypeScriptAdapter


_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" '
    'fill="currentColor"><path d="M6 9h36v8h-7v24h-8V17h-6v24h-8V17H6z"/></svg>'
)

SPEC = base.AgentSpec(
    agent_id="omp",
    display="Oh My Pi",
    executables=("omp",),
    color="#F5A623",
    logo_svg=_LOGO_SVG,
    logo_bitmap="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//////AA//////AA//////AA//////AA//////AA//////AA//////AA//////AAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAf4H+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
)


def default_extension_path() -> str:
    return os.path.expanduser("~/.omp/agent/extensions/codelight.ts")


def _extension_source_path() -> str:
    return os.path.join(os.path.dirname(__file__), "resources", "omp_extension.ts")


def build_integration(
    config: dict,
    *,
    log: Callable[[str], None] | None = None,
) -> base.AgentIntegration:
    extension_path = os.path.expanduser(
        str(config.get("extension_path") or default_extension_path())
    )

    def install_hooks(*, script_path: str, **_options) -> None:
        interpreter, _ = invocation.self_invocation()
        installed = TypeScriptAdapter(
            target_path=extension_path,
            source_path=_extension_source_path(),
            factory_name="createOmpExtension",
            command=(interpreter, script_path),
        ).install()
        if log:
            action = "installed extension" if installed else "preserved unowned file"
            log(f"[omp] {action}: {extension_path}")

    return base.AgentIntegration(
        spec=SPEC,
        install_hooks=install_hooks,
        removable_adapter_files=(extension_path,),
        removable_empty_dirs=(os.path.dirname(extension_path),),
    )
