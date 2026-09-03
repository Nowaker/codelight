from __future__ import annotations


def is_activity_process(command: str) -> bool:
    command_parts = command.split(maxsplit=1)
    if len(command_parts) < 2:
        return True
    first_argument = command_parts[1].split(maxsplit=1)[0]
    return first_argument != "app-server"
