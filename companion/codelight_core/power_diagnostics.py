from __future__ import annotations

from codelight_core.power_authority import AuthorityScopeDiagnostic

JsonValue = str | int | float | bool | None | list['JsonValue'] | dict[str, 'JsonValue']


def parse_scope_diagnostics(raw: list[JsonValue]) -> list[AuthorityScopeDiagnostic] | None:
    scopes: list[AuthorityScopeDiagnostic] = []
    for item in raw:
        if not isinstance(item, dict):
            return None
        agent, scope, generation = item.get('agentId'), item.get('scope'), item.get('generation')
        order = item.get('orderToken')
        snapshot = item.get('snapshotOrderToken')
        lease = item.get('leaseDeadlineNs')
        replayed = item.get('replayed')
        reason = item.get('reason')
        if (
            not isinstance(agent, str) or not isinstance(scope, str)
            or not isinstance(generation, str) or not isinstance(replayed, bool)
            or not isinstance(reason, str)
            or not isinstance(order, int) or isinstance(order, bool)
            or (snapshot is not None and (not isinstance(snapshot, int) or isinstance(snapshot, bool)))
            or (lease is not None and (not isinstance(lease, int) or isinstance(lease, bool)))
        ):
            return None
        scopes.append({
            'agentId': agent, 'scope': scope, 'generation': generation,
            'orderToken': order, 'snapshotOrderToken': snapshot,
            'leaseDeadlineNs': lease, 'replayed': replayed,
            'reason': reason,
        })
    return scopes
