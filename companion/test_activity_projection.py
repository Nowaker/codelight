import time
import unittest
from dataclasses import replace

from codelight_core.agents.base import AgentIntegration, AgentSpec
from codelight_core.agents.registry import AgentRegistry
from codelight_core.power_authority import AuthoritySession
from codelight_core.state import CodelightState


class ActivityProjectionTests(unittest.TestCase):
    def test_projection_unknown_does_not_poison_later_idle_evidence(self):
        states = iter(("unknown", "idle"))

        def resolve(sessions, covered_agents):
            self.assertEqual(sessions[0].session_id, "native")
            return (replace(sessions[0], state=next(states)),)

        registry = AgentRegistry(modules=[], extra_agents=(AgentIntegration(
            spec=AgentSpec(agent_id="fixture", display="Fixture", executables=()),
            activity_resolver=resolve),))
        state = CodelightState(default_agent_id="fixture", agent_registry={},
                               idle_window=60, idle_window_waiting=60,
                               agent_process_alive=lambda _: True,
                               activity_resolver=registry.resolve_activity)
        state.set_enabled_agents({"fixture"})
        state.update_provider_snapshot((AuthoritySession("native", "fixture", "working"),),
                                       agent_id="fixture", complete=True,
                                       observed_at=time.time(), authority_scope="host:directory")
        self.assertEqual(state.power_authority_snapshot()["state"], "unknown")
        self.assertEqual(state.power_authority_snapshot()["state"], "idle")


if __name__ == "__main__":
    unittest.main()
