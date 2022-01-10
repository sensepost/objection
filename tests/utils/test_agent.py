import unittest
from pathlib import Path
from unittest import mock

from objection.utils.agent_old import OldAgent


class TestAgent(unittest.TestCase):

    def setUp(self):
        agent_path = Path(__file__).parent.parent.parent / 'objection' / 'agent.js'
        if not agent_path.exists():
            self.skipTest('Compiled agent not available')

    @mock.patch('objection.utils.agent.app_state')
    def test_agent_loads_from_disk_successfully_without_debug(self, mock_app_state):
        mock_app_state.should_debug.return_value = False

        agent = OldAgent()
        source = agent._get_agent_source()

        self.assertTrue(mock_app_state.should_debug.called)
        self.assertTrue('rpc.exports' in source)

    @mock.patch('objection.utils.agent.app_state')
    def test_agent_loads_from_disk_successfully_with_debug(self, mock_app_state):
        mock_app_state.should_debug.return_value = True

        agent = OldAgent()
        source = agent._get_agent_source()

        self.assertTrue(mock_app_state.should_debug.called)
        self.assertTrue('rpc.exports' in source)
        self.assertTrue('application/json;charset=utf-8;base64' in source.split(':')[-1])

    def test_agent_fails_to_load_throws_error(self):
        with self.assertRaises(Exception) as _:
            agent = OldAgent()
            with mock.patch(agent, 'exists', False):
                agent._get_agent_source()
