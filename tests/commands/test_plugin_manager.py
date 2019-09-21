import os
import unittest
from unittest import mock

from objection.commands.plugin_manager import load_plugin
from ..helpers import capture


class TestPluginManager(unittest.TestCase):
    def setUp(self):
        self.plugin_path = os.path.abspath(os.path.dirname(__file__) + '/../data/plugin')

    def test_load_plugin_validates_arguments(self):
        with capture(load_plugin, []) as o:
            output = o

        expected_output = 'Usage: plugin load <plugin path> (<plugin namespace>)\n'
        self.assertEqual(output, expected_output)

    @mock.patch('objection.commands.plugin_manager.os.path.exists')
    def test_load_plugin_validates_plugin_init_exists(self, mock_exists):
        mock_exists.return_value = False
        with capture(load_plugin, [self.plugin_path]) as o:
            output = o

        self.assertTrue('tests/data/plugin does not appear to be a valid plugin. Missing __init__.py' in output)

    @mock.patch('objection.utils.plugin.state_connection')
    def test_load_plugin_loads_plugin(self, mock_state_connection):
        with capture(load_plugin, [self.plugin_path]) as o:
            output = o

        from objection.console import commands
        self.assertTrue(commands.COMMANDS['plugin']['commands']['version']['commands']['info']
                        ['meta'] == 'Get the current Frida version')
        self.assertEqual('Loaded plugin: version\n', output)
        self.assertTrue(mock_state_connection.get_agent.called)
