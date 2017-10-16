import unittest

from objection.state.app import app_state


class TestApp(unittest.TestCase):
    def tearDown(self):
        app_state.debug_hooks = False
        app_state.successful_commands = []

    def test_app_should_not_debug_hooks_by_default(self):
        self.assertFalse(app_state.should_debug_hooks())

    def test_app_should_debug_hooks_if_true(self):
        app_state.debug_hooks = True

        self.assertTrue(app_state.should_debug_hooks())

    def test_adds_command_to_history(self):
        app_state.add_command_to_history('foo')

        self.assertEqual(len(app_state.successful_commands), 1)
        self.assertEqual(app_state.successful_commands[0], 'foo')

    def test_clears_command_history(self):
        app_state.successful_commands = ['foo', 'bar']
        app_state.clear_command_history()

        self.assertEqual(len(app_state.successful_commands), 0)
