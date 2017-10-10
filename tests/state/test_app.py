import unittest

from objection.state.app import app_state


class TestApp(unittest.TestCase):
    def test_app_should_not_debug_hooks_by_default(self):
        self.assertFalse(app_state.should_debug_hooks())
