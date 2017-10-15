import unittest
from unittest import mock

from objection.commands.android.intents import launch_activity, launch_service
from ...helpers import capture


class TestIntents(unittest.TestCase):
    def test_launch_activity_validates_arguments(self):
        with capture(launch_activity, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android intent launch_activity <activity_class>\n')

    @mock.patch('objection.commands.android.intents.FridaRunner')
    def test_launch_activity(self, mock_runner):
        with capture(launch_activity, ['com.foo.bar']) as o:
            output = o

        self.assertEqual(output, 'Launching Activity: com.foo.bar...\nLaunched: com.foo.bar\n')
        self.assertTrue(mock_runner.return_value.run.called)

    def test_launch_service_validates_arguments(self):
        with capture(launch_service, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android intent launch_service <service_class>\n')

    @mock.patch('objection.commands.android.intents.FridaRunner')
    def test_launch_service(self, mock_runner):
        with capture(launch_service, ['com.foo.bar']) as o:
            output = o

        self.assertEqual(output, 'Launching Service: com.foo.bar...\nLaunched: com.foo.bar\n')
        self.assertTrue(mock_runner.return_value.run.called)
