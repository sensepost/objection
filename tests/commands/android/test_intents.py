import unittest
from unittest import mock

from objection.commands.android.intents import launch_activity, launch_service
from ...helpers import capture


class TestIntents(unittest.TestCase):
    def test_launch_activity_validates_arguments(self):
        with capture(launch_activity, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android intent launch_activity <activity_class>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_launch_activity(self, mock_api):
        launch_activity(['com.foo.bar'])

        self.assertTrue(mock_api.return_value.android_intent_start_activity.called)

    def test_launch_service_validates_arguments(self):
        with capture(launch_service, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android intent launch_service <service_class>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_launch_service(self, mock_api):
        launch_service(['com.foo.bar'])

        self.assertTrue(mock_api.return_value.android_intent_start_service.called)
