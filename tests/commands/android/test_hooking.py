import unittest
from unittest import mock

from objection.commands.android.hooking import _string_is_true, _should_dump_backtrace, _should_dump_args, \
    _should_dump_return_value, show_android_classes, show_android_class_methods, \
    show_registered_broadcast_receivers, show_registered_services, show_registered_activities, \
    set_method_return_value, get_current_activity
from ...helpers import capture


class TestHooking(unittest.TestCase):
    def test_checks_if_string_value_is_python_boolean_true(self):
        result = _string_is_true('true')

        self.assertTrue(result)

    def test_checks_if_string_value_is_python_boolean_false(self):
        result = _string_is_true('false')

        self.assertFalse(result)

    def test_argument_includes_backtrace_flag(self):
        result = _should_dump_backtrace([
            '--test',
            '--dump-backtrace'
        ])

        self.assertTrue(result)

    def test_argument_dump_args_returns_true(self):
        result = _should_dump_args([
            '--foo',
            '--dump-args'
        ])

        self.assertTrue(result)

    def test_argument_dump_args_returns_false(self):
        result = _should_dump_args([
            '--foo',
        ])

        self.assertFalse(result)

    def test_argument_dump_return_returns_true(self):
        result = _should_dump_return_value([
            '--foo',
            '--dump-return'
        ])

        self.assertTrue(result)

    def test_argument_dump_return_returns_false(self):
        result = _should_dump_return_value([
            '--foo',
        ])

        self.assertFalse(result)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_android_classes(self, mock_api):
        mock_api.return_value.android_hooking_get_classes.return_value = [
            'foo',
            'bar',
            'baz'
        ]

        with capture(show_android_classes, []) as o:
            output = o

        expected_output = """bar
baz
foo

Found 3 classes
"""

        self.assertEqual(output, expected_output)

    def test_show_android_class_methods_validates_arguments(self):
        with capture(show_android_class_methods, []) as o:
            output = o

        self.assertEqual(output, 'Usage: android hooking list class_methods <class name>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_android_class_methods(self, mock_api):
        mock_api.return_value.android_hooking_get_class_methods.return_value = [
            'foo',
            'bar',
            'baz'
        ]

        with capture(show_android_class_methods, ['com.foo.bar']) as o:
            output = o

        expected_output = """bar
baz
foo

Found 3 method(s)
"""
        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_registered_broadcast_receivers_handles_empty_data(self, mock_api):
        mock_api.return_value.android_hooking_list_broadcast_receivers.return_value = []

        with capture(show_registered_broadcast_receivers, []) as o:
            output = o

        self.assertEqual(output, '\nFound 0 classes\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_registered_broadcast_receivers(self, mock_api):
        mock_api.return_value.android_hooking_list_broadcast_receivers.return_value = [
            'foo', 'bar', 'baz'
        ]

        with capture(show_registered_broadcast_receivers, []) as o:
            output = o

        expected_output = """bar
baz
foo

Found 3 classes
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_registered_services_handles_empty_data(self, mock_api):
        mock_api.return_value.android_hooking_list_services.return_value = []

        with capture(show_registered_services, []) as o:
            output = o

        self.assertEqual(output, '\nFound 0 classes\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_services(self, mock_api):
        mock_api.return_value.android_hooking_list_services.return_value = [
            'foo', 'bar', 'baz'
        ]

        with capture(show_registered_services, []) as o:
            output = o

        expected_output = """bar
baz
foo

Found 3 classes
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_registered_activities_handles_empty_data(self, mock_api):
        mock_api.return_value.android_hooking_list_activities.return_value = []

        with capture(show_registered_activities, []) as o:
            output = o

        self.assertEqual(output, '\nFound 0 classes\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_registered_activities(self, mock_api):
        mock_api.return_value.android_hooking_list_activities.return_value = [
            'foo', 'bar', 'baz'
        ]

        with capture(show_registered_activities, []) as o:
            output = o

        expected_output = """bar
baz
foo

Found 3 classes
"""

        self.assertEqual(output, expected_output)

    def test_set_method_return_value_validates_arguments(self):
        with capture(set_method_return_value, ['com.foo.bar']) as o:
            output = o

        self.assertEqual(output, 'Usage: android hooking set return_value '
                                 '"<fully qualified class method>" "<optional'
                                 ' overload>" (eg: "com.example.test.doLogin") <true/false>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_method_return_value(self, mock_api):
        set_method_return_value(['com.foo.bar', 'isValid.overload(\'bar\')', 'false'])

        self.assertTrue(mock_api.return_value.android_hooking_set_method_return.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_get_current_activity_and_fragment(self, mock_api):
        mock_api.return_value.android_hooking_get_current_activity.return_value = {
            'activity': 'foo',
            'fragment': 'bar',
        }

        with capture(get_current_activity, []) as o:
            output = o

        expected_output = """Activity: foo
Fragment: bar
"""

        self.assertEqual(output, expected_output)
