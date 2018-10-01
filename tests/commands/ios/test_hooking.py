import unittest
from unittest import mock

from objection.commands.ios.hooking import _should_ignore_native_classes, _should_include_parent_methods, \
    _class_is_prefixed_with_native, _string_is_true, show_ios_class_methods, watch_class, watch_class_method, \
    set_method_return_value, \
    search_class, search_method
from ...helpers import capture


class TestHooking(unittest.TestCase):
    def test_should_ignore_native_classes_returns_true(self):
        result = _should_ignore_native_classes([
            '--test',
            '--ignore-native'
        ])

        self.assertTrue(result)

    def test_should_ignore_native_classes_returns_false(self):
        result = _should_ignore_native_classes([
            '--test',
        ])

        self.assertFalse(result)

    def test_should_include_parents_includes_returns_true(self):
        result = _should_include_parent_methods([
            '--test',
            '--include-parents'
        ])

        self.assertTrue(result)

    def test_should_include_parents_includes_returns_false(self):
        result = _should_include_parent_methods([
            '--test',
        ])

        self.assertFalse(result)

    def test_class_is_prefixed_with_native_returns_true(self):
        result = _class_is_prefixed_with_native('ACFoo')

        self.assertTrue(result)

    def test_class_is_prefixed_with_native_returns_false(self):
        result = _class_is_prefixed_with_native('FooBar')

        self.assertFalse(result)

    def test_string_is_true_returns_true(self):
        result = _string_is_true('true')

        self.assertTrue(result)

    def test_string_is_true_returns_false(self):
        result = _string_is_true('foo')

        self.assertFalse(result)

    def test_show_ios_class_methods_validates_arguments(self):
        with capture(show_ios_class_methods, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking list class_methods <class name> (--include-parents)\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_show_ios_class_methods(self, mock_api):
        mock_api.return_value.ios_hooking_get_class_methods.return_value = ['foo', 'bar']

        with capture(show_ios_class_methods, ['TEKeychainManager']) as o:
            output = o

        expected_output = """foo
bar

Found 2 methods
"""

        self.assertEqual(output, expected_output)

    def test_watch_class_validates_arguments(self):
        with capture(watch_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking watch class <class_name> (--include-parents)\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_watch_class(self, mock_api):
        watch_class(['TEKeychainManager'])

        self.assertTrue(mock_api.return_value.ios_hooking_watch_class.called)

    def test_watch_class_method_validates_arguments(self):
        with capture(watch_class_method, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking watch method <selector> '
                                 '(eg: -[ClassName methodName:]) (optional: --dump-backtrace) '
                                 '(optional: --dump-args) (optional: --dump-return)\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_watch_class_method(self, mock_api):
        watch_class_method(['-[TEKeychainManager forData:]', '--include-backtrace'])

        self.assertTrue(mock_api.return_value.ios_hooking_watch_method.called)

    def test_set_method_return_value_validates_arguments(self):
        with capture(set_method_return_value, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking set_method_return "<selector>" '
                                 '(eg: "-[ClassName methodName:]") <true/false>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_method_return_value(self, mock_api):
        set_method_return_value(['-[TEKeychainManager forData:]', 'true'])

        self.assertTrue(mock_api.return_value.ios_hooking_set_return_value.called)

    def test_search_class_validates_arguments(self):
        with capture(search_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search classes <name>\n')

    def test_search_class_validates_arguments(self):
        with capture(search_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search classes <name>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_search_class_handles_empty_data(self, mock_api):
        mock_api.return_value.ios_credential_storage.return_value = None

        with capture(search_class, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'No classes found\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_search_class(self, mock_api):
        mock_api.return_value.ios_hooking_get_classes.return_value = ['foo', 'bar', 'baz']

        with capture(search_class, ['FOO']) as o:
            output = o

        expected_output = """foo

Found 1 classes
"""

        self.assertEqual(output, expected_output)

    def test_search_method_validates_arguments(self):
        with capture(search_method, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search methods <name>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_search_method_handles_empty_data(self, mock_api):
        mock_api.return_value.ios_hooking_search_methods.return_value = []

        with capture(search_method, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'No methods found\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_search_method(self, mock_api):
        mock_api.return_value.ios_hooking_search_methods.return_value = ['foo', 'bar', 'baz']

        with capture(search_method, ['keychain']) as o:
            output = o

        expected_output = """foo
bar
baz

Found 3 methods
"""

        self.assertEqual(output, expected_output)
