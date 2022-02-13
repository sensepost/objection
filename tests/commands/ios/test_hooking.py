import unittest
from unittest import mock

from objection.commands.ios.hooking import _should_ignore_native_classes, _should_include_parent_methods, \
    _class_is_prefixed_with_native, _string_is_true, show_ios_class_methods, set_method_return_value
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

    def test_set_method_return_value_validates_arguments(self):
        with capture(set_method_return_value, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking set_method_return "<selector>" '
                                 '(eg: "-[ClassName methodName:]") <true/false>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_set_method_return_value(self, mock_api):
        set_method_return_value(['-[TEKeychainManager forData:]', 'true'])

        self.assertTrue(mock_api.return_value.ios_hooking_set_return_value.called)
