import unittest
from unittest import mock

from objection.commands.ios.hooking import _should_ignore_native_classes, _should_include_parent_methods, \
    _class_is_prefixed_with_native, _string_is_true, _get_ios_classes, show_ios_classes, \
    show_ios_class_methods, watch_class, watch_class_method, set_method_return_value, \
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

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_get_ios_classes_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(_get_ios_classes) as o:
            output = o

        self.assertEqual(output, 'Failed to list classes with error: test\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_get_ios_classes(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['foo', 'bar']

        mock_runner.return_value.get_last_message.return_value = mock_response

        self.assertEqual(_get_ios_classes(), ['foo', 'bar'])

    @mock.patch('objection.commands.ios.hooking._get_ios_classes')
    def test_show_ios_classes_handles_empty_classes(self, mock_get_classes):
        mock_get_classes.return_value = None

        with capture(show_ios_classes, []) as o:
            output = o

        self.assertEqual(output, '')

    @mock.patch('objection.commands.ios.hooking._get_ios_classes')
    def test_show_ios_classes_does_not_ignore_any_classes(self, mock_get_classes):
        mock_get_classes.return_value = [
            'Foo', 'Bar', 'Baz', 'WebFoo', 'NSBar'
        ]

        with capture(show_ios_classes, []) as o:
            output = o

        expected_outut = """Bar
Baz
Foo
NSBar
WebFoo
"""

        self.assertEqual(output, expected_outut)

    @mock.patch('objection.commands.ios.hooking._get_ios_classes')
    def test_show_ios_classes_ignores_native_prefixes(self, mock_get_classes):
        mock_get_classes.return_value = [
            'Foo', 'Bar', 'Baz', 'WebFoo', 'NSBar'
        ]

        with capture(show_ios_classes, ['--ignore-native']) as o:
            output = o

        expected_outut = """Bar
Baz
Foo
"""

        self.assertEqual(output, expected_outut)

    # ---

    def test_show_ios_class_methods_validates_arguments(self):
        with capture(show_ios_class_methods, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking list class_methods <class name> (--include-parents)\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_show_ios_class_methods_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(show_ios_class_methods, ['TEKeychainManager']) as o:
            output = o

        self.assertEqual(output, 'Failed to list classes with error: test\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_show_ios_class_methods(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['foo', 'bar']

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(show_ios_class_methods, ['TEKeychainManager']) as o:
            output = o

        self.assertEqual(output, 'foo\nbar\n')

    def test_watch_class_validates_arguments(self):
        with capture(watch_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking watch class <class_name> (--include-parents)\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_watch_class(self, mock_runner):
        watch_class(['TEKeychainManager'])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    def test_watch_class_method_validates_arguments(self):
        with capture(watch_class_method, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking watch method <selector> '
                                 '(eg: -[ClassName methodName:]) (optional: --dump-backtrace) '
                                 '(optional: --dump-args) (optional: --dump-return)\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_watch_class_method(self, mock_runner):
        watch_class_method(['-[TEKeychainManager forData:]', '--include-backtrace'])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    def test_set_method_return_value_validates_arguments(self):
        with capture(set_method_return_value, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking set_method_return "<selector>" '
                                 '(eg: "-[ClassName methodName:]") <true/false>\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_set_method_return_value(self, mock_runner):
        set_method_return_value(['-[TEKeychainManager forData:]', 'true'])

        self.assertTrue(mock_runner.return_value.run_as_job.called)

    def test_search_class_validates_arguments(self):
        with capture(search_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search classes <name>\n')

    def test_search_class_validates_arguments(self):
        with capture(search_class, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search classes <name>\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_class_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_class, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'Failed to search for classes with error: test\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_class_handles_empty_data(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = None

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_class, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'No classes found\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_class(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['foo', 'bar', 'baz']

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_class, ['keychain']) as o:
            output = o

        expected_output = """foo
bar
baz

Found 3 classes
"""

        self.assertEqual(output, expected_output)

    def test_search_method_validates_arguments(self):
        with capture(search_method, []) as o:
            output = o

        self.assertEqual(output, 'Usage: ios hooking search methods <name>\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_method_handles_hook_error(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = False
        type(mock_response).error_reason = 'test'

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_method, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'Failed to search for methods with error: test\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_method_handles_empty_data(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = None

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_method, ['keychain']) as o:
            output = o

        self.assertEqual(output, 'No methods found\n')

    @mock.patch('objection.commands.ios.hooking.FridaRunner')
    def test_search_method(self, mock_runner):
        mock_response = mock.Mock()
        mock_response.is_successful.return_value = True
        type(mock_response).data = ['foo', 'bar', 'baz']

        mock_runner.return_value.get_last_message.return_value = mock_response

        with capture(search_method, ['keychain']) as o:
            output = o

        expected_output = """foo
bar
baz

Found 3 methods
"""

        self.assertEqual(output, expected_output)
