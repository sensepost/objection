import unittest

from objection.state.device import device_state, Ios
from objection.utils.helpers import clean_argument_flags
from objection.utils.helpers import get_tokens
from objection.utils.helpers import normalize_gadget_name
from objection.utils.helpers import pretty_concat
from objection.utils.helpers import print_frida_connection_help
from objection.utils.helpers import sizeof_fmt
from objection.utils.helpers import warn_about_older_operating_systems
from ..helpers import capture


class TestHelpers(unittest.TestCase):
    def test_pretty_concat_with_less_than_seventy_five_chars(self):
        result = pretty_concat('test')

        self.assertEqual(result, 'test')

    def test_pretty_concat_with_more_than_max_chars(self):
        result = pretty_concat('testing', 5)

        self.assertEqual(result, 'testi...')

    def test_pretty_concat_with_more_than_max_chars_to_the_left(self):
        result = pretty_concat('testing', 5, left=True)

        self.assertEqual(result, '...sting')

    def test_sizeof_formats_values(self):
        result = sizeof_fmt(3000)

        self.assertEqual(result, '2.9 KiB')

    def test_gets_tokens_without_quotes(self):
        result = get_tokens('this is a test')

        self.assertEqual(result, ['this', 'is', 'a', 'test'])

    def test_gets_tokens_with_quotes(self):
        result = get_tokens('this is "a test"')

        self.assertEqual(result, ['this', 'is', 'a test'])

    def test_gets_tokens_and_handles_missing_quotes(self):
        result = get_tokens('this is "a test')

        self.assertEqual(result, ['lajfhlaksjdfhlaskjfhafsdlkjh'])

    def test_normalizes_gadget_names_when_interger_is_given(self):
        result = normalize_gadget_name('400')

        self.assertEqual(type(result), int)
        self.assertEqual(result, 400)

    def test_normalizes_gadget_name_when_string_name_is_given(self):
        result = normalize_gadget_name('gadget')

        self.assertEqual(result, 'gadget')

    def test_cleans_argument_lists_with_flags(self):
        result = clean_argument_flags(['foo', '--bar'])
        self.assertEqual(result, ['foo'])

    def test_prints_frida_connection_help(self):
        with capture(print_frida_connection_help) as o:
            output = o

        expected_output = """If you are using a rooted/jailbroken device, specify a process with the --gadget flag. Eg: objection --gadget "Calendar" explore
If you are using a non rooted/jailbroken device, ensure that your patched application is running and in the foreground.

If you have multiple devices, specify the target device with --serial. A list of attached device serials can be found with the frida-ls-devices command.

For more information, please refer to the objection wiki at: https://github.com/sensepost/objection/wiki
"""

        self.assertEqual(output, expected_output)

    def test_warns_about_operating_system_versions(self):
        device_state.device_type = Ios
        with capture(warn_about_older_operating_systems) as o:
            output = o

        expected_output = """Warning: You appear to be running iOS 1 which may result in some hooks failing.
It is recommended to use at least an iOS version 9 device with objection.
"""

        self.assertEqual(output, expected_output)
