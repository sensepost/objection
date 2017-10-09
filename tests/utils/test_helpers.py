import unittest

from objection.utils.helpers import get_tokens
from objection.utils.helpers import normalize_gadget_name
from objection.utils.helpers import pretty_concat
from objection.utils.helpers import sizeof_fmt


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
        resilt = normalize_gadget_name('gadget')

        self.assertEqual(resilt, 'gadget')
