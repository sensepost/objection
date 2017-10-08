import unittest

from prompt_toolkit.document import Document

from objection.console.completer import CommandCompleter


class TestConsoleCommandCompletion(unittest.TestCase):
    def setUp(self):
        self.command_completer = CommandCompleter()

    def test_can_find_command_completion(self):
        document = Document('android hooking list ', 21)

        completions = self.command_completer.find_completions(document)

        self.assertEqual(type(completions), dict)
        self.assertEqual(completions['activities']['meta'], 'List the registered Activities')

    def test_will_have_empty_dict_for_invalid_command(self):
        document = Document('android hooking list fruitcakes ', 30)

        completions = self.command_completer.find_completions(document)

        self.assertEqual(type(completions), dict)
        self.assertEqual(len(completions), 0)
