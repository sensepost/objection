import unittest

from prompt_toolkit.document import Document

from objection.console.completer import CommandCompleter


class TestConsoleCommandCompletion(unittest.TestCase):
    def setUp(self):
        self.command_completer = CommandCompleter()
        self.original_download_dynamic = self.command_completer.COMMANDS['filesystem']['commands']['download']['dynamic']
        self.command_completer.COMMANDS['filesystem']['commands']['download']['dynamic'] = (
            lambda: {'remote_file': {'meta': 'stubbed dynamic completion'}}
        )

    def tearDown(self):
        self.command_completer.COMMANDS['filesystem']['commands']['download']['dynamic'] = self.original_download_dynamic

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

    def test_download_completes_dynamic_for_first_parameter(self):
        document = Document('filesystem download rem', 23)

        completions = self.command_completer.find_completions(document)

        self.assertIn('remote_file', completions)

    def test_download_completes_flags_after_first_parameter(self):
        document = Document('filesystem download remote_file ', 32)

        completions = self.command_completer.find_completions(document)

        self.assertIn('--folder', completions)

