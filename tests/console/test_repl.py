import unittest
from unittest import mock
from unittest.mock import MagicMock

from frida import TimedOutError

from objection.__init__ import __version__
from objection.commands.android.hooking import show_registered_activities
from objection.console.repl import Repl
from ..helpers import capture


class TestRepl(unittest.TestCase):
    def setUp(self):
        self.repl = Repl()

    def test_sets_prompt_tokens(self):
        self.repl.set_prompt_tokens(('a', 'b', 'c', 'd'))

        self.assertEqual(type(self.repl.prompt_tokens), list)
        self.assertEqual(len(self.repl.prompt_tokens), 5)

        # test the token values. not 100% how to test the types properly
        # [(Token.Applicationname, 'a'), (Token.On, ' on '),
        # (Token.Devicetype, '(c: '), (Token.Version, 'd) '), (Token.Connection, '[usb] # ')]
        self.assertEqual(self.repl.prompt_tokens[0][1], 'a')
        self.assertEqual(self.repl.prompt_tokens[1][1], ' on ')
        self.assertEqual(self.repl.prompt_tokens[2][1], '(c: ')
        self.assertEqual(self.repl.prompt_tokens[3][1], 'd) ')
        self.assertEqual(self.repl.prompt_tokens[4][1], '[usb] # ')

    def test_gets_prompt_tokens_without_having_them_set_first(self):
        self.assertEqual(type(self.repl.prompt_tokens), list)
        self.assertEqual(len(self.repl.prompt_tokens), 0)

        tokens = self.repl.get_prompt_message()

        # [(Token.Applicationname, 'unknown application'),
        # (Token.On, ''), (Token.Devicetype, ''), (Token.Version, ' '), (Token.Connection, '[usb] # ')]
        self.assertEqual(tokens[0][1], 'unknown application')
        self.assertEqual(tokens[1][1], '')
        self.assertEqual(tokens[2][1], '')
        self.assertEqual(tokens[3][1], ' ')
        self.assertEqual(tokens[4][1], '[usb] # ')

    def test_gets_prompt_tokens_after_setting_them(self):
        self.repl.set_prompt_tokens(('a', 'b', 'c', 'd'))

        tokens = self.repl.get_prompt_message()

        self.assertEqual(tokens[0][1], 'a')
        self.assertEqual(tokens[1][1], ' on ')
        self.assertEqual(tokens[2][1], '(c: ')
        self.assertEqual(tokens[3][1], 'd) ')
        self.assertEqual(tokens[4][1], '[usb] # ')

    def test_does_nothing_when_empty_command_is_passed(self):
        with capture(self.repl.run_command, '') as output:
            self.assertEqual('', output)

    def test_does_nothing_when_only_spaces_as_command_is_passed(self):
        with capture(self.repl.run_command, '      ') as o:
            output = o

        self.assertEqual(output, '')

    @mock.patch('objection.console.repl.delegator.run')
    def test_runs_os_command_when_prefixed_with_excalmation_mark(self, patched_delegator):
        patched_delegator.return_value = mock.MagicMock(out=b'out_test', err=b'err_test')

        with capture(self.repl.run_command, '!id') as o:
            output = o

        expected_output = ('Running OS command: id\n'
                           '\n'
                           'out_test\n'
                           'err_test\n')
        self.assertEqual(output, expected_output)

    def test_finds_help_when_prefixed_with_help_command(self):
        with capture(self.repl.run_command, 'help android') as o:
            output = o

        expected_output = ('Contains subcommands to work with Android specific features. These include\n'
                           'shell commands, bypassing SSL pinning and simulating a rooted environment.\n'
                           '\n')

        self.assertEqual(output, expected_output)

    def test_fails_to_find_help_for_invalid_command(self):
        with capture(self.repl.run_command, 'help what') as o:
            output = o

        expected_output = ('No help found for: what. Either the command '
                           'does not exist or contains subcommands with help.\n')

        self.assertEqual(output, expected_output)

    def test_fails_when_invalid_command_is_passed(self):
        with capture(self.repl.run_command, 'android wont do this') as o:
            output = o

        expected_outut = 'Unknown or ambiguous command: `android wont do this`. Try `help android wont do this`.\n'
        self.assertEqual(output, expected_outut)

    def test_is_able_to_find_an_executable_method_to_run_with_tokens_passed(self):
        walk_count, method = self.repl._find_command_exec_method(['android', 'hooking', 'list', 'activities'])

        self.assertEqual(walk_count, 4)
        self.assertEqual(method, show_registered_activities)

    def test_will_fail_to_find_exec_method_with_invalid_tokens(self):
        walk_count, method = self.repl._find_command_exec_method(['android', 'hooking', 'list', 'invalid'])

        self.assertEqual(walk_count, 4)
        self.assertIsNone(method)

    def test_is_able_to_locate_nested_helpfile_contents(self):
        help_file = self.repl._find_command_help(['ios', 'keychain', 'clear'])

        expected_output = ('Command: ios keychain clear\n'
                           '\n'
                           'Usage: ios keychain clear\n'
                           '\n'
                           'Clears all the keychain items for the current application. This is achieved by\n'
                           'iterating over the keychain type classes available in iOS and populating a search\n'
                           'dictionary with them. This dictionary is then used as a query to SecItemDelete(),\n'
                           'deleting the entries.\n'
                           'Items that will be deleted include everything stored with the entitlement group used\n'
                           'during the patching/signing process.\n'
                           '\n'
                           'Examples:\n'
                           '   ios keychain clear\n')

        self.assertEqual(help_file, expected_output)

    @mock.patch('objection.utils.agent.Agent.inject')
    @mock.patch('objection.utils.agent.Agent.unload')
    @mock.patch('objection.console.repl.get_device_info')
    def test_hanldes_reconnects(self, get_device_info, mock_unload, mock_inject):
        mock_inject.return_value = None
        mock_unload.return_type = None
        get_device_info.return_value = ('a', 'b', 'c', 'd')

        with capture(self.repl.handle_reconnect, 'reconnect') as o:
            output = o

        expected_output = ('Reconnecting...\n'
                           'Reconnection successful!\n')

        self.assertEqual(output, expected_output)
        self.assertTrue(get_device_info.called)
        self.assertTrue(mock_unload.called)
        self.assertTrue(mock_inject.called)

    @mock.patch('objection.utils.agent.Agent.unload')
    @mock.patch('objection.console.repl.get_device_info')
    def test_handles_reconnects_and_reports_failures(self, mock_unload, get_device_info):
        mock_unload.return_type = None
        get_device_info.side_effect = TimedOutError()

        with capture(self.repl.handle_reconnect, 'reconnect') as o:
            output = o

        expected_output = ('Reconnecting...\n'
                           'Failed to reconnect with error: \n')

        self.assertEqual(output, expected_output)

    def test_starts_repl_and_exists_cleanly_with_banner(self):
        self.repl.session = MagicMock(name='session')
        self.repl.session.prompt.return_value = 'exit'

        with capture(self.repl.start_repl, False) as o:
            output = o

        expected_output = ("""
     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v{0}

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
Exiting...\n""".format(__version__))

        self.assertEqual(output, expected_output)

    def test_starts_repl_and_exists_cleanly_with_banner_and_quiet_flag(self):
        self.repl.session = MagicMock(name='session')
        self.repl.session.prompt.return_value = 'exit'

        with capture(self.repl.start_repl, True) as o:
            output = o

        expected_output = 'Exiting...\n'

        self.assertEqual(output, expected_output)

    @mock.patch('objection.console.repl.PromptSession')
    @mock.patch('objection.console.repl.Repl.run_command')
    def test_runs_commands_and_catches_exceptions(self, prompt, run_command):
        prompt.return_value.prompt.return_value = 'ios keychain clear'
        run_command.side_effect = TypeError()

        self.assertRaises(TypeError)
