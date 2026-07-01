import unittest
from unittest import mock

from click.testing import CliRunner

from objection.__init__ import __version__
from objection.console.cli import cli, version, patchipa, patchapk
from objection.state.connection import state_connection


class TestsCommandLineInteractions(unittest.TestCase):
    def setUp(self):
        state_connection.use_usb()
        state_connection.host = None
        state_connection.port = None

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(version)

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, 'objection: ' + __version__ + '\n')

    @mock.patch('objection.console.cli.patch_android_apk')
    def test_patchapk_runs_with_minimal_cli_arguments(self, _):
        runner = CliRunner()
        result = runner.invoke(patchapk, ['--source', 'foo.apk'])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)

    @mock.patch('objection.console.cli.patch_android_apk')
    def test_patchapk_runs_with_all_cli_arguments(self, _):
        runner = CliRunner()
        result = runner.invoke(patchapk, [
            '--source', 'foo.apk',
            '--architecture', 'x86',
            '--pause',
            '--skip-resources',
            '--network-security-config',
            '--skip-cleanup',
            '--enable-debug',
        ])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)

    def test_patchapk_fails_and_wants_source(self):
        runner = CliRunner()
        result = runner.invoke(patchapk)

        self.assertIsNotNone(result.exception)
        self.assertEqual(result.exit_code, 2)

    @mock.patch('objection.console.cli.patch_ios_ipa')
    def test_patchipa_runs_with_source_and_codesignature(self, _):
        runner = CliRunner()
        result = runner.invoke(patchipa, ['--source', 'foo.ipa', '--codesign-signature', 'bar'])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)

    @mock.patch('objection.console.cli.patch_ios_ipa')
    def test_patchipa_runs_with_all_cli_arguments(self, _):
        runner = CliRunner()
        result = runner.invoke(patchipa, [
            '--source', 'foo.ipa',
            '--codesign-signature', 'bar',
            '--provision-file', 'baz.mobileprovision',
            '--binary-name', 'zet',
            '--skip-cleanup'
        ])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)

    def test_patchipa_fails_and_wants_source(self):
        runner = CliRunner()
        result = runner.invoke(patchipa, ['--codesign-signature', 'foo'])

        self.assertIsNotNone(result.exception)
        self.assertEqual(result.exit_code, 2)

    def test_patchipa_fails_and_wants_codesign_signature(self):
        runner = CliRunner()
        result = runner.invoke(patchipa, ['--source', 'foo'])

        self.assertIsNotNone(result.exception)
        self.assertEqual(result.exit_code, 2)

    def test_cli_uses_local_connection_mode(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--local', 'version'])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(state_connection.device_type, 'local')
        self.assertFalse(state_connection.network)

    def test_cli_uses_network_connection_mode(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--network', '--host', '10.0.0.5', '--port', '28000', 'version'])

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(state_connection.device_type, 'remote')
        self.assertTrue(state_connection.network)
        self.assertEqual(state_connection.host, '10.0.0.5')
        self.assertEqual(state_connection.port, 28000)

    def test_cli_rejects_local_and_network_together(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--local', '--network', 'version'])

        self.assertIsNotNone(result.exception)
        self.assertEqual(result.exit_code, 2)
        self.assertIn('cannot be used with --network', result.output)
