import unittest
from unittest import mock

from click.testing import CliRunner

from objection.__init__ import __version__
from objection.console.cli import version, patchipa, patchapk, device_type


class TestsCommandLineInteractions(unittest.TestCase):
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(version)

        self.assertIsNone(result.exception)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, 'objection: ' + __version__ + '\n')

    @mock.patch('objection.utils.agent.Agent.inject')
    @mock.patch('objection.console.cli.get_device_info')
    def test_device_info(self, mock_inject, get_device_info):
        mock_inject.return_value = None
        get_device_info.return_value = 'a', 'b', 'c', 'd'

        runner = CliRunner()
        runner.invoke(device_type)

        self.assertTrue(get_device_info.called)

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
