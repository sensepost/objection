import unittest
import uuid
from unittest import mock

from objection.utils.frida_transport import RunnerMessage, FridaJobRunner, FridaRunner
from ..helpers import capture


class TestRunnerMessage(unittest.TestCase):
    def setUp(self):
        self.success_message_sample = {
            'status': 'success',
            'error_reason': None,
            'type': 'send',
            'data': {
                'foo': 'bar'
            }
        }

        self.failed_message_sample = {
            'status': 'error',
            'error_reason': 'testing',
            'type': 'send',
            'data': None
        }

    def test_inits_with_message_and_extra_data(self):
        message = RunnerMessage(self.success_message_sample, {'baz': 'bar'})

        self.assertTrue(message.success)
        self.assertEqual(message.type, 'send')
        self.assertIsNone(message.error_reason)
        self.assertEqual(message.data, {'foo': 'bar'})
        self.assertEqual(message.extra_data, {'baz': 'bar'})

    def test_inits_with_message_and_empty_extra_data(self):
        message = RunnerMessage(self.success_message_sample, None)

        self.assertIsNone(message.extra_data)

    def test_reports_successful(self):
        message = RunnerMessage(self.success_message_sample, None)

        self.assertTrue(message.is_successful())

    def test_reports_failed(self):
        message = RunnerMessage(self.failed_message_sample, None)

        self.assertFalse(message.is_successful())

    def test_gets_extra_data_with_helper_method(self):
        message = RunnerMessage(self.success_message_sample, 'test')

        data = message.get_extra_data()

        self.assertEqual(data, 'test')

    def test_gets_extra_data_with_helper_with_no_data(self):
        message = RunnerMessage(self.success_message_sample, None)

        data = message.get_extra_data()

        self.assertEqual(data, None)

    def test_gets_data_from_data_dictionary_by_dot_notation(self):
        message = RunnerMessage(self.success_message_sample, {'foo': 'bar'})

        data = message.foo

        self.assertEqual(data, 'bar')

    def test_gets_data_from_dictionary_by_key_notation(self):
        message = RunnerMessage(self.success_message_sample, {'foo': 'bar'})

        data = message['foo']

        self.assertEqual(data, 'bar')

    def test_prints_representation_of_successful_message(self):
        message = RunnerMessage(self.success_message_sample, None)

        self.assertEqual(repr(message), '<SuccessfulRunnerMessage Type: send Data: {\'foo\': \'bar\'}>')

    def test_prints_representation_of_failed_message(self):
        message = RunnerMessage(self.failed_message_sample, None)

        self.assertEqual(repr(message), '<FailedRunnerMessage Reason: testing Type: send Data: None>')


class TestFridaJobRunner(unittest.TestCase):
    def setUp(self):
        self.runner = FridaJobRunner(name='testing', args=None)

        # set status values for some determined by
        # uuid & time
        self.runner.id = 'testing-id'
        self.runner.started = '2017-10-09 15:03:23'

        self.successful_message = {
            'payload': {
                'type': 'send',
                'status': 'success',
                'data': 'data for unittest'
            }
        }

        self.error_message = {
            'payload': {
                'type': 'send',
                'status': 'error',
                'data': 'error data for unittest'
            }
        }

        self.unknown_message = {
            'payload': {
                'type': 'send',
                'status': 'invalid',
                'data': 'invalid data for unittest'
            }
        }

        self.invalid_message = {
            'invalid': 'invalid'
        }

    @mock.patch('objection.utils.frida_transport.random.choice')
    def test_inits_job_runner(self, choice):
        choice.return_value = 'green'

        runner = FridaJobRunner('test', ['foo'])

        self.assertEqual(runner.name, 'test')
        self.assertEqual(type(runner.id), uuid.UUID)
        self.assertFalse(runner.has_had_error)
        self.assertIsNone(runner.hook)
        self.assertIsNone(runner.session)
        self.assertIsNone(runner.script)
        self.assertEqual(runner.args, ['foo'])
        self.assertEqual(runner.success_color, 'green')

    def test_receive_successful_message_from_hook(self):
        with capture(self.runner.on_message, self.successful_message, None) as o:
            output = o

        self.assertEqual(output, '[testing-id] [send] data for unittest\n')

    def test_receive_error_message_from_hook(self):
        with capture(self.runner.on_message, self.error_message, None) as o:
            output = o

        expected_output = 'Failed to process an incoming message from hook: \'error_reason\'\n'

        self.assertEqual(output, expected_output)
        # self.assertTrue(self.runner.has_had_error)  # TODO: Erm, ???

    def test_receive_unknown_message_from_hook(self):
        with capture(self.runner.on_message, self.unknown_message, None) as o:
            output = o

        self.assertEqual(output, '[testing-id][invalid] invalid data for unittest\n')

    @mock.patch('objection.utils.frida_transport.app_state.should_debug_hooks')
    def test_receive_message_and_debug_response_outut(self, should_debug_hooks):
        should_debug_hooks.return_value = True

        with capture(self.runner.on_message, self.successful_message, None) as o:
            output = o

        expected_value = """- [response] ------------------
{
  "payload": {
    "data": "data for unittest",
    "status": "success",
    "type": "send"
  }
}
- [./response] ----------------
[testing-id] [send] data for unittest
"""

        self.assertEqual(output, expected_value)

    def test_prints_representation_of_running_job(self):
        self.assertEqual(repr(self.runner), '<ID: testing-id Started:2017-10-09 15:03:23>')


class TestFridaRunner(unittest.TestCase):
    def setUp(self):
        self.runner = FridaRunner()

        self.successful_message = {
            'payload': {
                'type': 'send',
                'status': 'success',
                'error_reason': None,
                'data': 'data for unittest'
            }
        }

        self.error_message = {
            'payload': {
                'type': 'send',
                'status': 'error',
                'error_reason': 'error_message',
                'data': 'error data for unittest'
            }
        }

        self.sample_hook = """// this is a comment

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-readable',
    data: { path: '{{ path }}', readable: Boolean(file.canRead()) }
};

send(response);"""

    def test_init_runner_without_hook(self):
        runner = FridaRunner()

        self.assertEqual(runner.messages, [])
        self.assertIsNone(runner.script)

    def test_init_runner_with_hook(self):
        runner = FridaRunner('test')

        self.assertEqual(runner.hook, 'test')

    def test_handles_incoming_success_message_and_adds_message(self):
        self.runner._on_message(self.successful_message, None)

        self.assertEqual(len(self.runner.messages), 1)

    def test_handles_incoming_error_message_and_warns_while_adding_message(self):
        with capture(self.runner._on_message, self.error_message, None) as o:
            output = o

        expected_output = '[hook failure] error_message\n'

        self.assertEqual(output, expected_output)
        self.assertEqual(len(self.runner.messages), 1)

    @mock.patch('objection.utils.frida_transport.app_state.should_debug_hooks')
    def test_handles_incoming_success_message_and_prints_debug_output(self, should_debug_hooks):
        should_debug_hooks.return_value = True

        with capture(self.runner._on_message, self.successful_message, None) as o:
            output = o

        expected_output = """- [response] ------------------
{
  "payload": {
    "data": "data for unittest",
    "error_reason": null,
    "status": "success",
    "type": "send"
  }
}
- [./response] ----------------
"""

        self.assertEqual(output, expected_output)

    def test_hook_processor_beautifies_javascript_output_from_hook_property(self):
        self.runner.hook = self.sample_hook

        hook = self.runner._hook_processor()

        expected_outut = """var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-readable',
    data: { path: '', readable: Boolean(file.canRead()) }
};
send(response);"""

        self.assertEqual(hook, expected_outut)

    def test_can_fetch_last_message_with_multiple_messages_received(self):
        # ignore the output we get from the error message
        with capture(self.runner._on_message, self.error_message, None) as _:
            pass
        self.runner._on_message(self.successful_message, None)

        last_message = self.runner.get_last_message()

        self.assertEqual(last_message.data, self.successful_message['payload']['data'])

    def test_sets_hook_with_data(self):
        self.runner.set_hook_with_data('{{ test }}', test='testing123')

        self.assertEqual(self.runner.hook, 'testing123')
