import json
import random
import uuid
from time import strftime

import click
import frida
import jsbeautifier
from frida.core import ScriptExports
from jinja2 import Template

from ..state.app import app_state
from ..state.connection import state_connection
from ..state.jobs import job_manager_state
from ..utils.templates import template_env


class RunnerMessage(object):
    """ Object to store a response message from a Frida hook. """

    def __init__(self, message: dict, data) -> None:

        # set some defaults
        self.success = False
        self.error_reason = None
        self.type = None
        self.data = None
        self.extra_data = None

        if message['status'] == 'success':
            self.success = True

        if message['error_reason']:
            self.error_reason = message['error_reason']

        if message['type']:
            self.type = message['type']

        if message['data']:
            self.data = message['data']

        # we have extra data (aka second arg of frida send()),
        # add it
        if data is not None:
            self.extra_data = data

    def is_successful(self) -> bool:
        """
            Check if the message is considered a success message.

            :return:
        """

        return self.success

    def get_extra_data(self):
        """
            Returns the extra data send along with a hooks send() method
            as the second argument.

            :return:
        """

        return self.extra_data

    def __getitem__(self, item: str):
        """
            Allow for access to the data property using
            the self['item'] syntax.
        """

        if item not in self.data:
            raise Exception('{0} not in data.'.format(item))

        return self.data[item]

    def __getattr__(self, item: str):
        """
            Allow for access to the data property using
            the self.item syntax.
        """

        if item not in self.data:
            raise Exception('{0} not in data.'.format(item))

        return self.data[item]

    def __repr__(self) -> str:

        if self.is_successful():
            return '<SuccessfulRunnerMessage Type: {0} Data: {1}>'.format(self.type, self.data)

        else:
            return '<FailedRunnerMessage Reason: {0} Type: {1} Data: {2}>'.format(self.error_reason,
                                                                                  self.type,
                                                                                  self.data)


class FridaJobRunner(object):
    """
        Jobs that need to be continuously running
        are represented by an instance of this class
    """

    def __init__(self, name: str, args: list) -> None:
        """
            Init a new FridaJobRunner with a given name
        """

        self.id = uuid.uuid4()
        self.started = strftime('%Y-%m-%d %H:%M:%S')
        self.name = name
        self.has_had_error = False
        self.args = args

        self.hook = None
        self.session = None
        self.script = None

        # set a color for this jobs output
        self.success_color = random.choice(['green', 'blue', 'magenta', 'cyan'])

    def on_message(self, message: dict, data) -> None:
        """
            This handler is used to echoing data instead of
            the other being used for direct, one time runs.

            :param message:
            :param data:
            :return:
        """

        try:

            # log the hook response if needed
            if app_state.should_debug_hooks():
                click.secho('- [response] ' + '-' * 18, dim=True)
                click.secho(json.dumps(message, indent=2, sort_keys=True), dim=True)
                click.secho('- [./response] ' + '-' * 16, dim=True)

            # process the response
            if message and 'payload' in message:

                # extract the payload and echo the message to the tty
                payload = message['payload']

                # success messages are green...
                if payload['status'] == 'success':

                    click.secho('[{0}] [{1}] {2}'.format(
                        str(self.id)[-12:], payload['type'], payload['data']), fg=self.success_color, bold=True)

                # ... errors are red ...
                elif payload['status'] == 'error':

                    click.secho('[{0}] [{1}] {2}'.format(
                        str(self.id)[-12:], payload['type'], payload['error_reason']), fg='red', bold=True)

                    # mark this job as one that has had an error occur
                    self.has_had_error = True

                # everything else is.. who knows.
                else:

                    click.secho('[{0}][{1}] {2}'.format(
                        str(self.id)[-12:], payload['status'], payload['data']))

        except Exception as e:

            click.secho('Failed to process an incoming message from hook: {0}'.format(e),
                        fg='red', bold=True)

    def end(self) -> None:
        """
            The method used to 'finish' the hook by unloading it from
            the processes memory.

            :return:
        """

        self.script.unload()
        self.session = None

    def __repr__(self) -> str:
        return '<ID: {0} Started:{1}>'.format(self.id, self.started)


class FridaRunner(object):
    """
        Class to handle Frida runs, collecting
        responses in the messages property.
    """

    def __init__(self, hook: str = None):

        self.messages = []
        self.script = None

        if hook:
            self.hook = hook

    def _on_message(self, message: dict, data):
        """
            The callback to run when a message is received from a hook.

            :param message:
            :param data:
            :return:
        """

        try:

            # log the hook response if needed
            if app_state.should_debug_hooks():
                click.secho('- [response] ' + '-' * 18, dim=True)
                click.secho(json.dumps(message, indent=2, sort_keys=True), dim=True)
                click.secho('- [./response] ' + '-' * 16, dim=True)

            # process the response
            if message and 'payload' in message:

                self.messages.append(RunnerMessage(message['payload'], data))

                # check if the last message was an error
                msg = self.get_last_message()
                if not msg.is_successful():
                    click.secho('[hook failure] {0}'.format(msg.error_reason), fg='red')

        except Exception as e:
            click.secho('Failed to process an incoming message from hook: {0}'.format(e), fg='red', bold=True)
            raise e

    def _hook_processor(self, hook: str = None) -> str:
        """

            Clean up a hook by removing the lines that contain
            comments and newlines. Lines that start with // are
            considered comments lines. Thank you Cpt. Verbose.

            :param hook:
            :return:
        """

        if not hook:
            hook = self.hook

        # perform a final compile of the hook, processing any
        # remaining expressions and statements
        hook = template_env.from_string(hook).render()

        # cleanup any comments
        hook = '\n'.join([line for line in hook.splitlines() if not line.strip().startswith('//')])

        # remove redundant newlines
        hook = '\n'.join([x for x in hook.splitlines() if x.strip()])

        # log the hook if needed
        if app_state.should_debug_hooks():
            click.secho('- [hook] ' + '-' * 22, dim=True)
            click.secho(jsbeautifier.beautify(hook), dim=True)
            click.secho('- [./hook] ' + '-' * 20, dim=True)

        return hook

    def get_last_message(self) -> RunnerMessage:
        """
            Reusing a runner would mean multiple messages
            get stored. This method pops the last one as
            a response.
        """

        return self.messages[-1]

    @staticmethod
    def get_session():
        """
            Attempt to get a Frida session.
        """

        if state_connection.get_comms_type() == state_connection.TYPE_USB:
            return frida.get_usb_device(5).attach(state_connection.gadget_name)

        if state_connection.get_comms_type() == state_connection.TYPE_REMOTE:
            try:
                device = frida.get_device("tcp@%s:%d" % (state_connection.host, state_connection.port))
            except frida.TimedOutError:
                device = frida.get_device_manager().add_remote_device(
                    "%s:%d" % (state_connection.host, state_connection.port))

            return device.attach(state_connection.gadget_name)

    def set_hook_with_data(self, hook: str, **kwargs) -> None:
        """
            Sometimes, extra data is needed in a hook, and this
            is populated using Jinja templates. This method should
            make it easier to simply supply the **kwargs to use in
            template compilation.

            :param hook:
            :param kwargs:
            :return:
        """

        template = Template(hook)
        self.hook = template.render(**kwargs)

    def rpc_exports(self, hook: str = None) -> ScriptExports:
        """
            Loads a Fridascript and returns the exports that
            are available to use. This will allow for
            methods that are exposed via 'rpc.exports' in the
            loaded Frida scripts to be called directory from a
            runner.

            :param hook:
            :return:
        """

        if not hook:
            hook = self.hook

        if not hook:
            raise Exception('Like, we need a hook to run y0')

        session = self.get_session()
        self.script = session.create_script(self._hook_processor(hook))
        self.script.on('message', self._on_message)
        self.script.load()

        return self.script.exports

    def run(self, hook: str = None) -> None:
        """
            Run a hook synchronously and unload once finished.

            :param hook:
            :return:
        """

        if not hook:
            hook = self.hook

        if not hook:
            raise Exception('Like, we need a hook to run y0')

        session = self.get_session()
        script = session.create_script(self._hook_processor(hook))
        script.on('message', self._on_message)
        script.load()
        script.unload()

    def run_as_job(self, name: str, hook: str = None, args: list = None) -> None:
        """
            Run a hook as a background job, identified by a name.

            Jobs will have unique id's generated for them, so two jobs
            entries can have the same name without problems.

            :param name:
            :param hook:
            :param args:
            :return:
        """

        if not hook:
            hook = self.hook

        if not hook:
            raise Exception('Like, we need a hook to run y0')

        job = FridaJobRunner(name=name, args=args)

        click.secho('Job: {0} - Starting'.format(job.id), dim=True)

        job.hook = hook
        job.session = self.get_session()

        # attempt to load the hook. external scripts are also
        # loaded (with the import command) and may have some severe
        # syntax errors etc. to cater for this we wrap the load in
        # a try catch to ensure we don't crash the repl
        try:

            job.script = job.session.create_script(self._hook_processor(job.hook))

        except frida.InvalidArgumentError as e:

            # explain what went wrong and that the job was not 'started'
            click.secho('Failed to load script with error: {0}'.format(e), fg='red')
            click.secho('Job: {0} - Starting Failed'.format(job.id), fg='red', dim=True)

            return

        # load the job script
        job.script.on('message', job.on_message)
        job.script.load()

        # check if any errors in the script itself were thrown. if there
        # were, lets assume it failed and unload the script.
        if job.has_had_error:
            click.secho('Unloading script due to startup errors.', fg='red')
            self.unload_script()

            return

        # tell the state manager about this job
        job_manager_state.add_job(job)
        click.secho('Job: {0} - Started'.format(job.id), fg='green')

    def unload_script(self) -> None:
        """
            Unloads a script if one exists in the script property.

            This method would only really be used with hooks that
            make use of rpc exports.

            :return:
        """

        if self.script:
            self.script.unload()
