import json
import uuid
from time import strftime

import click
import frida
from jinja2 import Template

from ..state.connection import state_connection
from ..state.jobs import job_manager_state


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
        Jobs that need to be continously running
        are represented by an instance of this class
    """

    def __init__(self, name: str) -> None:
        """
            Init a new FridaJobRunner with a given name

            :param name:
        """

        self.id = uuid.uuid4()
        self.started = strftime('%Y-%m-%d %H:%M:%S')
        self.name = name

        self.hook = None
        self.session = None
        self.script = None

    def on_message(self, message: dict, data) -> None:
        """
            This handler is used to echoing data instead of
            the other being used for direct, one time runs.

            :param message:
            :param data:
            :return:
        """

        try:

            if message and 'payload' in message:

                # extract the payload and echo the message to the tty
                payload = json.loads(message['payload'])

                # success messages are green...
                if payload['status'] == 'success':

                    click.secho('[{0}] [{1}] {2}'.format(
                        str(self.id)[-12:], payload['type'],
                        payload['data']), fg='green', bold=True)

                # ... errors are red ...
                elif payload['status'] == 'error':

                    click.secho('[{0}] [{1}] {2}'.format(
                        str(self.id)[-12:], payload['type'],
                        payload['error_reason']), fg='red', bold=True)

                # everything else is.. who knows.
                else:

                    click.secho('[{0}][{1}] {2}'.format(
                        str(self.id)[-12:], payload['status'], payload['data']))

        except Exception as e:
            click.secho('Failed to process an incoming message from hook: {0}'.format(e))

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

            if message and 'payload' in message:
                payload = json.loads(message['payload'])
                self.messages.append(RunnerMessage(payload, data))

                # check if the last message was an error
                msg = self.get_last_message()
                if not msg.is_successful():
                    click.secho('Frida hook failure: {0}'.format(msg.error_reason), fg='red')

        except Exception as e:
            click.secho('Failed to process an incoming message from hook: {0}'.format(e))

    def get_last_message(self) -> RunnerMessage:
        """
            Reusing a runner would mean multiple messages
            get stored. This method pops the last one as
            a response.
        """

        return self.messages[-1]

    def get_session(self):
        """
            Attempt to get a Frida session.
        """

        if state_connection.get_comms_type() == state_connection.TYPE_USB:
            return frida.get_usb_device().attach(state_connection.gadget_name)

        if state_connection.get_comms_type() == state_connection.TYPE_REMOTE:
            return frida.get_remote_device().attach(state_connection.gadget_name)

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

    def run(self, hook: str = None) -> None:
        """
            Run a hook syncronously and unload once finished.

            :param hook:
            :return:
        """

        if not hook:
            hook = self.hook

        if not hook:
            raise Exception('Like, we need a hook to run y0')

        session = self.get_session()
        script = session.create_script(hook)
        script.on('message', self._on_message)
        script.load()
        script.unload()

    def run_as_job(self, name: str, hook: str = None) -> None:
        """
            Run a hook as a background job, identified by a name.

            Jobs will have unique id's generated for them, so two jobs
            entries can have the same name without problems.

            :param name:
            :param hook:
            :return:
        """

        if not hook:
            hook = self.hook

        if not hook:
            raise Exception('Like, we need a hook to run y0')

        job = FridaJobRunner(name=name)

        click.secho('Job: {0} - Starting'.format(job.id), dim=True)

        job.hook = hook
        job.session = self.get_session()

        # attempt to load the hook. external scripts are also
        # loaded (with the import command) and may have some severe
        # syntax errors etc. to cater for this we wrap the load in
        # a try catch to ensure we dont crash the repl
        try:

            job.script = job.session.create_script(job.hook)

        except frida.InvalidArgumentError as e:

            # explain what went wrong and that the job was not 'started'
            click.secho('Failed to load script with error: {0}'.format(e), fg='red')
            click.secho('Job: {0} - Starting Failed'.format(job.id), fg='red', dim=True)

            return

        job.script.on('message', job.on_message)
        job.script.load()

        # tell the state manager about this job
        job_manager_state.add_job(job)
        click.secho('Job: {0} - Started'.format(job.id), fg='green')
