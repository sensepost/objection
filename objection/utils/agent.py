import atexit
import json
import os
from pprint import pprint

import click
import frida
from frida.core import ScriptExports

from objection.state.jobs import job_manager_state
from ..state.app import app_state
from ..state.connection import state_connection
from ..utils.helpers import debug_print


class Agent(object):
    """ Class to manage the lifecycle of the Frida agent. """

    def __init__(self):
        """
            Initialises a new Agent instance to run the Frida agent.
        """

        # Compiled frida agent path
        self.agent_path = os.path.abspath(
            os.path.join(os.path.abspath(os.path.dirname(__file__)), '../', 'agent.js'))
        debug_print('Agent path is: {path}'.format(path=self.agent_path))

        self.session = None
        self.script = None

        self.device = None
        self.spawned_pid = None
        self.resumed = False

        atexit.register(self.cleanup)

    @staticmethod
    def on_message(message: dict, data):
        """
            The callback to run when a message is received from the agent.

            :param message:
            :param data:

            :return:
        """

        try:

            # log the hook response if needed
            if app_state.should_debug():
                click.secho('- [incoming message] ' + '-' * 18, dim=True)
                click.secho(json.dumps(message, indent=2, sort_keys=True), dim=True)
                click.secho('- [./incoming message] ' + '-' * 16, dim=True)

            # process the response
            if message and 'payload' in message:
                if len(message['payload']) > 0:
                    if isinstance(message['payload'], dict):
                        click.secho('(agent) ' + json.dumps(message['payload']))
                    elif isinstance(message['payload'], str):
                        click.secho('(agent) ' + message['payload'])
                    else:
                        click.secho('Dumping unknown agent message', fg='yellow')
                        pprint(message['payload'])

        except Exception as e:
            click.secho('Failed to process an incoming message from agent: {0}'.format(e), fg='red', bold=True)
            raise e

    @staticmethod
    def on_detach(message: str, crash):
        """
            The callback to run for the detach signal

            :param message:
            :param crash:

            :return:
        """

        try:

            # log the hook response if needed
            if app_state.should_debug():
                click.secho('- [incoming message] ' + '-' * 18, dim=True)
                click.secho(json.dumps(message, indent=2, sort_keys=True), dim=True)
                click.secho('- [./incoming message] ' + '-' * 16, dim=True)

            # process the response
            if message:
                click.secho('(session detach message) ' + message, fg='red')

            # Frida 12.3 crash reporting
            # https://www.nowsecure.com/blog/2019/02/07/frida-12-3-debuts-new-crash-reporting-feature/
            if crash:
                click.secho('(process crash report)', fg='red')
                click.secho('\n\t{0}'.format(crash.report), dim=True)

        except Exception as e:
            click.secho('Failed to process an incoming message for a session detach signal: {0}'.format(e), fg='red',
                        bold=True)
            raise e

    @staticmethod
    def _get_device() -> frida.core.Device:
        """
            Attempt to get a handle on a device.

            :return:
        """

        if state_connection.get_comms_type() == state_connection.TYPE_USB:

            if state_connection.device_serial:
                device = frida.get_device(state_connection.device_serial)
                click.secho('Using USB device `{n}`'.format(n=device.name), bold=True)

                return device

            else:
                device = frida.get_usb_device(5)
                click.secho('Using USB device `{n}`'.format(n=device.name), bold=True)

                return device

        if state_connection.get_comms_type() == state_connection.TYPE_REMOTE:
            device = frida.get_device_manager().add_remote_device('{host}:{port}'.format(
                host=state_connection.host, port=state_connection.port))
            click.secho('Using networked device @`{n}`'.format(n=device.name), bold=True)

            return device

        raise Exception('Failed to find a device to attach to!')

    def get_session(self) -> frida.core.Session:
        """
            Attempt to get a Frida session on a device.
        """

        if self.session:
            return self.session

        self.device = self._get_device()

        # try and get the target process.
        try:

            debug_print('Attempting to attach to process: `{process}`'.format(
                process=state_connection.gadget_name))
            self.session = self.device.attach(state_connection.gadget_name)
            debug_print('Process attached!')
            self.resumed = True

            self.session.on('detached', self.on_detach)

            return self.session

        except frida.ProcessNotFoundError:
            debug_print('Unable to find process: `{process}`, attempting spawn'.format(
                process=state_connection.gadget_name))

        # TODO: Handle the fact that gadget mode can't spawn

        self.spawned_pid = self.device.spawn(state_connection.gadget_name)
        debug_print('PID `{pid}` spawned, attaching...'.format(pid=self.spawned_pid))

        self.session = self.device.attach(self.spawned_pid)
        return self.session

    def _get_agent_source(self) -> str:
        """
            Loads the frida-compiled agent from disk.

            :return:
        """

        if not os.path.exists(self.agent_path):
            raise Exception('Unable to locate Objection agent sources at: {location}. '
                            'If this is a development install, check the wiki for more '
                            'information on building the agent.'.format(location=self.agent_path))

        with open(self.agent_path, 'r', encoding='utf-8') as f:
            agent = f.readlines()

        # If we are not in debug mode, strip the source map
        if not app_state.should_debug():
            agent = agent[:-1]

        return ''.join([str(x) for x in agent])

    def inject(self):
        """
            Injects the Objection Agent.

            :return:
        """

        debug_print('Injecting agent...')

        session = self.get_session()
        self.script = session.create_script(source=self._get_agent_source())
        self.script.on('message', self.on_message)
        self.script.load()

        if not self.resumed:
            debug_print('Resuming PID `{pid}`'.format(pid=self.spawned_pid))
            self.device.resume(self.spawned_pid)

        # ping the agent
        if not self.exports().ping():
            click.secho('Failed to ping the agent', fg='red')
            raise Exception('Failed to communicate with agent')

        click.secho('Agent injected and responds ok!', fg='green', dim=True)

        return self

    def single(self, source: str, unload=True) -> list:
        """
            Executes a single adhoc script, capturing the output and returning it.

            :param source:
            :param unload:
            :return:
        """

        message_buffer = []

        def on_message(message: str, data):
            """
                Simple message buffer helper.

                :param message:
                :param data:
                :return:
            """

            message_buffer.append(message)

        session = self.get_session()
        script = session.create_script(source=source)
        script.on('message', on_message)
        script.load()

        if not self.resumed:
            debug_print('Resuming PID `{pid}`'.format(pid=self.spawned_pid))
            self.device.resume(self.spawned_pid)

        if unload:
            script.unload()

        return message_buffer

    def background(self, source: str):
        """
            Executes an artibrary Frida script in the background, using the
            default on_message handler for incoming messages from the script.

            :param source:
            :return:
        """

        debug_print('Loading a background script')

        session = self.get_session()
        script = session.create_script(source=source)
        script.on('message', self.on_message)
        script.load()

        if not self.resumed:
            debug_print('Resuming PID `{pid}`'.format(pid=self.spawned_pid))
            self.device.resume(self.spawned_pid)

        debug_print('Background script loaded')

    def exports(self) -> frida.core.ScriptExports:
        """
            Get the exports of the agent.

            :return:
        """

        return self.script.exports

    def unload(self) -> None:
        """
            Run cleanup routines on an agent.

            :return:
        """

        if self.script:
            debug_print('Calling unload()')
            self.script.unload()

    def cleanup(self) -> None:
        """
            Cleanup an Agent

            :return:
        """

        try:

            if self.script:
                click.secho('Asking jobs to stop...', dim=True)
                job_manager_state.cleanup()
                click.secho('Unloading objection agent...', dim=True)
                self.unload()

        except frida.InvalidOperationError as e:
            click.secho('Unable to run cleanups: {error}'.format(error=str(e)), fg='yellow', dim=True)
