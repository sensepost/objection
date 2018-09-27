import atexit
import json
import os

import click
import frida
from frida.core import ScriptExports

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

    def _on_message(self, message: dict, data):
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
                    click.secho('(agent) ' + message['payload'])

        except Exception as e:
            click.secho('Failed to process an incoming message from agent: {0}'.format(e), fg='red', bold=True)
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

            try:

                device = frida.get_device(
                    'tcp@{host}:{port}'.format(host=state_connection.host, port=state_connection.port))
                click.secho('Using networked device @`{n}`'.format(n=device.name), bold=True)

                return device

            except frida.TimedOutError:
                device = frida.get_device_manager().add_remote_device(
                    '{host}:{port}'.format(host=state_connection.host, port=state_connection.port))
                click.secho('Using networked device @`{n}`'.format(n=device.name), bold=True)

                return device

        raise Exception('Failed to find a device to attach to!')

    def _get_session(self) -> frida.core.Session:
        """
            Attempt to get a Frida session on a device.
        """

        self.device = self._get_device()

        # try and get the target process.
        try:

            debug_print('Attempting to attach to process: `{process}`'.format(process=state_connection.gadget_name))
            session = self.device.attach(state_connection.gadget_name)
            debug_print('Process attached!')
            self.resumed = True

            return session

        except frida.ProcessNotFoundError:
            debug_print(
                'Unable to find process: `{process}`, attempting spawn'.format(process=state_connection.gadget_name))

        # TODO: Handle the fact that gadget mode can't spawn

        self.spawned_pid = self.device.spawn(state_connection.gadget_name)
        debug_print('PID `{pid}` spawned, attaching...'.format(pid=self.spawned_pid))

        return self.device.attach(state_connection.gadget_name)

    def _get_agent_source(self) -> str:
        """
            Loads the frida-compiled agent from disk.

            :return:
        """

        if not os.path.exists(self.agent_path):
            raise Exception('Unable to locate Objection agent sources at: {location}'.format(
                location=self.agent_path))

        with open(self.agent_path, 'r') as f:
            agent = f.readlines()

        # If we are not in debug mode, strip the source map
        if not app_state.should_debug():
            agent = agent[:-1]

        return ''.join(agent)

    def inject(self):
        """
            Injects the Objection Agent.

            :return:
        """

        debug_print('Injecting agent...')

        self.session = self._get_session()
        self.script = self.session.create_script(source=self._get_agent_source())
        self.script.on('message', self._on_message)

        debug_print('Loading script')
        self.script.load()

        if not self.resumed:
            debug_print('Resuming PID `{pid}`'.format(pid=self.spawned_pid))
            self.device.resume(self.spawned_pid)

        click.secho('Agent v{version} injected!'.format(version=self.exports().version()), fg='green', dim=True)

        return self

    def exports(self) -> frida.core.ScriptExports:
        """
            Get the exports of the agent.

            :return:
        """

        return self.script.exports

    def unload(self) -> None:

        debug_print('Calling unload()')
        self.script.unload()

    def cleanup(self) -> None:
        """
            Cleanup an Agent

            :return:
        """

        # TODO: Ask agent to stop jobs

        if self.script:
            click.secho('Unloading objection agent...', dim=True)
            self.unload()
