import argparse
import atexit
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from pprint import pprint

import click
import frida

from objection.state.app import app_state
from objection.state.connection import state_connection
from objection.state.device import device_state, Ios, Android, Macos
from objection.state.jobs import job_manager_state
from objection.utils.helpers import debug_print


@dataclass
class AgentConfig(object):
    """ Default configuration for an Agent instance """

    name: str
    host: str = None
    port: int = None
    device_type: str = 'usb'
    device_id: str = None
    foremost: bool = False
    spawn: bool = False
    pause: bool = True
    debugger: bool = False
    uid: int = None


class OutputHandlers(object):
    """ Output handlers for an Agent instance """

    def device_output(self):
        pass

    def device_lost(self):
        pass

    @staticmethod
    def session_on_detached(message: str, crash):
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
    def script_on_message(message: dict, data):
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


class Agent(object):
    """ Class to manage the lifecycle of the objection Frida agent """

    agent_path: Path = None
    c: AgentConfig

    handlers: OutputHandlers

    device: frida.core.Device = None
    session: frida.core.Session = None
    script: frida.core.Script = None

    pid: int = None
    resumed: bool = True

    def __init__(self, config: AgentConfig):
        """ initialises the agent class """

        self.agent_path = Path(__file__).parent.parent / 'agent.js'
        if not self.agent_path.exists():
            raise Exception(f'Unable to locate Objection agent sources at: {self.agent_path}. '
                            'If this is a development install, check the wiki for more '
                            'information on building the agent.')
        debug_print('Agent path is: {path}'.format(path=self.agent_path))

        self.config = config
        debug_print(f'agent config: {self.config}')
        self.handlers = OutputHandlers()

        atexit.register(self.teardown)

    def _get_agent_source(self) -> str:
        """
            Loads the frida-compiled agent from disk.

            :return:
        """

        with open(self.agent_path, 'r', encoding='utf-8') as f:
            src = f.readlines()

        return ''.join([str(x) for x in src])

    def set_device(self):
        """
            Set's the target device to work with.

            :return:
        """

        if self.config.device_id is not None:
            self.device = frida.get_device(self.config.device_id)

        elif (self.config.host is not None) or (self.config.device_type == 'remote'):
            if self.config.host is None:
                self.device = frida.get_remote_device()
            else:
                host = self.config.host
                port = self.config.port
                self.device = frida.get_device_manager() \
                    .add_remote_device(f'{host}:{port}' if host is not None else f'127.0.0.1:{port}')

        elif self.config.device_type is not None:
            for dev in frida.enumerate_devices():
                if dev.type == self.config.device_type:
                    self.device = dev
        else:
            self.device = frida.get_local_device()

        # surely we have a device by now?
        if self.device is None:
            raise Exception('Unable to find a device')

        self.device.on('output', self.handlers.device_output)
        self.device.on('lost', self.handlers.device_lost)

        debug_print(f'device determined as: {self.device}')

    def set_target_pid(self):
        """
            Set's the PID we should attach to. This method will spawn the
            target if needed. The resumed value is also toggled here.

            Defaults:
                resumed: bool = True

            :return:
        """

        if (self.config.name is None) and (not self.config.foremost):
            raise Exception('Need a target name to spawn/attach to')

        if self.config.foremost:
            try:
                app = self.device.get_frontmost_application()
            except Exception as e:
                raise Exception(f'Could not get foremost application on {self.device.name}: {e}')

            if app is None:
                raise Exception(f'No foremost application on {self.device.name}')

            self.pid = app.pid
            # update the global state for the prompt etc.
            state_connection.name = app.identifier

        elif self.config.spawn:
            if self.config.uid is not None:
                self.pid = self.device.spawn(self.config.name, uid=int(self.config.uid))
            else:
                self.pid = self.device.spawn(self.config.name)
            self.resumed = False
        else:
            # check if the name is actually an integer. this way we can
            # assume we got the target PID already
            try:
                self.pid = int(self.config.name)
            except ValueError:
                pass

            if self.pid is None:
                # last resort, maybe we have a process name
                self.pid = self.device.get_process(self.config.name).pid

        debug_print(f'process PID determined as {self.pid}')

    def attach(self):
        """
            Attaches to an enumerated PID, injecting the objection agent.

            :return:
        """

        if self.pid is None:
            raise Exception('A PID needs to be set before attach()')

        if self.config.uid is None:
            self.session = self.device.attach(self.pid)
        else:
            self.session = self.device.attach(self.pid, uid=self.config.uid)

        self.session.on('detached', self.handlers.session_on_detached)

        if self.config.debugger:
            self.session.enable_debugger()

        self.script = self.session.create_script(source=self._get_agent_source())
        self.script.on('message', self.handlers.script_on_message)
        self.script.load()

    def attach_script(self, source):
        """
            Attaches an arbitrary script session.

            # TODO: Implement some script management so we could unload these later.

            :param source:
            :return:
        """

        session = self.device.attach(self.pid)
        script = session.create_script(source=source)
        script.on('message', self.handlers.script_on_message)
        script.load()

    def update_device_state(self):
        """
            Updates the device_state. Useful in other parts where we
            need platform specific decisions.

            :return:
        """

        params = self.device.query_system_parameters()

        # set os platform
        if params['os']['id'] == 'ios':
            device_state.set_platform(Ios)
        elif params['os']['id'] == 'android':
            device_state.set_platform(Android)
        elif params['os']['id'] == 'macos':
            device_state.set_platform(Macos)
        # set os version
        device_state.set_version(params['os']['version'])

    def resume(self):
        """
            Resume the target pid.

            :return:
        """

        if self.resumed:
            return

        if not self.pid:
            raise Exception('Cannot resume without self.pid')

        self.device.resume(self.pid)
        self.resumed = True

    def exports(self):
        """
            Returns the RPC exports exposed by the Frida agent

            :return:
        """

        if not self.script:
            raise Exception('Need a script created before reading exports()')

        return self.script.exports

    def run(self):
        """
            Run the Agent by getting a device, setting the target pid and attaching.
            If we should skip pausing, also resume the process.

            :return:
        """

        self.set_device()
        self.set_target_pid()
        self.attach()

        # internal state
        self.update_device_state()

        if not self.config.pause:
            debug_print('asked to run without pausing, so resuming in run()')
            self.resume()

    def teardown(self):
        try:
            if self.script:
                click.secho('Asking jobs to stop...', dim=True)
                job_manager_state.cleanup()
                click.secho('Unloading objection agent...', dim=True)
                self.script.unload()
        except frida.InvalidOperationError as e:
            click.secho(f'Unable to run cleanups: {e}', fg='yellow', dim=True)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('name', help='target app to attach/spawn. needs to be bundle '
                                     'identifier for spawn')
    parser.add_argument('--no-spawn', dest='no_spawn', default=True, action='store_false',
                        help='do not try and spawn the target app')
    parser.add_argument('--no-pause', dest='no_pause', default=True, action='store_false',
                        help='resume the app after spawning')
    parser.add_argument('--debug', default=False, action='store_true', help='print debug logging')
    args = parser.parse_args()

    if args.name is None:
        print('error: need a target app to attach/spawn')
        sys.exit(1)

    if args.debug:
        app_state.debug = True

    c = AgentConfig(name=args.name, spawn=args.no_spawn, pause=args.no_pause)
    a = Agent(config=c)
    a.run()

    print(a.exports().env_frida())
