import os
import threading
import time

import click
import frida

from .repl import Repl
from ..__init__ import __version__
from ..api.app import create_app as create_api_app
from ..commands.device import get_device_info
from ..commands.mobile_packages import patch_ios_ipa, patch_android_apk
from ..commands.plugin_manager import load_plugin
from ..state.app import app_state
from ..state.connection import state_connection
from ..utils.agent import Agent
from ..utils.helpers import normalize_gadget_name, print_frida_connection_help, warn_about_older_operating_systems, \
    debug_print


# Start the Click command group
@click.group()
@click.option('--network', '-N', is_flag=True, help='Connect using a network connection instead of USB.',
              show_default=True)
@click.option('--host', '-h', default='127.0.0.1', show_default=True)
@click.option('--port', '-p', required=False, default=27042, show_default=True)
@click.option('--api-host', '-ah', default='127.0.0.1', show_default=True)
@click.option('--api-port', '-ap', required=False, default=8888, show_default=True)
@click.option('--gadget', '-g', required=False, default='Gadget',
              help='Name of the Frida Gadget/Process to connect to.', show_default=True)
@click.option('--serial', '-S', required=False, default=None, help='A device serial to connect to.')
@click.option('--debug', '-d', required=False, default=False, is_flag=True,
              help='Enable debug mode with verbose output. (Includes agent source map in stack traces)')
def cli(network: bool, host: str, port: int, api_host: str, api_port: int,
        gadget: str, serial: str, debug: bool) -> None:
    """
        \b
             _   _         _   _
         ___| |_|_|___ ___| |_|_|___ ___
        | . | . | | -_|  _|  _| | . |   |
        |___|___| |___|___|_| |_|___|_|_|
              |___|(object)inject(ion)
        \b
             Runtime Mobile Exploration
                by: @leonjza from @sensepost

        By default, communications will happen over USB, unless the --network
        option is provided.
    """

    if debug:
        app_state.debug = debug

    # disable the usb comms if network is chosen.
    if network:
        state_connection.use_network()
        state_connection.host = host
        state_connection.port = port

    if serial:
        state_connection.device_serial = serial

    # set api parameters
    app_state.api_host = api_host
    app_state.api_port = api_port

    state_connection.gadget_name = normalize_gadget_name(gadget_name=gadget)


@cli.command()
def api():
    """
        Start the objection API server in headless mode.
    """

    agent = Agent()

    try:
        agent.inject()
    except frida.ServerNotRunningError as e:
        click.secho('Unable to connect to the frida server: {error}'.format(error=str(e)), fg='red')
        return

    state_connection.set_agent(agent=agent)

    click.secho('Starting API server on {host}:{port}'.format(
        host=app_state.api_host, port=app_state.api_port), fg='yellow', bold=True)

    create_api_app().run(host=app_state.api_host, port=app_state.api_port, debug=app_state.debug)


@cli.command()
@click.option('--startup-command', '-s', required=False, multiple=True,
              help='A command to run before the repl polls the device for information.')
@click.option('--quiet', '-q', required=False, default=False, is_flag=True,
              help='Do not display the objection logo on startup.')
@click.option('--file-commands', '-c', required=False, type=click.File('r'),
              help=('A file containing objection commands, separated by a '
                    'newline, that will run before the repl polls the device for information.'))
@click.option('--startup-script', '-S', required=False, type=click.File('r'),
              help='A script to import and run before the repl polls the device for information.')
@click.option('--enable-api', '-a', required=False, default=False, is_flag=True,
              help='Start the objection API server.')
@click.option('--plugin-folder', '-P', required=False, default=None, help='The folder to load plugins from.')
def explore(startup_command: str, quiet: bool, file_commands, startup_script: click.File, enable_api: bool,
            plugin_folder: str) -> None:
    """
        Start the objection exploration REPL.
    """

    agent = Agent()

    try:
        agent.inject()
    except (frida.ServerNotRunningError, frida.NotSupportedError) as e:
        click.secho('Unable to connect to the frida server: {error}'.format(error=str(e)), fg='red')
        return

    # set the frida agent
    state_connection.set_agent(agent=agent)

    # load plugins
    if plugin_folder:
        folder = os.path.abspath(plugin_folder)
        debug_print('[plugin] Plugins path is: {0}'.format(folder))

        for p in os.scandir(folder):
            # skip files and hidden directories
            if p.is_file() or p.name.startswith('.'):
                debug_print('[plugin] Skipping {0}'.format(p.name))
                continue

            debug_print('[plugin] Attempting to load plugin at {0}'.format(p.path))
            load_plugin([p.path])

    # start the main REPL
    r = Repl()

    # if we have a command to run, do that first before
    # the call to get_device_info().
    if startup_command:
        for command in startup_command:
            click.secho('Running a startup command... {0}'.format(command), dim=True)
            r.run_command(command)

    # If we have a script, import and run that asap
    if startup_script:
        click.secho('Importing and running startup script at: {location}'.format(location=startup_script), dim=True)
        response = agent.single(startup_script.read())
        print(response)

    try:

        # poll the device for information. this method also sets
        # the device type internally in state.device
        device_info = get_device_info()

    except (frida.TimedOutError, frida.ServerNotRunningError,
            frida.ProcessNotFoundError, frida.NotSupportedError) as e:

        click.secho('Could not connect with error: {0}'.format(str(e)), fg='red')
        print_frida_connection_help()

        return

    # process commands from a resource file
    if file_commands:
        click.secho('Running commands from file...', bold=True)
        for command in file_commands.readlines():

            # clean up newlines
            command = command.strip()

            # do nothing for empty lines
            if command == '':
                continue

            # run the command using the instantiated repl
            click.secho('Running: \'{0}\':\n'.format(command), dim=True)
            r.run_command(command)

    warn_about_older_operating_systems()

    # start the api server
    if enable_api:
        def api_thread():
            """
                Small method to run Flash non-blocking

                :return:
            """

            a = create_api_app()
            a.run(host=app_state.api_host, port=app_state.api_port)

        click.secho('Starting API server on {host}:{port}'.format(
            host=app_state.api_host, port=app_state.api_port), fg='yellow', bold=True)

        thread = threading.Thread(target=api_thread)
        thread.daemon = True
        thread.start()

        time.sleep(2)

    # run the REPL and wait for more commands
    r.set_prompt_tokens(device_info)
    r.start_repl(quiet=quiet)


@cli.command()
@click.option('--hook-debug', '-d', required=False, default=False, is_flag=True,
              help='Print compiled hooks as they are run to the screen and logfile.')
@click.argument('command', nargs=-1)
def run(hook_debug: bool, command: tuple) -> None:
    """
        Run a single objection command.
    """

    if len(command) <= 0:
        click.secho('Please specify a command to run', fg='red')
        return

    # specify if hooks should be debugged
    app_state.debug_hooks = hook_debug

    # Inject the agent
    agent = Agent()
    agent.inject()
    state_connection.set_agent(agent=agent)

    try:

        click.secho('Determining environment...', dim=True)
        get_device_info()

    except (frida.TimedOutError, frida.ServerNotRunningError) as e:
        click.secho('Error: {0}'.format(e), fg='red')
        return

    command = ' '.join(command)

    # use the methods in the main REPL to run the command
    click.secho('Running command... `{0}`'.format(command), dim=True)
    Repl().run_command(command)


@cli.command()
def version() -> None:
    """
        Prints the current version and exists.
    """

    click.secho('objection: {0}'.format(__version__))


@cli.command()
def device_type():
    """
        Get information about an attached device.
    """

    try:

        # Inject the agent
        agent = Agent()
        agent.inject()
        state_connection.set_agent(agent=agent)

        device_name, system_name, model, system_version = get_device_info()

    except frida.ProcessNotFoundError as e:

        click.secho('Could not connect with error: {0}'.format(str(e)), fg='red')
        print_frida_connection_help()

        return

    if state_connection.get_comms_type() == state_connection.TYPE_USB:
        click.secho('Connection: USB')

    elif state_connection.get_comms_type() == state_connection.TYPE_REMOTE:
        click.secho('Connection: Network')

    click.secho('Name: {0}'.format(device_name))
    click.secho('System: {0}'.format(system_name))
    click.secho('Model: {0}'.format(model))
    click.secho('Version: {0}'.format(system_version))


@cli.command()
@click.option('--source', '-s', help='The source IPA to patch', required=True)
@click.option('--gadget-version', '-V', help=('The gadget version to use. If not '
                                              'specified, the latest version will be used.'), default=None)
@click.option('--codesign-signature', '-c',
              help='Codesigning Identity to use. Get it with: `security find-identity -p codesigning -v`',
              required=True)
@click.option('--provision-file', '-P', help='The .mobileprovision file to use in the patched .ipa')
@click.option('--binary-name', '-b', help='Name of the Mach-O binary in the IPA (used to patch with Frida)')
@click.option('--skip-cleanup', '-k', is_flag=True,
              help='Do not clean temporary files once finished.', show_default=True)
@click.option('--pause', '-p', is_flag=True, help='Pause the patcher before rebuilding the IPA.',
              show_default=True)
@click.option('--unzip-unicode', '-z', is_flag=True, help='Unzip IPA containing Unicode characters.')
@click.option('--gadget-config', '-C', default=None, help=(
        'The gadget configuration file to use. '
        'Refer to https://frida.re/docs/gadget/ for more information.'), show_default=False)
@click.option('--script-source', '-l', default=None, help=(
        'A script file to use with the the "path" config type. '
        'Remember that use the name of this file in your "path". It will be next to the config.'), show_default=False)
def patchipa(source: str, gadget_version: str, codesign_signature: str, provision_file: str, binary_name: str,
             skip_cleanup: bool, pause: bool, unzip_unicode: bool, gadget_config: str, script_source: str) -> None:
    """
        Patch an IPA with the FridaGadget dylib.
    """

    patch_ios_ipa(**locals())


@cli.command()
@click.option('--source', '-s', help='The source APK to patch', required=True)
@click.option('--architecture', '-a',
              help=('The architecture of the device the patched APK will run on. '
                    'This can be determined with `adb shell getprop ro.product.cpu.abi`. '
                    'If it is not specified, this command will try and determine it automatically.'), required=False)
@click.option('--gadget-version', '-V', help=('The gadget version to use. If not '
                                              'specified, the latest version will be used.'), default=None)
@click.option('--pause', '-p', is_flag=True, help='Pause the patcher before rebuilding the APK.',
              show_default=True)
@click.option('--skip-cleanup', '-k', is_flag=True,
              help='Do not clean temporary files once finished.', show_default=True)
@click.option('--enable-debug', '-d', is_flag=True,
              help='Set the android:debuggable flag to true in the application manifest.', show_default=True)
@click.option('--network-security-config', '-N', is_flag=True, default=False,
              help='Include a network_security_config.xml file allowing for user added CA\'s to be trusted on '
                   'Android 7 and up. This option can not be used with the --skip-resources flag.')
@click.option('--skip-resources', '-D', is_flag=True, default=False,
              help='Skip resource decoding as part of the apktool processing.', show_default=False)
@click.option('--target-class', '-t', help='The target class to patch.', default=None)
@click.option('--use-aapt2', '-2', is_flag=True, default=False,
              help='Use the aapt2 binary instead of aapt as part of the apktool processing.', show_default=False)
@click.option('--gadget-config', '-c', default=None, help=(
        'The gadget configuration file to use. '
        'Refer to https://frida.re/docs/gadget/ for more information.'), show_default=False)
@click.option('--script-source', '-l', default=None,
              help=('A script file to use with the the "path" config type. '
                    'Specify "libfrida-gadget.script.so" as the "path" in your config.'), show_default=False)
@click.option('--ignore-nativelibs', '-n', is_flag=True, default=False,
              help=('Do not change the extractNativeLibs flag in the AndroidManifest.xml.'), show_default=False)
def patchapk(source: str, architecture: str, gadget_version: str, pause: bool, skip_cleanup: bool,
             enable_debug: bool, skip_resources: bool, network_security_config: bool, target_class: str,
             use_aapt2: bool, gadget_config: str, script_source: str, ignore_nativelibs: bool) -> None:
    """
        Patch an APK with the frida-gadget.so.
    """

    # ensure we decode resources if we have the network-security-config flag.
    if network_security_config and skip_resources:
        click.secho('The --network-security-config flag is incompatible with the --skip-resources flag.', fg='red')
        return

    # ensure we decode resources if we have the enable-debug flag.
    if enable_debug and skip_resources:
        click.secho('The --enable-debug flag is incompatible with the --skip-resources flag.', fg='red')
        return

    # ensure we decode resources if we do not have the --ignore-nativelibs flag.
    if not ignore_nativelibs and skip_resources:
        click.secho('The --ignore-nativelibs flag is required with the --skip-resources flag.', fg='red')
        return

    patch_android_apk(**locals())


if __name__ == '__main__':
    cli()
