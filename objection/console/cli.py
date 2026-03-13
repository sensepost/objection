import threading
import time
from pathlib import Path

import click
from frida import ServerNotRunningError

from objection.commands.plugin_manager import load_plugin
from objection.utils.agent import Agent, AgentConfig
from objection.utils.helpers import debug_print, warn_about_older_operating_systems
from .repl import Repl
from ..__init__ import __version__
from ..commands.mobile_packages import patch_ios_ipa, patch_android_apk, sign_android_apk
from ..state.api import api_state
from ..state.app import app_state
from ..state.connection import state_connection


def get_agent() -> Agent:
    """ get_agent bootstraps an agent instance """
    agent = Agent(AgentConfig(
        name=state_connection.name,
        host=state_connection.host,
        port=state_connection.port,
        device_type=state_connection.device_type,
        device_id=state_connection.device_id,
        spawn=state_connection.spawn,
        foremost=state_connection.foremost,
        debugger=state_connection.debugger,
        pause=not state_connection.no_pause,
        uid=state_connection.uid
    ))

    try:
        agent.run()
    except ServerNotRunningError:
        click.secho('Frida server or gadget is not running on the target!', fg='red')
        exit(1)

    return agent


# Start the Click command group
@click.group()
@click.option('--network', '-N', is_flag=True, help='Connect using a network connection instead of USB.',
              show_default=True)
@click.option('--host', '-h', default='127.0.0.1', show_default=True)
@click.option('--port', '-P', required=False, default=27042, show_default=True)
@click.option('--api-host', '-ah', default='127.0.0.1', show_default=True)
@click.option('--api-port', '-ap', required=False, default=8888, show_default=True)
@click.option('--name', '-n', required=False,
              help='Name or bundle identifier to attach to.', show_default=True)
@click.option('--gadget', '-g', is_eager=True, hidden=True, deprecated="Please use '-n' or '--name' instead")
@click.option('--serial', '-S', required=False, default=None, help='A device serial to connect to.')
@click.option('--debug', '-d', required=False, default=False, is_flag=True,
              help='Enable debug mode with verbose output.')
@click.option('--spawn', '-s', required=False, is_flag=True, help='Spawn the target.')
@click.option('--no-pause', '-p', required=False, is_flag=True, help='Resume the target immediately.')
@click.option('--foremost', '-f', required=False, is_flag=True, help='Use the current foremost application.')
@click.option('--debugger', required=False, default=False, is_flag=True, help='Enable the Chrome debug port.')
@click.option('--uid', required=False, default=None, help='Specify the uid to run as (Android only).')
def cli(network: bool, host: str, port: int, api_host: str, api_port: int,
        name: str, gadget: str, serial: str, debug: bool, spawn: bool, no_pause: bool,
        foremost: bool, debugger: bool, uid: int) -> None:
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
    """

    if debug:
        app_state.debug = debug

    if network:
        state_connection.use_network()
        state_connection.host = host
        state_connection.port = port

    if serial:
        state_connection.device_id = serial

    # set api parameters
    app_state.api_host = api_host
    app_state.api_port = api_port

    # Backwards compatibility
    if gadget is not None:
        name = gadget

    state_connection.name = name
    state_connection.spawn = spawn
    state_connection.no_pause = no_pause
    state_connection.foremost = foremost
    state_connection.debugger = debugger
    state_connection.uid = uid


@cli.command()
def api():
    """
        Start the objection API server in headless mode.
    """

    agent = get_agent()
    state_connection.set_agent(agent=agent)

    click.secho(f'Starting API server on {app_state.api_host}:{app_state.api_port}', fg='yellow', bold=True)
    api_state.start(app_state.api_host, app_state.api_port, app_state.debug)


@cli.command()
@click.option('--plugin-folder', '-P', required=False, default=None, help='The folder to load plugins from.')
@click.option('--quiet', '-q', required=False, default=False, is_flag=True)
@click.option('--startup-command', '-s', required=False, multiple=True,
              help='A command to run before the repl polls the device for information.')
@click.option('--file-commands', '-c', required=False, type=click.File('r'),
              help=('A file containing objection commands, separated by a '
                    'newline, that will run before the repl polls the device for information.'))
@click.option('--startup-script', '-S', required=False, type=click.File('r'),
              help='A script to import and run before the repl polls the device for information.')
@click.option('--enable-api', '-a', required=False, default=False, is_flag=True,
              help='Start the objection API server.')
def start(plugin_folder: str, quiet: bool, startup_command: str, file_commands, startup_script: click.File,
          enable_api: bool) -> None:
    """
        Start a new session
    """

    agent = get_agent()
    state_connection.set_agent(agent)

    # load plugins
    if plugin_folder:
        folder = Path(plugin_folder).resolve()
        debug_print(f'[plugin] Plugins path is: {folder}')
        for p in folder.iterdir():
            if p.is_file() or p.name.startswith('.'):
                debug_print(f'[plugin] Skipping {p.name}')
                continue

            debug_print(f'[plugin] Attempting to load plugin at {p}')
            load_plugin([p])

    repl = Repl()

    if startup_script:
        click.secho(f'Importing and running startup script at: {startup_script}', dim=True)
        script_name = f'startup_script<{startup_script.name}>'
        agent.attach_script(script_name, startup_script.read())

    if startup_command:
        for command in startup_command:
            click.secho(f'Running a startup command... {command}', dim=True)
            repl.run_command(command)

    if file_commands:
        click.secho('Running commands from file...', bold=True)
        for command in file_commands.readlines():

            command = command.strip()
            if command == '':
                continue

            # run the command using the instantiated repl
            click.secho(f'Running: \'{command}\':\n', dim=True)
            repl.run_command(command)

    warn_about_older_operating_systems()

    # start the api server
    if enable_api:
        def api_thread():
            """ Small method to run Flask non-blocking """
            api_state.start(app_state.api_host, app_state.api_port)

        click.secho(f'Starting API server on {app_state.api_host}:{app_state.api_port}', fg='yellow', bold=True)
        thread = threading.Thread(target=api_thread)
        thread.daemon = True
        thread.start()

        time.sleep(2)

    # drop into the repl
    repl.run(quiet=quiet)

# Some ugly backwards compatibility
@cli.command(deprecated="Use 'objection start' instead of 'objection explore'", hidden=True)
@click.option('--plugin-folder', '-P', required=False, default=None, help='The folder to load plugins from.')
@click.option('--quiet', '-q', required=False, default=False, is_flag=True)
@click.option('--startup-command', '-s', required=False, multiple=True,
              help='A command to run before the repl polls the device for information.')
@click.option('--file-commands', '-c', required=False, type=click.File('r'),
              help=('A file containing objection commands, separated by a '
                    'newline, that will run before the repl polls the device for information.'))
@click.option('--startup-script', '-S', required=False, type=click.File('r'),
              help='A script to import and run before the repl polls the device for information.')
@click.option('--enable-api', '-a', required=False, default=False, is_flag=True,
              help='Start the objection API server.')
def explore(plugin_folder: str, quiet: bool, startup_command: str, file_commands, startup_script: click.File,
            enable_api: bool) -> None:
    """
        Deprecated: Use 'start' instead.
    """
    # Call the start command's callback directly
    ctx = click.get_current_context()
    ctx.invoke(start,
               plugin_folder=plugin_folder,
               quiet=quiet,
               startup_command=startup_command,
               file_commands=file_commands,
               startup_script=startup_script,
               enable_api=enable_api)

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

    agent = get_agent()
    state_connection.set_agent(agent=agent)

    command = ' '.join(command)

    # use the methods in the main REPL to run the command
    click.secho('Running command... `{0}`'.format(command), dim=True)
    Repl().run_command(command)


@cli.command()
def version() -> None:
    """
        Prints the current version and exits.
    """

    click.secho('objection: {0}'.format(__version__))


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
@click.option('--bundle-id', '-b', default=None, help='The bundleid to set when codesigning the IPA')
def patchipa(source: str, gadget_version: str, codesign_signature: str, provision_file: str, binary_name: str,
             skip_cleanup: bool, pause: bool, unzip_unicode: bool, gadget_config: str, script_source: str,
             bundle_id: str) -> None:
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
@click.option('--skip-signing', '-C', is_flag=True, default=False,
              help='Skip signing the apk file.', show_default=False)
@click.option('--target-class', '-t', help='The target class to patch.', default=None)
@click.option('--use-aapt2', '-2', is_flag=True, default=False,
              help='Use the aapt2 binary instead of aapt as part of the apktool processing and for badge dumping.', show_default=False)
@click.option('--gadget-config', '-c', default=None, help=(
        'The gadget configuration file to use. '
        'Refer to https://frida.re/docs/gadget/ for more information.'), show_default=False)
@click.option('--script-source', '-l', default=None,
              help=('A script file to use with the the "path" config type. '
                    'Specify "libfrida-gadget.script.so" as the "path" in your config.'), show_default=False)
@click.option('--ignore-nativelibs', '-n', is_flag=True, default=False,
              help='Do not change the extractNativeLibs flag in the AndroidManifest.xml.', show_default=False)
@click.option('--manifest', '-m', help='A decoded AndroidManifest.xml file to read.', default=None)
@click.option('--only-main-classes', help="Only patch classes that are in the main dex file.", is_flag=True, default=False)
@click.option('--fix-concurrency-to', '-j', help="Only use N threads for repackaging - set to 1 if running into OOM errors.", default=None)

def patchapk(source: str, architecture: str, gadget_version: str, pause: bool, skip_cleanup: bool,
             enable_debug: bool, skip_resources: bool, network_security_config: bool, target_class: str,
             use_aapt2: bool, gadget_config: str, script_source: str, ignore_nativelibs: bool, manifest: str, skip_signing: bool, only_main_classes:bool = False, fix_concurrency_to = None) -> None:
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


@cli.command()
@click.argument('sources', nargs=-1, type=click.Path(exists=True), required=True)
@click.option('--skip-cleanup', '-k', is_flag=True,
              help='Do not clean temporary files once finished.', show_default=True)
def signapk(sources, skip_cleanup: bool) -> None:
    """
        Zipalign and sign an APK with the objection key.
    """
    for source in sources:
        sign_android_apk(source, skip_cleanup)


if __name__ == '__main__':
    cli()
