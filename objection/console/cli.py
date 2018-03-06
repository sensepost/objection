import click
import frida

from .repl import Repl
from ..__init__ import __version__
from ..commands.device import get_device_info
from ..commands.mobile_packages import patch_ios_ipa, patch_android_apk
from ..state.app import app_state
from ..state.connection import state_connection
from ..utils.helpers import normalize_gadget_name, print_frida_connection_help


# Start the Click command group
@click.group()
@click.option('--network', '-N', is_flag=True, help='Connect using a network connection instead of USB.',
              show_default=True)
@click.option('--host', '-h', default='127.0.0.1', show_default=True)
@click.option('--port', '-p', required=False, default=27042, show_default=True)
@click.option('--gadget', '-g', required=False, default='Gadget',
              help='Name of the Frida Gadget/Process to connect to.',
              show_default=True)
def cli(network: bool, host: str, port: int, gadget: str) -> None:
    """
        \b
             _     _         _   _
         ___| |_  |_|___ ___| |_|_|___ ___
        | . | . | | | -_|  _|  _| | . |   |
        |___|___|_| |___|___|_| |_|___|_|_|
                |___|(object)inject(ion)
        \b
             Runtime Mobile Exploration
                by: @leonjza from @sensepost

        By default, communications will happen over USB, unless the --network
        option is provided.
    """

    # disable the usb comms if network is chosen.
    if network:
        state_connection.use_network()
        state_connection.host = host
        state_connection.port = port

    state_connection.gadget_name = normalize_gadget_name(gadget_name=gadget)


@cli.command()
@click.option('--startup-command', '-s', required=False, multiple=True,
              help='A command to run before the repl polls the device for information.')
@click.option('--startup-script', '-S', required=False,
              help='A script to import and run before the repl polls the device for information.')
@click.option('--hook-debug', '-d', required=False, default=False, is_flag=True,
              help='Print compiled hooks as they are run to the screen and logfile.')
@click.option('--quiet', '-q', required=False, default=False, is_flag=True,
              help='Do not display the objection logo on startup.')
@click.option('--file-commands', '-c', required=False, type=click.File('r'),
              help=('A file containing objection commands, seperated by a ' 'newline, that will be '
                    'executed before showing the prompt.'))
def explore(startup_command: str, startup_script: str, hook_debug: bool, quiet: bool, file_commands) -> None:
    """
        Start the objection exploration REPL.
    """

    # specify if hooks should be debugged
    app_state.debug_hooks = hook_debug

    # start the main REPL
    r = Repl()

    # if we have a command to run, do that first before
    # the call to get_device_info().
    if startup_command:
        for command in startup_command:
            click.secho('Running a startup command... {0}'.format(command), dim=True)
            r.run_command(command)

    # if we have a startup script to run, use the 'import' command
    # and give it the users path.
    if startup_script:
        click.secho('Importing and running a startup script...', dim=True)
        r.run_command('import {0}'.format(startup_script))

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
@click.option('--provision-file', '-p', help='The .mobileprovision file to use in the patched .ipa')
@click.option('--binary-name', '-b', help='Name of the Mach-O binary in the IPA (used to patch with Frida)')
@click.option('--skip-cleanup', '-k', is_flag=True,
              help='Do not clean temporary files once finished.', show_default=True)
def patchipa(source: str, gadget_version: str, codesign_signature: str, provision_file: str, binary_name: str,
             skip_cleanup: bool) -> None:
    """
        Patch an IPA with the FridaGadget dylib.
    """

    patch_ios_ipa(**locals())


@cli.command()
@click.option('--source', '-s', help='The source APK to patch', required=True)
@click.option('--architecture', '-a', help=('The architecture of the device the patched '
                                            'APK will run on. This can be determined with '
                                            '`adb shell getprop ro.product.cpu.abi`. If it '
                                            'is not specified, this command will try and '
                                            'determine it automatically.'), required=False)
@click.option('--gadget-version', '-V', help=('The gadget version to use. If not '
                                              'specified, the latest version will be used.'), default=None)
@click.option('--pause', '-p', is_flag=True, help='Pause the patcher before rebuilding the APK.',
              show_default=True)
@click.option('--skip-cleanup', '-k', is_flag=True,
              help='Do not clean temporary files once finished.', show_default=True)
@click.option('--enable-debug', '-d', is_flag=True,
              help='Set the android:debuggable flag to true in the application manifiest.', show_default=True)
@click.option('--decode-resources', '-D', is_flag=True, default=False,
              help='Also decode resources as part of the apktool processing.', show_default=True)
def patchapk(source: str, architecture: str, gadget_version: str, pause: bool, skip_cleanup: bool,
             enable_debug: bool, decode_resources: bool) -> None:
    """
        Patch an APK with the frida-gadget.so.
    """

    patch_android_apk(**locals())


if __name__ == '__main__':
    cli()
