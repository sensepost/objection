import os
import sys

import click
import frida
from tabulate import tabulate

from ..state.connection import state_connection
from ..state.device import device_state, Android, Ios, Darwin


def _darwin_executable_path(pid):
    """Return executable path for pid on macOS, or None."""
    if sys.platform != 'darwin' or pid is None:
        return None
    try:
        from ctypes import CDLL, create_string_buffer, c_uint32
        libproc = CDLL('libproc.dylib')
        buf = create_string_buffer(4096)
        n = libproc.proc_pidpath(pid, buf, c_uint32(4096))
        if n and n > 0:
            return buf.value.decode('utf-8', errors='replace').strip('\x00') or None
    except Exception:
        pass
    return None


def get_environment(args: list = None) -> None:
    """
        Get information about the current environment.

        This method will call the correct runtime specific
        method to get the information that it can.

        :param args:
        :return:
    """

    platform = getattr(device_state, 'platform', None)
    if platform is None:
        # Fallback: detect platform from device (e.g. remote device may not set it at attach)
        try:
            dev = state_connection.get_agent().device
            params = dev.query_system_parameters()
            os_id = (params.get('os') or {}).get('id', '')
            os_name = ((params.get('os') or {}).get('name') or '').lower()
            if os_id in ('darwin', 'macos') or os_name in ('macos', 'mac os x', 'darwin'):
                device_state.set_platform(Darwin)
                platform = Darwin
            elif os_id == 'ios':
                device_state.set_platform(Ios)
                platform = Ios
            elif os_id == 'android':
                device_state.set_platform(Android)
                platform = Android
        except Exception:
            pass
    if platform is None:
        click.secho('Environment info is only available for iOS, Android and macOS targets.', fg='yellow')
        return

    if platform == Ios:
        _get_ios_environment()
    elif platform == Android:
        _get_android_environment()
    elif platform == Darwin:
        _get_macos_environment()


def _get_ios_environment() -> None:
    """
        Prints information about the iOS environment.

        This includes the current OS version as well as directories
        of interest for the current applications Documents, Library and
        main application bundle.

        :return:
    """

    paths = state_connection.get_api().env_ios_paths()

    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))


def _get_android_environment() -> None:
    """
        Prints information about the Android environment.

        :return:
    """

    paths = state_connection.get_api().env_android_paths()

    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))


def _get_macos_environment() -> None:
    """
        Prints information about the macOS environment.

        Includes home directory, temp directory, current working directory
        and main executable path. Uses env_darwin_paths() when available,
        otherwise falls back to evaluate() for bundled/legacy agents.
    """
    api = state_connection.get_api()
    paths = None
    try:
        paths = api.env_darwin_paths()
    except frida.core.RPCException as e:
        if 'envDarwinPaths' in str(e):
            # Agent may be bundled without envDarwinPaths; try evaluate()
            try:
                js = (
                    '(function(){ var m = Process.mainModule; return { '
                    'HomeDirectory: Process.getHomeDir(), '
                    'TempDirectory: Process.getTmpDir(), '
                    'CurrentDirectory: Process.getCurrentDir(), '
                    'ExecutablePath: m ? m.path : "n/a" }; })()'
                )
                paths = api.evaluate(js)
            except Exception:
                # No RPC: use local env (same machine for 127.0.0.1) + PID executable
                paths = _macos_env_fallback()
        else:
            raise
    if not paths:
        click.secho('Could not get environment.', fg='yellow')
        return
    click.secho('')
    click.secho(tabulate(paths.items(), headers=['Name', 'Path']))


def _macos_env_fallback():
    """
    Fallback when agent has no env/evaluate RPC (e.g. minimal Gadget).
    Uses local env (same machine for 127.0.0.1) and PID executable path.
    """
    home = os.environ.get('HOME') or os.path.expanduser('~')
    tmp = os.environ.get('TMPDIR', '/tmp')
    pid = None
    try:
        pid = state_connection.get_agent().pid
    except Exception:
        pass
    exe = _darwin_executable_path(pid) if pid else None
    return {
        'HomeDirectory': home,
        'TempDirectory': tmp.rstrip('/'),
        'CurrentDirectory': 'n/a (agent RPC not available)',
        'ExecutablePath': exe or 'n/a (agent RPC not available)',
    }
