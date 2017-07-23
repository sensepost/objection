import shlex

from ..commands import filemanager
from ..state.device import device_state
from ..state.jobs import job_manager_state
from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook, android_hook

# variable used to cache entries from the ls-like
# commands used in the below helpers. only used
# by the _get_short_*_listing methods.
_ls_cache = {}


def _get_short_ios_listing() -> list:
    """
        Get a shortened file and directory listing for
        iOS devices.

        :return:
    """

    # default to the pwd. this method is for tab
    # completions anyways.
    directory = filemanager.pwd()

    # the response for this directory
    resp = []

    # check our cheap cache if we have a listing
    if directory in _ls_cache:
        return _ls_cache[directory]

    # fetch a fresh listing
    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('filesystem/ls'), path=directory)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        # cache an empty response as an error occured
        _ls_cache[directory] = resp

        return resp

    # loop the response, marking entries as either being
    # a file or a directory. this response will be stored
    # in the _ls_cache too.
    for name, attribs in response.data['files'].items():

        # attributes key contains the type
        attributes = attribs['attributes']

        # if the attributes dict does not have the file type,
        # just continue as we cant be sure what it is.
        if 'NSFileType' not in attributes:
            continue

        # append a tuple with name, type
        resp.append((name, 'directory' if attributes['NSFileType'] == 'NSFileTypeDirectory' else 'file'))

    # cache the response so its faster next time!
    _ls_cache[directory] = resp

    # grab the output lets seeeeee
    return resp


def _get_short_android_listing() -> list:
    """
        Get a shortened file and directory listing for
        Android devices.

        :return:
    """

    # default to the pwd. this method is for tab
    # completions anyways.
    directory = filemanager.pwd()

    # the response for this directory
    resp = []

    # check our cheap cache if we have a listing
    if directory in _ls_cache:
        return _ls_cache[directory]

    # fetch a fresh listing
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('filesystem/ls'), path=directory)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        # cache an empty response as an error occured
        _ls_cache[directory] = resp

        return resp

    # loop the response, marking entries as either being
    # a file or a directory. this response will be stored
    # in the _ls_cache too.
    for name, attribs in response.data['files'].items():
        attributes = attribs['attributes']

        # append a tuple with name, type
        resp.append((name, 'directory' if attributes['isDirectory'] else 'file'))

    # cache the response so its faster next time!
    _ls_cache[directory] = resp

    # grab the output lets seeeeee
    return resp


def list_folders_in_current_fm_directory() -> dict:
    """
        Return folders in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # get the folders based on the runtime
    if device_state.device_type == 'ios':
        response = _get_short_ios_listing()

    elif device_state.device_type == 'android':
        response = _get_short_android_listing()

    # looks like we landed in an unknown runtime.
    # just return.
    else:
        return resp

    # loop the response to get entries for the 'directory'
    # type.
    for entry in response:
        file_name, file_type = entry

        if file_type == 'directory':
            resp[file_name] = file_name

    return resp


def list_files_in_current_fm_directory() -> dict:
    """
        Return files in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # check for existance based on the runtime
    if device_state.device_type == 'ios':
        response = _get_short_ios_listing()

    elif device_state.device_type == 'android':
        response = _get_short_android_listing()

    # looks like we landed in an unknown runtime.
    # just return.
    else:
        return resp

    # loop the response to get entries for the 'directory'
    # type.
    for entry in response:
        file_name, file_type = entry

        if file_type == 'file':
            resp[file_name] = file_name

    return resp


def list_current_jobs() -> dict:
    """
        Return a list of the currently listed objection jobs.
        Used for tab completion in the repl.
    """

    resp = {}

    for job in job_manager_state.jobs:
        resp[str(job.id)] = str(job.id)

    return resp


def pretty_concat(data: str, at_most: int = 75) -> str:
    """
        Limits a string to the maximum value of 'at_most',
        ending it off with 3 '.'s.

        :param data:
        :param at_most:
        :return:
    """

    return data[:at_most] + (data[at_most:] and '...')


def sizeof_fmt(num: float, suffix: str = 'B') -> str:
    """
        Pretty print bytes
    """

    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return '%3.1f %s%s' % (num, unit, suffix)
        num /= 1024.0
    return '%.1f %s%s' % (num, 'Yi', suffix)


def get_tokens(text: str) -> list:
    """
        Split the text line, shell-style.

        Sometimes we will have strings that dont have the last
        quotes added yet. In those cases, we can just ignore
        shlex errors. :)

        :param text:
        :return:
    """

    try:

        tokens = shlex.split(text)

    except ValueError:

        # return a response that wont match a next command
        tokens = ['lajfhlaksjdfhlaskjfhafsdlkjh']

    return tokens
