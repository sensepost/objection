import shlex

from ..commands import filemanager
from ..state.jobs import job_manager_state
from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook

# variable used to cache entries from the ls-like
# commands used in the below helpers
_ls_cache = {}


def _get_device_file_listing() -> list:
    """
        Helper method used to get file listings in the current
        working directory.

        :return:
    """

    directory = filemanager.pwd()

    # check our cheap cache if we have a listing
    if directory in _ls_cache:
        return _ls_cache[directory]

    # fetch a fresh listing
    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('filesystem/ls'), path=directory)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        # cache an empty response as an error occured
        _ls_cache[directory] = None
        return

    # cache the response
    _ls_cache[directory] = response

    # grab the output lets seeeeee
    return runner.get_last_message()


def list_folders_in_current_fm_directory() -> dict:
    """
        Return folders in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # grab the output lets seeeeee
    response = _get_device_file_listing()

    # ensure the response was successful
    if not response.is_successful():
        return resp

    # loop the resultant files and extract directories
    for name, attribs in response.data['files'].items():
        attributes = attribs['attributes']
        if 'NSFileType' in attributes:
            if attributes['NSFileType'] == 'NSFileTypeDirectory':
                resp[name] = name

    return resp


def list_files_in_current_fm_directory() -> dict:
    """
        Return files in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # grab the output lets seeeeee
    response = _get_device_file_listing()

    # ensure the response was successful
    if not response.is_successful():
        return resp

    # loop the resultant files and extract directories
    for name, attribs in response.data['files'].items():
        attributes = attribs['attributes']
        if 'NSFileType' in attributes:
            if attributes['NSFileType'] == 'NSFileTypeRegular':
                resp[name] = name

    return resp


def list_files_in_current_host_directory() -> None:
    pass


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
