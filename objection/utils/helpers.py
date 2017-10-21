import shlex

from ..state.jobs import job_manager_state


def list_current_jobs() -> dict:
    """
        Return a list of the currently listed objection jobs.
        Used for tab completion in the repl.
    """

    resp = {}

    for job in job_manager_state.jobs:
        resp[str(job.id)] = str(job.id)

    return resp


def pretty_concat(data: str, at_most: int = 75, left: bool = False) -> str:
    """
        Limits a string to the maximum value of 'at_most',
        ending it off with 3 '.'s. If true is specified for
        the left parameter, the end of the string will be
        used with 3 '.'s prefixed.

        :param data:
        :param at_most:
        :param left:
        :return:

    """

    # do nothing if we are below the max length
    if len(data) <= at_most:
        return data

    if left:
        return '...' + data[len(data) - at_most:]

    return data[:at_most] + '...'


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

        Sometimes we will have strings that don't have the last
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


def normalize_gadget_name(gadget_name: str):
    """
        Takes a string input and converts it into an integer
        if possible. This helps the attach() process in the Frida
        API determine if it should be attaching to a process name or a PID.

        :param gadget_name:
        :return:
    """

    try:

        gadget_name = int(gadget_name)

    except ValueError:
        pass

    return gadget_name


def clean_argument_flags(args: list) -> list:
    """
        Returns a list of arguments with flags removed.

        Items are considered flags when they are prefixed
        with two dashes.

        :param args:
        :return:
    """

    return [x for x in args if not x.startswith('--')]
