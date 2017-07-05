from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def monitor(args: list = None) -> None:
    """
        Starts a new objection job that monitors the iOS pasteboard
        and reports on new strings found.

        :param args:
        :return:
    """

    hook = ios_hook('pasteboard/monitor')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='pasteboard-monitor')
