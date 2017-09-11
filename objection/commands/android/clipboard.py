from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def monitor(args: list = None) -> None:
    """
        Starts a new objection job that monitors the Android clipboard
        and reports on new strings found.

        :param args:
        :return:
    """

    hook = android_hook('clipboard/monitor')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='clipboard-monitor')
