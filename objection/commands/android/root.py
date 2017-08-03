from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def disable(args: list = None) -> None:
    """
        Performs a generic anti root detection.

        :param args:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('root/disable'))

    runner.run_as_job(name='root-disable')


def simulate(args: list = None) -> None:
    """
        Simulate a rooted environment.

        :param args:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('root/simulate'))

    runner.run_as_job(name='root-simulate')
