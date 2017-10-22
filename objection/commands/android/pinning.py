from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def _should_be_quiet(args: list) -> bool:
    """
        Checks if --quiet is part of the
        commands arguments.

        :param args:
        :return:
    """

    return '--quiet' in args


def android_disable(args: list = None) -> None:
    """
        Starts a new objection job that hooks common classes and functions,
        applying new logic in an attempt to bypass SSL pinning.

        :param args:
        :return:
    """

    hook = android_hook('pinning/disable')

    runner = FridaRunner()
    runner.set_hook_with_data(hook=hook, quiet=_should_be_quiet(args))
    runner.run_as_job(name='pinning-disable')
