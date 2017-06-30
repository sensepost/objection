from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def ios_disable(args: list = None) -> None:
    """
        Starts a new objection job that hooks common classes and functions,
        applying new logic in an attempt to bypass SSL pinning.

        :param args:
        :return:
    """

    hook = ios_hook('pinning/disable')

    runner = FridaRunner(hook=hook)
    runner.run_as_job(name='pinning-disable')
