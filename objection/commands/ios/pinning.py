from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def _should_ignore_ios10_tls_helper_hook(args: list) -> bool:
    """
        Checks if --ignore-ios10-tls-helper is part
        of the commands arguments.

        :param args:
        :return:
    """

    return '--ignore-ios10-tls-helper' in args


def _should_be_quiet(args: list) -> bool:
    """
        Checks if --quiet is part of the
        commands arguments.

        :param args:
        :return:
    """

    return '--quiet' in args


def ios_disable(args: list = None) -> None:
    """
        Starts a new objection job that hooks common classes and functions,
        applying new logic in an attempt to bypass SSL pinning.

        :param args:
        :return:
    """

    hook = ios_hook('pinning/disable')

    runner = FridaRunner()
    runner.set_hook_with_data(hook=hook,
                              ignore_ios10_tls_helper=_should_ignore_ios10_tls_helper_hook(args),
                              quiet=_should_be_quiet(args))
    runner.run_as_job(name='pinning-disable')
