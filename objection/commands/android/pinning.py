from objection.state.connection import state_connection


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

    api = state_connection.get_api()
    api.android_ssl_pinning_disable(_should_be_quiet(args))
