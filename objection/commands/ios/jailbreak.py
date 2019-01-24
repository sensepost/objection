from objection.state.connection import state_connection


def disable(args: list = None) -> None:
    """
        Attempts to disable jailbreak detection.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.ios_jailbreak_disable()


def simulate(args: list = None) -> None:
    """
        Attempts to simulate a Jailbroken environment

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.ios_jailbreak_enable()
