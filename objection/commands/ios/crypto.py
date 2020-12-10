from objection.state.connection import state_connection

def ios_disable(args: list = None) -> None:
    """
        Attempts to disable ios crypto monitoring.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.ios_crypto_disable()


def ios_monitor(args: list = None) -> None:
    """
        Attempts to enable ios crypto monitoring.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.ios_crypto_monitor()
