from objection.state.connection import state_connection


def disable(args: list = None) -> None:
    """
        Performs a generic anti root detection.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_root_detection_disable()


def simulate(args: list = None) -> None:
    """
        Simulate a rooted environment.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_root_detection_enable()
