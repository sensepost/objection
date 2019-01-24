from objection.state.connection import state_connection


def monitor(args: list = None) -> None:
    """
        Starts a new objection job that monitors the Android clipboard
        and reports on new strings found.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_monitor_clipboard()
