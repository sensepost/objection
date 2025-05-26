from objection.state.connection import state_connection

def _should_watch_encrypted_only(args: list = None) -> bool:
    """
        Check if --encrypted_only is part of the arguments.

        :param args:
        :return:
    """

    return '--encrypted-only' in args

def monitor(args: list = None) -> None:
    """
        Monitors the use of Android shared preferences.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    should_watch_encrypted_only = _should_watch_encrypted_only(args)
    api.android_sharedprefs_monitor(should_watch_encrypted_only)