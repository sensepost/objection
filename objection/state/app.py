class AppState(object):
    """ A class representing generic state variable for this app """

    def __init__(self):
        self.debug_hooks = False
        self.debug = False
        self.api_host = '127.0.0.1'
        self.api_port = 8888
        self.successful_commands = []

    def add_command_to_history(self, command: str) -> None:
        """
            Adds a command to the list of successful commands.

            :param command:
            :return:
        """

        if command not in self.successful_commands:
            self.successful_commands.append(command)

    def clear_command_history(self) -> None:
        """
            Clears the list of successful commands recorded
            for this session.

            :return:
        """

        self.successful_commands = []

    def should_debug_hooks(self) -> bool:
        """
            Returns if debugging of Frida hooks is needed.

            :return:
        """

        return self.debug_hooks

    def should_debug(self) -> bool:
        """

            Checks if debugging is enabled

            :return:
        """

        return self.debug


app_state = AppState()
