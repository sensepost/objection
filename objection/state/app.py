class AppState(object):
    """ A class representing generic state variable for this app """

    def __init__(self):
        self.debug_hooks = False
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


app_state = AppState()
