class AppState(object):
    """ A class representing generic state variable for this app """

    def __init__(self):
        self.debug_hooks = False

    def should_debug_hooks(self) -> bool:
        """
            Returns if debugging of Frida hooks is needed.

            :return:
        """

        return self.debug_hooks


app_state = AppState()
