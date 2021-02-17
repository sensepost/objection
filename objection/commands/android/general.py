from objection.state.connection import state_connection


def deoptimise(args: list) -> None:
    """
        Forces the VM to execute everything with its interpreter.
        Necessary to prevent optimizations from bypassing method hooks in some cases.

        Ref: https://frida.re/docs/javascript-api/

        :param args:
        :return:
    """

    api = state_connection.get_api()
    api.android_deoptimize()
