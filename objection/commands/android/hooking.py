import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags


def _string_is_true(s: str) -> bool:
    """
        Check if a string should be considered as "True"

        :param s:
        :return:
    """

    return s.lower() in ('true', 'yes')


def _should_dump_backtrace(args: list) -> bool:
    """
        Check if --dump-backtrace is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-backtrace' in args


def _should_dump_args(args: list) -> bool:
    """
        Check if --dump-args is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-args' in args


def _should_dump_return_value(args: list) -> bool:
    """
        Check if --dump-return is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-return' in args


def show_android_classes(args: list = None) -> None:
    """
        Show the currently loaded classes.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    classes = api.android_hooking_get_classes()

    # print the enumerated classes
    for class_name in sorted(classes):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(classes)), bold=True)


def show_android_class_methods(args: list = None) -> None:
    """
        Shows the methods available on an Android class.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking list class_methods <class name>', bold=True)
        return

    class_name = args[0]

    api = state_connection.get_api()
    methods = api.android_hooking_get_class_methods(class_name)

    # print the enumerated classes
    for class_name in sorted(methods):
        click.secho(class_name)

    click.secho('\nFound {0} method(s)'.format(len(methods)), bold=True)


def watch_class(args: list) -> None:
    """
        Watches for invocations of all methods in an Android
        Java class. All overloads for methods found are also watched.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking watch class <class> '
                    '(eg: com.example.test)', bold=True)
        return

    target_class = args[0]

    api = state_connection.get_api()
    api.android_hooking_watch_class(target_class)


def watch_class_method(args: list) -> None:
    """
        Watches for invocations of an Android Java class method.
        All overloads for the same method are also watched.

        Optionally, this method will dump the watched methods arguments,
        backtrace as well as return value.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho(('Usage: android hooking watch class_method <fully qualified class method> '
                     '(eg: com.example.test.dologin) '
                     '(optional: --dump-args) '
                     '(optional: --dump-backtrace) '
                     '(optional: --dump-return)'), bold=True)
        return

    fully_qualified_class = args[0]

    api = state_connection.get_api()
    api.android_hooking_watch_method(fully_qualified_class,
                                     _should_dump_args(args),
                                     _should_dump_backtrace(args),
                                     _should_dump_return_value(args))

    return


def show_registered_broadcast_receivers(args: list = None) -> None:
    """
        Enumerate all registered BroadcastReceivers

        :param args:
        :return:
    """

    api = state_connection.get_api()
    receivers = api.android_hooking_list_broadcast_receivers()

    for class_name in sorted(receivers):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(receivers)), bold=True)


def show_registered_services(args: list = None) -> None:
    """
        Enumerate all registered Services

        :param args:
        :return:
    """

    api = state_connection.get_api()
    services = api.android_hooking_list_services()

    for class_name in sorted(services):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(services)), bold=True)


def show_registered_activities(args: list = None) -> None:
    """
        Enumerate all registered Activities

        :param args:
        :return:
    """

    api = state_connection.get_api()
    activities = api.android_hooking_list_activities()

    for class_name in sorted(activities):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(activities)), bold=True)


def set_method_return_value(args: list = None) -> None:
    """
        Sets a Java methods return value to a specified boolean.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho(('Usage: android hooking set return_value '
                     '"<fully qualified class method (with overload if needed)>" (eg: "com.example.test.doLogin") '
                     '<true/false>'),
                    bold=True)
        return

    class_name = args[0].replace('\'', '"')  # fun!
    retval = True if _string_is_true(args[1]) else False

    api = state_connection.get_api()
    api.android_hooking_set_method_return(class_name, retval)


def search_class(args: list) -> None:
    """
        Searches the current Android application for instances
        of a class.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking search classes <name>', bold=True)
        return

    search = args[0]
    found = 0

    api = state_connection.get_api()
    classes = api.android_hooking_get_classes()

    # print the enumerated classes
    for class_name in sorted(classes):

        if search.lower() in class_name.lower():
            click.secho(class_name)
            found += 1

    click.secho('\nFound {0} classes'.format(found), bold=True)
