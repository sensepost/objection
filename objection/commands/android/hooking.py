import click
import frida

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
                     '<optional overload> '
                     '(optional: --dump-args) '
                     '(optional: --dump-backtrace) '
                     '(optional: --dump-return)'), bold=True)
        return

    fully_qualified_class = args[0]
    overload_filter = args[1].replace(' ', '') if (len(args) > 1 and '--' not in args[1]) else None

    api = state_connection.get_api()
    api.android_hooking_watch_method(fully_qualified_class,
                                     overload_filter,
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


def get_current_activity(args: list = None) -> None:
    """
        Get the currently active activity

        :param args:
        :return:
    """

    api = state_connection.get_api()
    activity = api.android_hooking_get_current_activity()

    click.secho('Activity: {0}'.format(activity['activity']), bold=True)
    click.secho('Fragment: {0}'.format(activity['fragment']))


def set_method_return_value(args: list = None) -> None:
    """
        Sets a Java methods return value to a specified boolean.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho(('Usage: android hooking set return_value '
                     '"<fully qualified class method>" "<optional overload>" (eg: "com.example.test.doLogin") '
                     '<true/false>'),
                    bold=True)
        return

    # make sure we got a true/false
    if args[-1].lower() not in ('true', 'false'):
        click.secho('Return value must be set to either true or false', bold=True)
        return

    class_name = args[0].replace('\'', '"')  # fun!

    # check if we got an overload
    overload_filter = args[1].replace(' ', '') if len(args) == 3 else None
    retval = True if _string_is_true(args[-1]) else False

    api = state_connection.get_api()
    api.android_hooking_set_method_return(class_name,
                                          overload_filter,
                                          retval)


def search_class(args: list) -> None:
    """
        Searches the current Android application for a class.

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


def search_methods(args: list) -> None:
    """
        Searches the current Android application for a class method.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking search methods <name> (optional: <package-filter>)', bold=True)
        return

    search = args[0]
    class_filter = args[1] if len(clean_argument_flags(args)) > 1 else None
    found = 0

    if not class_filter:
        click.secho('Warning, searching all classes may take some time and in some cases, '
                    'crash the target application.', fg='yellow')
        if not click.confirm('Continue?'):
            return

    api = state_connection.get_api()

    # get the classes we have
    classes = api.android_hooking_get_classes()
    click.secho('Found {0} classes, searching methods (this may take some time)...'.format(len(classes)), dim=True)
    if class_filter:
        click.secho('Filtering classes with {0}'.format(class_filter), dim=True)

    # loop the classes and check the methods
    for class_name in sorted(classes):
        if class_filter and class_filter.lower() not in class_name.lower():
            continue

        try:

            for method in api.android_hooking_get_class_methods(class_name):
                # get only the raw method, minus returns, throws and args
                method = method.split('(')[0].split(' ')[-1]
                if search.lower() in method.lower():
                    click.secho(method)
                    found += 1

        except frida.core.RPCException as e:
            click.secho('Enumerating methods for class \'{0}\' failed with: {1}'.format(class_name, e), fg='red',
                        dim=True)
            click.secho('Ignoring error and continuing search...', dim=True)

    click.secho('\nFound {0} methods'.format(found), bold=True)
