import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.helpers import clean_argument_flags
from objection.utils.templates import android_hook


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

    hook = android_hook('hooking/list-classes')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list classes with error: {0}'.format(response.error_reason), fg='red')
        return None

    # print the enumerated classes
    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)


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

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('hooking/list-class-methods'), class_name=class_name)

    runner.run()
    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list class methods with error: {0}'.format(response.error_reason), fg='red')
        return None

    # print the enumerated classes
    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} method(s)'.format(len(response.data)), bold=True)


def watch_class(args: list) -> None:
    """
        Watches for invocations of all methods in an Android
        Java class. All overloads for methods found are also watched.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking watch class <class> '
                    '(eg: com.example.test) '
                    '(optional: --dump-args) '
                    '(optional: --dump-backtrace) '
                    '(optional: --dump-return)', bold=True)
        return

    target_class = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('hooking/watch-class-methods'),
                              target_class=target_class,
                              dump_args=_should_dump_args(args),
                              dump_return=_should_dump_return_value(args),
                              dump_backtrace=_should_dump_backtrace(args))

    runner.run_as_job(name='watch-java-class', args=args)


def watch_class_method(args: list) -> None:
    """
        Watches for invocations of an Android Java class method.
        All overloads for the same method are also watched.

        Optionally, this method will dump the watched methods arguments,
        backtrace as well as return value.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho(('Usage: android hooking watch class_method <class> <method> '
                     '(eg: com.example.test dologin) '
                     '(optional: --dump-args) '
                     '(optional: --dump-backtrace) '
                     '(optional: --dump-return)'), bold=True)
        return

    target_class = args[0]
    target_method = args[1]

    runner = FridaRunner()

    runner.set_hook_with_data(android_hook('hooking/watch-method'),
                              target_class=target_class,
                              target_method=target_method,
                              dump_args=_should_dump_args(args),
                              dump_return=_should_dump_return_value(args),
                              dump_backtrace=_should_dump_backtrace(args))

    runner.run_as_job(name='watch-java-method', args=args)


def show_registered_broadcast_receivers(args: list = None) -> None:
    """
        Enumerate all registered BroadcastReceivers

        :param args:
        :return:
    """

    hook = android_hook('hooking/list-broadcast-receivers')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list broadcast receivers with error: {0}'.format(response.error_reason), fg='red')
        return None

    if not response.data:
        click.secho('No broadcast receivers were found', fg='yellow')
        return None

    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)


def show_registered_services(args: list = None) -> None:
    """
        Enumerate all registered Services

        :param args:
        :return:
    """

    hook = android_hook('hooking/list-services')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list services with error: {0}'.format(response.error_reason), fg='red')
        return None

    if not response.data:
        click.secho('No services were found', fg='yellow')
        return None

    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)


def show_registered_activities(args: list = None) -> None:
    """
        Enumerate all registered Activities

        :param args:
        :return:
    """

    hook = android_hook('hooking/list-activities')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list activities with error: {0}'.format(response.error_reason), fg='red')
        return None

    if not response.data:
        click.secho('No activities were found', fg='yellow')
        return None

    for class_name in sorted(response.data):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)


def set_method_return_value(args: list = None) -> None:
    """
        Sets a Java methods return value to a specified boolean.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho(('Usage: android hooking set return_value '
                     '"<fully qualified class>" (eg: "com.example.test") '
                     '"<method (with overload if needed)>" (eg: see help for details) '
                     '<true/false>'),
                    bold=True)
        return

    class_name = args[0]
    method_name = args[1].replace('\'', '"')  # fun!
    retval = args[2]

    runner = FridaRunner()
    runner.set_hook_with_data(
        android_hook('hooking/set-return'), class_name=class_name, method_name=method_name, retval=retval)

    runner.run_as_job(name='set-return-value', args=args)


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

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('hooking/search-class'), search=search)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to search for classes with error: {0}'.format(response.error_reason), fg='red')
        return None

    if response.data:

        # dump the classes to screen
        for classname in response.data:
            click.secho(classname)

        click.secho('\nFound {0} classes'.format(len(response.data)), bold=True)

    else:
        click.secho('No classes found')
