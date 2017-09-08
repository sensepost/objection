import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import android_hook


def _string_is_true(s: str) -> bool:
    """
        Check if a string should be considered as "True"

        :param s:
        :return:
    """

    return s.lower() in ('true', 'yes')


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

    if len(args) <= 0:
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


def watch_class_method(args: list) -> None:
    """
        Watches for invocations of an Android Java class method.
        All overloads are watched.

        :param args:
        :return:
    """

    if len(args) < 2:
        click.secho(('Usage: android hooking watch class_method <class> <method>'
                     ' (eg: com.example.test dologin)'), bold=True)
        return

    target_class = args[0]
    target_method = args[1]

    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('hooking/watch-method'),
                              target_class=target_class, target_method=target_method)

    runner.run_as_job(name='watch-java-method')


def dump_android_method_args(args: list) -> None:
    """
        Starts an objection job that hooks into a class method and
        dumps the argument values as the method is invoked.

        :param args:
        :return:
    """

    if len(args) < 2:
        click.secho('Usage: android hooking dump_args <class> <method>', bold=True)
        return

    target_class = args[0]
    target_method = args[1]

    # prepare a runner for the arg dump hook
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('hooking/dump-arguments'),
                              target_class=target_class, target_method=target_method)

    runner.run_as_job(name='dump-arguments')


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

    if len(args) < 2:
        click.secho(('Usage: android hooking set return_value '
                     '"<fully qualified class>" (eg: "com.example.test") '
                     '"<method (with overload if needed)>" (eg: see help for details) '
                     '<true/false>'),
                    bold=True)
        return

    class_name = args[0]
    method_name = args[1]
    retval = args[2]

    runner = FridaRunner()
    runner.set_hook_with_data(
        android_hook('hooking/set-return'), class_name=class_name, method_name=method_name, retval=retval)

    runner.run_as_job(name='set-return-value')


def search_class(args: list) -> None:
    """
        Searches the current Android application for instances
        of a class.

        :param args:
        :return:
    """

    if len(args) < 1:
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
