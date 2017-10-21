import click

from objection.utils.frida_transport import FridaRunner
from objection.utils.helpers import clean_argument_flags
from objection.utils.templates import ios_hook

# a thumbsucked list of prefixes used in Objective-C runtime
# for iOS applications. This is not a science, but a gut feeling.
native_prefixes = [
    '_',
    'NS',
    # '_NS',
    # '__NS',
    'CF',
    'OS_',
    'UI',
    # '_UI',

    'AWD',
    'GEO',

    'AC',
    'AF',
    'AU',
    'AV',
    'BK',
    'BS',
    'CA',
    'CB',
    'CI',
    'CL',
    'CT',
    'CUI',
    'DOM',
    'FBS',
    'LA',
    'LS',
    'MC',
    'MTL',
    'PFUbiquity',
    'PKPhysics',
    'SBS',
    'TI',
    'TXR',
    'UM',
    'Web',
]


def _should_ignore_native_classes(args: list) -> bool:
    """
        Checks if --ignore-native is in a list of tokens received
        from the commandline.

        :param args:
        :return:
    """

    if len(args) <= 0:
        return False

    return '--ignore-native' in args


def _should_include_parent_methods(args: list) -> bool:
    """
        Checks if --include-parents exists in a list of tokens received
        from the commandline.

        :param args:
        :return:
    """

    if len(args) <= 0:
        return False

    return '--include-parents' in args


def _class_is_prefixed_with_native(class_name: str) -> bool:
    """
        Check if a class name received is prefixed with one of the
        prefixes in the native_prefixes list.

        :param class_name:
        :return:
    """

    for prefix in native_prefixes:

        if class_name.startswith(prefix):
            return True

    return False


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


def _get_ios_classes() -> list:
    """
        Gets a list of all of the classes available in the current
        Objective-C runtime.

        :return:
    """

    hook = ios_hook('hooking/list-classes')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list classes with error: {0}'.format(response.error_reason), fg='red')
        return []

    return response.data


def show_ios_classes(args: list = None) -> None:
    """
        Prints the classes available in the current Objective-C
        runtime to the screen.

        :param args:
        :return:
    """

    classes = _get_ios_classes()
    if not classes:
        return

    # loop the class names and check if we should be ignoring it.
    for class_name in sorted(classes):

        if _should_ignore_native_classes(args):

            if not _class_is_prefixed_with_native(class_name):
                click.secho(class_name)
                continue

        else:
            click.secho(class_name)


def show_ios_class_methods(args: list) -> None:
    """
        Displays the methods available in a class.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: ios hooking list class_methods <class name> (--include-parents)', bold=True)
        return

    classname = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/list-class-methods'), classname=classname,
        include_parents=_should_include_parent_methods(args))

    runner.run()
    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list classes with error: {0}'.format(response.error_reason), fg='red')
        return None

    # dump the methods to screen
    for method in response.data:
        click.secho(method)


def watch_class(args: list) -> None:
    """
        Starts an objection job that hooks into all of the methods
        available in a class and reports on invocations.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: ios hooking watch class <class_name> (--include-parents)', bold=True)
        return

    class_name = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/watch-class-methods'),
        class_name=class_name, include_parents=_should_include_parent_methods(args))

    runner.run_as_job(name='watch-class-methods', args=args)


def watch_class_method(args: list) -> None:
    """
        Starts an objection jon that hooks into a specific class method
        and reports on invocations.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho(('Usage: ios hooking watch method <selector> (eg: -[ClassName methodName:]) '
                     '(optional: --dump-backtrace) '
                     '(optional: --dump-args) '
                     '(optional: --dump-return)'), bold=True)
        return

    selector = args[0]
    argument_count = selector.count(':')

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('hooking/watch-method'), selector=selector,
                              argument_count=argument_count,
                              dump_backtrace=_should_dump_backtrace(args),
                              dump_args=_should_dump_args(args),
                              dump_return=_should_dump_return_value(args))

    runner.run_as_job(name='watch-method', args=args)


def set_method_return_value(args: list) -> None:
    """
        Make an Objective-C method return a specific boolean
        value, always.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho('Usage: ios hooking set_method_return "<selector>" (eg: "-[ClassName methodName:]") <true/false>',
                    bold=True)
        return

    selector = args[0]
    retval = args[1]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/set-return'), selector=selector, retval=_string_is_true(retval))

    runner.run_as_job(name='set-return-value', args=args)


def search_class(args: list) -> None:
    """
        Searching for Objective-C classes in the current
        application by name.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: ios hooking search classes <name>', bold=True)
        return

    search = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('hooking/search-class'), search=search)
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


def search_method(args: list) -> None:
    """
        Search for Objective-C methods by name.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: ios hooking search methods <name>', bold=True)
        return

    search = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('hooking/search-method'), search=search)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to search for methods with error: {0}'.format(response.error_reason), fg='red')
        return None

    if response.data:

        # dump the methods to screen
        for method in response.data:
            click.secho(method)

        click.secho('\nFound {0} methods'.format(len(response.data)), bold=True)

    else:
        click.secho('No methods found')
