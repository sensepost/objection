import click

from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook

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
        Check if a class name recieved is prefixed with one of the
        prefixes in the native_prefixes list.

        :param class_name:
        :return:
    """

    for prefix in native_prefixes:

        if class_name.startswith(prefix):
            return True

    return False


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
        return None

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

    if len(args) <= 0:
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


def dump_ios_method_args(args: list) -> None:
    """
        Starts an objection job that hooks into a class method and
        dumps the argument values as the method is invoked.

        :param args:
        :return:
    """

    # small helper method to reduce copy/paste code for the usage info
    def usage():
        click.secho('Usage: ios hooking dump method_args <+/-> <class_name> <method_name>', bold=True)

    if len(args) < 3:
        usage()
        return

    class_instance = args[0]
    class_name = args[1]
    method_name = args[2]

    if class_instance not in ['-', '+']:
        click.secho('Specify a class method (+) or instance method (-) with either a "+" or a "-"', fg='red')
        usage()
        return

    full_method = "{0}[{1} {2}]".format(class_instance, class_name, method_name)
    argument_count = full_method.count(':')
    click.secho('Full method: {0} ({1} arguments)'.format(full_method, argument_count))

    # prepare a runner for the arg dump hook
    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/dump-arguments'),
        method=full_method, argument_count=argument_count)

    runner.run_as_job(name='dump-arguments')


def watch_class(args: list) -> None:
    """
        Starts an objection job that hooks into all of the methods
        available in a class and reports on invocations.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios hooking watch class <class_name> (--include-parents)', bold=True)
        return

    class_name = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/watch-class-methods'),
        class_name=class_name, include_parents=_should_include_parent_methods(args))

    runner.run_as_job(name='watch-class-methods')


def watch_class_method(args):
    """
        Starts an objection jon that hooks into a specific class method
        and reports on invocations.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios hooking watch method <selector> (eg: -[ClassName methodName:])', bold=True)
        return

    selector = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/watch-method'), selector=selector)

    runner.run_as_job(name='watch-method')
