import click

from ..utils.frida_transport import FridaRunner
from ..utils.templates import ios_hook

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


def _should_ignore_native_classes(args):
    if len(args) <= 0:
        return False

    return '--ignore-native' in args


def _should_include_parent_methods(args):
    if len(args) <= 0:
        return False

    return '--include-parents' in args


def _class_is_prefixed_with_native(class_name):
    for prefix in native_prefixes:
        if class_name.startswith(prefix):
            return True

    return False


def _get_ios_classes():
    hook = ios_hook('hooking/list-classes')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list classes with error: {0}'.format(response.error_reason), fg='red')
        return None

    return response.data


def show_ios_classes(args=None):
    classes = _get_ios_classes()
    if not classes:
        return

    for class_name in sorted(classes):
        if _should_ignore_native_classes(args):
            if not _class_is_prefixed_with_native(class_name):
                click.secho(class_name)
                continue
        else:
            click.secho(class_name)


def show_ios_class_methods(args):
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

    for method in response.data:
        click.secho(method)


def dump_ios_method_args(args):
    def usage():
        click.secho('Usage: ios hooking dump method_args <+/-> <class_name> <method_name>', bold=True)

    if len(args) < 3:
        usage()
        return

    class_instance = args[0]
    class_name = args[1]
    method_name = args[2]

    if class_instance not in ['-', '+']:
        click.secho('Specify a class (+) or instance (-) method with a "+" or a "-"', fg='red')
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


def watch_class(args):
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
    if len(args) <= 0:
        click.secho('Usage: ios hooking watch method <selector> (eg: -[ClassName methodName:])', bold=True)
        return

    selector = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('hooking/watch-method'), selector=selector)
    runner.run_as_job(name='watch-method')
