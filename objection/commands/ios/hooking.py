import json
from typing import Optional

import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags

# a thumb sucked list of prefixes used in Objective-C runtime
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


def show_ios_classes(args: list = None) -> None:
    """
        Prints the classes available in the current Objective-C
        runtime to the screen.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    classes = api.ios_hooking_get_classes()

    # loop the class names and check if we should be ignoring it.
    for class_name in sorted(classes):
        if _should_ignore_native_classes(args):
            if not _class_is_prefixed_with_native(class_name):
                click.secho(class_name)
                continue

        else:
            click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(classes)), bold=True)


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

    api = state_connection.get_api()
    methods = api.ios_hooking_get_class_methods(classname, _should_include_parent_methods(args))

    if len(methods) > 0:

        # dump the methods to screen
        for method in methods:
            click.secho(method)

        click.secho('\nFound {0} methods'.format(len(methods)), bold=True)

    else:
        click.secho('No class / methods found')


def watch(args: list) -> None:
    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: ios hooking watch class <class_name> (--include-parents)', bold=True)
        return

    should_watch_args = _should_dump_args(args)
    should_watch_ret = _should_dump_return_value(args)
    should_backtrace = _should_dump_backtrace(args)
    should_watch_parents = _should_include_parent_methods(args)

    pattern = args[0]

    api = state_connection.get_api()
    api.ios_hooking_watch(pattern, should_watch_args, should_backtrace, should_watch_ret, should_watch_parents)


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

    api = state_connection.get_api()
    api.ios_hooking_set_return_value(selector, _string_is_true(retval))


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

    query = args[0]

    api = state_connection.get_api()
    classes = api.ios_hooking_get_classes(query)
    found_classes = 0

    if len(classes) > 0:

        # filter the classes for the search
        for classname in classes:

            if query.lower() in classname.lower():
                click.secho(classname)
                found_classes += 1

        click.secho('\nFound {0} classes'.format(found_classes), bold=True)

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

    query = args[0]

    api = state_connection.get_api()
    methods = api.ios_hooking_search_methods(query)

    if len(methods) > 0:

        # filter the methods for the search
        for method in methods:
            click.secho(method)

        click.secho('\nFound {0} methods'.format(len(methods)), bold=True)

    else:
        click.secho('No methods found')


def search(args: list) -> None:
    """
        Searches the current iOS application for classes and methods.

        :param args:
        :return:
    """
    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: ios hooking search \'*[CLASS METHOD]\'', bold=True)
        return

    should_print_only_classes = _should_print_only_classes(args)
    should_dump_json = _should_dump_json(args)

    api = state_connection.get_api()
    results = api.ios_hooking_search(args[0])

    data = {}
    for func in results:
        fullname = func['name']
        start_bracket = fullname.find('[') + 1
        class_name = fullname[start_bracket: fullname.find(' ')]
        if data.get(class_name) is not None:
            data[class_name].append(fullname)
        else:
            data[class_name] = []

    # Print the matching methods
    for klass in data.keys():
        methods = data[klass]
        print(klass)
        for method in methods:
            if not should_print_only_classes:
                print(f'\t{method}')

    if should_dump_json:
        target_file = _get_flag_value('--json', args)
        if target_file:
            with open(target_file, 'w') as fd:
                fd.write(json.dumps(data))
                click.secho(f'JSON dumped to {target_file}', bold=True)


def _should_print_only_classes(args: list) -> bool:
    return '--only-classes' in args


def _should_dump_json(args: list) -> bool:
    return '--json' in args


def _get_flag_value(flag:str, args: list) -> Optional[str]:
    target = None
    for i in range(len(args)):
        if args[i] == flag:
            target = i + 1

    if target is None:
        return None
    elif target < len(args):
        return args[target]
    else:
        click.secho(f'Could not find specified value for {flag}', bold=True)
        return None


def _should_be_quiet(args: list) -> bool:
    return '--quiet' in args
