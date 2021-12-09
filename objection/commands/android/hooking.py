import json
from typing import Optional

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


def show_android_classes(args: list) -> None:
    """
        Show the currently loaded classes. 
        Note that Java classes are only loaded when they are used, 
        so not all classes may be present.

        :return:
    """

    api = state_connection.get_api()
    classes = api.android_hooking_get_classes()

    # print the enumerated classes
    for class_name in sorted(classes):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(classes)), bold=True)


def show_android_class_loaders(args: list) -> None:
    """
        Show the currently registered class loaders.

        :return:
    """

    api = state_connection.get_api()
    loaders = api.android_hooking_get_class_loaders()

    # print the enumerated classes
    for loader in sorted(loaders):
        click.secho('* {0}'.format(loader))

    click.secho('\nFound {0} class loaders'.format(len(loaders)), bold=True)


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


def notify(args: list) -> None:
    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking notify $PATTERN', bold=True)
        return

    pattern = args[0]

    api = state_connection.get_api()
    api.android_hooking_lazy_watch_for_pattern(pattern)


def watch(args: list) -> None:
    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking watch <pattern> '
                    '(eg: com.example.test, *com.example*!*, com.example.test!toString)'
                    '(optional: --dump-args) '
                    '(optional: --dump-backtrace) '
                    '(optional: --dump-return)',
                    bold=True)
    api = state_connection.get_api()
    api.android_hooking_watch(args[0],
                              _should_dump_args(args),
                              _should_dump_backtrace(args),
                              _should_dump_return_value(args)
                              )
    return


def show_registered_broadcast_receivers(args: list) -> None:
    """
        Enumerate all registered BroadcastReceivers

        :return:
    """

    api = state_connection.get_api()
    receivers = api.android_hooking_list_broadcast_receivers()

    for class_name in sorted(receivers):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(receivers)), bold=True)


def show_registered_services(args: list) -> None:
    """
        Enumerate all registered Services

        :return:
    """

    api = state_connection.get_api()
    services = api.android_hooking_list_services()

    for class_name in sorted(services):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(services)), bold=True)


def show_registered_activities(args: list) -> None:
    """
        Enumerate all registered Activities

        :return:
    """

    api = state_connection.get_api()
    activities = api.android_hooking_list_activities()

    for class_name in sorted(activities):
        click.secho(class_name)

    click.secho('\nFound {0} classes'.format(len(activities)), bold=True)


def get_current_activity(args: list) -> None:
    """
        Get the currently active activity

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


def _should_be_quiet(args: list) -> bool:
    return '--quiet' in args


def _should_dump_json(args: list) -> bool:
    return '--json' in args


def _get_flag_value(flag: str, args: list) -> Optional[str]:
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


def _should_print_only_classes(args: list) -> bool:
    return '--only-classes' in args


def search(args: list) -> None:
    """
        Enumerates the current Android application for classes and methods.

        :param args:
        :return:
    """
    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking search \'<class>!<method>\''
                    '(optional: --json <filename>)'
                    '(optional: --only-classes)'
                    '(optional: --quiet)', bold=True)
        return

    should_dump_json = _should_dump_json(args)
    should_print_only_classes = _should_print_only_classes(args)
    should_be_quiet = _should_be_quiet(args)

    api = state_connection.get_api()
    results_json = {
        'meta': {
            'runtime': 'java'
        }
    }
    results = api.android_hooking_enumerate(args[0])
    # Only get overloads if this flag is specified, otherwise just enumerating can be kind of slow
    if should_dump_json:
        for result in results:
            for _class in result['classes']:
                loader = result['loader']
                if loader is not None:
                    # <instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>
                    # but we only care about the className
                    # TODO(cduplooy): This can/has to be improved
                    startIndex = loader.find('$className: ') + 12
                    startPart = loader[startIndex:]
                    if startPart.find('>'):
                        endIndex = startPart.find('>')
                    else:
                        endIndex = startPart.find(' ')
                    loader = startPart[:endIndex]
                _class['overloads'] = api.android_hooking_get_class_methods_overloads(_class['name'], _class['methods'], loader)

    if not should_be_quiet:
        for result in results:
            for _class in result['classes']:
                print(_class['name'])
                if not should_print_only_classes:
                    for method in _class['methods']:
                        print(f'\t{method}')

    if should_dump_json:
        target_file = _get_flag_value('--json', args)
        if target_file:
            results_json['data'] = results
            with open(target_file, 'w') as fd:
                fd.write(json.dumps(results_json))
                click.secho(f'JSON dumped to {target_file}', bold=True)
