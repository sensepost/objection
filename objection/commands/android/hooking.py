import json
from typing import Optional

import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags


def _is_pattern_or_constant(s: str) -> bool:
    """
        Check if a provided pattern matches "CLASS!METHOD"

        :param s:
        :return:
    """

    # No pattern case
    if "!" not in s:
        return True

    # Check if CLASS and METHOD is defined at all
    parts = s.split('!')
    if len(parts) != 2:
        return False
    elif len(parts[0]) == 0 or len(parts[1]) == 0:
        return False

    return True


def _string_is_true(s: str) -> bool:
    """
        Check if a string should be considered as "True"

        :param s:
        :return:
    """

    return s.lower() in ('true', 'yes')


def _should_dump_backtrace(args: list = None) -> bool:
    """
        Check if --dump-backtrace is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-backtrace' in args


def _should_dump_args(args: list = None) -> bool:
    """
        Check if --dump-args is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-args' in args


def _should_dump_return_value(args: list = None) -> bool:
    """
        Check if --dump-return is part of the arguments.

        :param args:
        :return:
    """

    return '--dump-return' in args


def _should_dump_json(args: list) -> bool:
    """
        Check if --json is part of the arguments.

        :param args:
        :return:
    """

    return '--json' in args


def _should_be_quiet(args: list) -> bool:
    """
        Check if --quiet is part of the arguments.

        :param args:
        :return:
    """

    return '--quiet' in args


def _should_print_only_classes(args: list = None) -> bool:
    """
        Check if --only-classes is part of the arguments.

        :param args:
        :return:
    """

    return '--only-classes' in args


def _get_flag_value(flag: str, args: list) -> Optional[str]:
    """
        Gets the value for a flag

        :param flag:
        :param args:
        :return:
    """

    target = None

    for i in range(len(args)):
        if args[i] == flag:
            target = i + 1

    if target is None:
        return None
    elif target < len(args):
        return args[target]
    else:
        return None


def show_android_classes(args: list = None) -> None:
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


def show_android_class_loaders(args: list = None) -> None:
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


def notify(args: list = None) -> None:
    """
        Notify when a class becomes available.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking notify <pattern>', bold=True)
        return

    query = args[0]
    if not _is_pattern_or_constant(query):
        click.secho('Incorrect query syntax, please use <class>!<method> or just the class name', fg='red')
        return

    api = state_connection.get_api()
    api.android_hooking_lazy_watch_for_pattern(query)


def watch(args: list = None) -> None:
    """
        Hook functions and print useful information when they are called.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking watch <package pattern> '
                    '(eg: com.example.test, *com.example*!*, com.example.test!toString)'
                    '(optional: --dump-args) '
                    '(optional: --dump-backtrace) '
                    '(optional: --dump-return)',
                    bold=True)
        return

    query = args[0]
    if not _is_pattern_or_constant(query):
        click.secho('Incorrect query syntax, please use <CLASS>!<METHOD>', fg='red')
        return

    api = state_connection.get_api()
    api.android_hooking_watch(query,
                              _should_dump_args(args),
                              _should_dump_backtrace(args),
                              _should_dump_return_value(args))
    return


def search(args: list = None) -> None:
    """
        Enumerates the current Android application for classes and methods.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking search \'<class>!<method>\n\''
                    '(optional: --json <filename>)'
                    '(optional: --only-classes)', bold=True)
        return

    query = args[0]

    if not _is_pattern_or_constant(query):
        click.secho('Incorrect query syntax, please use <class>!<method>', fg='red')
        return

    api = state_connection.get_api()
    results = api.android_hooking_enumerate(query)

    # Only get overloads if this flag is specified, otherwise just enumerating can be kind of slow
    if _should_dump_json(args):
        results_json = {
            'meta': {
                'runtime': 'java'
            }
        }

        for result in results:
            for _class in result['classes']:
                loader = result['loader']
                if loader is not None:
                    # <instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>
                    # but we only care about the className
                    start_index = loader.find('$className: ') + 12
                    start_part = loader[start_index:]
                    if start_part.find('>'):
                        end_index = start_part.find('>')
                    else:
                        end_index = start_part.find(' ')
                    loader = start_part[:end_index]

                _class['overloads'] = api.android_hooking_get_class_methods_overloads(_class['name'], _class['methods'],
                                                                                      loader)

        target_file = _get_flag_value('--json', args)
        if target_file:
            results_json['data'] = results
            with open(target_file, 'w') as fd:
                fd.write(json.dumps(results_json))
                click.secho(f'JSON dumped to file {target_file}', bold=True)

        return

    # just print to the console
    for result in results:
        for _class in result['classes']:
            if _should_print_only_classes(args):
                print(_class['name'])
                continue

            for method in _class['methods']:
                print(f'{_class["name"]}.{method}')


def show_registered_broadcast_receivers(args: list = None) -> None:
    """
        Enumerate all registered BroadcastReceivers

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
