import fnmatch
import json

import click
import frida

from typing import Optional

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
        Note that Java classes are only loaded when they are used, 
        so not all classes may be present.

        :param args:
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

        :param args:
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

def watch(args: list) -> None:
    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking watch <pattern> '
                    '(eg: com.example.test, *com.example*!*, com.example.test!toString)'
                    '(optional: --dump-args) '
                    '(optional: --dump-backtrace) '
                    '(optional: --dump-return)'
                    ,bold=True)
    api = state_connection.get_api()
    api.android_hooking_watch(args[0],
                              _should_dump_args(args),
                              _should_dump_backtrace(args),
                              _should_dump_return_value(args)
                              )
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
        Searches the currently loaded classes for a class.
        Note that Java classes are only loaded when they are used, 
        so if you don't get results, the class might not have been used yet.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: android hooking search classes <name>', bold=True)
        return

    click.secho('Note that Java classes are only loaded when they are used,'
                ' so if the expected class has not been found, it might not have been loaded yet.', fg='yellow')

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

    click.secho('Note that Java classes are only loaded when they are used,'
                ' so if the expected class has not been found, it might not have been loaded yet.', fg='yellow')

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



def _should_be_quiet(args: list) -> bool:
    return '--quiet' in args



def _should_dump_json(args: list) -> Optional[str]:
    target = None
    for i in range(len(args)):
        if args[i] == '--json':
            target = i + 1
        i = i + 1

    if target is None:
        return None
    elif target < len(args):
        return args[target]
    else:
        click.secho('Please specify a target file', bold=True)

    return None



def _should_print_only_classes(args: list) -> bool:
   return '--only-classes' in args


def enumerate(args: list) -> None:
    """
        Enumerates the current Android application for classes and methods.

        :param query:
        :return:
    """
    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: android hooking enumerate \'<class>!<method>\''
                    '<optional overload> '
                    '(optional: --dump-args) '
                    '(optional: --dump-backtrace) '
                    '(optional: --dump-return)'
                    '(optional: --json <filename>)'
                    '(optional: --only-classes)'
                    '(optional: --quiet)', bold=True)
        return

    shouldDumpJSON = _should_dump_json(args)
    shouldPrintOnlyClasses = _should_print_only_classes(args)
    shouldWatchArgs = _should_dump_args(args)
    shouldWatchRet= _should_dump_return_value(args)
    shouldBeQuiet = _should_be_quiet(args)
    shouldBacktrace = _should_dump_backtrace(args)
    overload_filter = args[1].replace(' ', '') if (len(args) > 1 and '--' not in args[1]) else None

    api = state_connection.get_api()
    results = api.android_hooking_enumerate(args[0])
    # Only get overloads if this flag is specified, otherwise just enumerating can be kind of slow
    if shouldDumpJSON:
        for result in results:
            for _class in result['classes']:
                _class['overloads'] = api.android_hooking_get_class_methods_overloads(_class['name'], _class['methods'])

    if shouldWatchArgs or shouldWatchRet or shouldBacktrace:
        for result in results:
            for _class in result['classes']:
                classname = _class['name']
                methods = _class['methods']
                for method in methods:
                    fullyQualifiedMethod = f'{classname}.{method}'
                    api.android_hooking_watch_method(fullyQualifiedMethod,
                                                     overload_filter,
                                                     shouldWatchArgs,
                                                     shouldBacktrace,
                                                     shouldWatchRet)


    if not shouldBeQuiet:
        for result in results:
            for _class in result['classes']:
                print(_class['name'])
                if not shouldPrintOnlyClasses:
                    for method in _class['methods']:
                        print(f'\t{method}')


    targetFile = shouldDumpJSON
    if targetFile:
        with open(targetFile, 'w') as fd:
            fd.write(json.dumps(results))
            click.secho(f'JSON dumped to {shouldDumpJSON}', bold=True)
