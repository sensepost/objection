import pprint

import click
from prompt_toolkit import prompt
from prompt_toolkit.lexers import PygmentsLexer
from pygments.lexers.javascript import JavascriptLexer
from tabulate import tabulate

from objection.state.connection import state_connection


def _should_ignore_methods_with_arguments(args) -> bool:
    """
        Check if the --without-arguments flag exists

        :param args:
        :return:
    """

    return len(args) > 0 and '--without-arguments' in args


def _should_return_as_string(args) -> bool:
    """
        Check if the --return-string flag exists

        :param args:
        :return:
    """

    return len(args) > 0 and '--return-string' in args


def instances(args: list) -> None:
    """
        Asks the agent to print the currently live instances of a particular class

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap search instances <class> (eg: com.example.test)', bold=True)
        return

    target_class = args[0]

    api = state_connection.get_api()
    instance_results = api.android_heap_get_live_class_instances(target_class)

    if len(instance_results) <= 0:
        return

    click.secho(tabulate(
        [[
            entry['hashcode'],
            entry['classname'],
            entry['tostring'],
        ] for entry in instance_results], headers=['Hashcode', 'Class', 'toString()'],
    ))


def methods(args: list) -> None:
    """
        Get the methods available on a handle

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap print methods <hashcode> (eg: 24688232)', bold=True)
        return

    target_handle = int(args[0])

    api = state_connection.get_api()
    method_results = api.android_heap_print_methods(target_handle)

    # apply argument filters
    # we assume methods that end with braces don't need arguments
    if _should_ignore_methods_with_arguments(args):
        method_results[1] = list(filter(lambda x: '()' in x, method_results[1]))

    click.secho(tabulate(
        [[
            entry,
        ] for entry in method_results], headers=['Method'],
    ))


def execute(args: list) -> None:
    """
        Executes a method on a handle which is assumed to be a Java
        class instance.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap execute method <hashcode> <method> (eg: 24688232)', bold=True)
        return

    target_handle = int(args[0])
    method = args[1]

    api = state_connection.get_api()
    exec_results = api.android_heap_execute_handle_method(target_handle, method,
                                                          _should_return_as_string(args))

    if exec_results:
        if isinstance(exec_results, dict):
            click.secho(pprint.pformat(exec_results))
        else:
            click.secho(str(exec_results))


def fields(args: list) -> None:
    """

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap print fields <hashcode> (eg: 24688232)', bold=True)
        return

    target_handle = int(args[0])

    api = state_connection.get_api()
    field_results = api.android_heap_print_fields(target_handle)

    click.secho(tabulate(
        [[
            value['name'],
            value['value']
        ] for value in field_results], headers=['Name', 'Value'],
    ))


def evaluate(args: list) -> None:
    """
        Evaluates JavaScript on a handle

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: android heap execute js <hashcode> (eg: 24688232)', bold=True)
        return

    target_handle = int(args[0])

    js = prompt(
        click.secho('(The hashcode at `{handle}` will be available as the `clazz` variable.)'.format(
            handle=target_handle
        ), dim=True),
        multiline=True, lexer=PygmentsLexer(JavascriptLexer),
        bottom_toolbar='JavaScript edit mode. [ESC] and then [ENTER] to accept. [CTRL] + C to cancel.').strip()

    click.secho('JavaScript capture complete. Evaluating...', dim=True)

    api = state_connection.get_api()
    api.android_heap_evaluate_handle_method(target_handle, js)
