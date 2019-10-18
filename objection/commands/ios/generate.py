import os

import click

from objection.state.connection import state_connection


def clazz(args: list) -> None:
    """
        Simply echoes the source for a generic Hook Manager
        sample for Objective-C hooks with Frida.

        :param args:
        :return:
    """

    js_path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        '../../utils/assets', 'objchookmanager.js'
    )

    with open(js_path, 'r') as f:
        click.secho(f.read(), dim=True)


def simple(args: list) -> None:
    """
        Generate simple hooks for all methods in a class.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: ios hooking generate simple <class name>', bold=True)
        return

    classname = args[0]

    api = state_connection.get_api()
    methods = api.ios_hooking_get_class_methods(classname, False)

    if len(methods) <= 0:
        click.secho('No class / methods found')
        return

    click.secho("var target = ObjC.classes.{};".format(classname), dim=True)

    for method in methods:
        hook = """
Interceptor.attach(target['{method}'].implementation, {
  onEnter: function (args) {
    console.log('Entering {method}!');
  },
  onLeave: function (retval) {
    console.log('Leaving {method}');
  },
});
    """.replace('{method}', method)

        click.secho(hook, dim=True)
