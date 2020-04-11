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
        '../../utils/assets', 'javahookmanager.js'
    )

    with open(js_path, 'r') as f:
        click.secho(f.read(), dim=True)


def simple(args: list) -> None:
    """
        Generate simple hooks for all methods in a Java class.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: android hooking generate simple <class name>', bold=True)
        return

    classname = args[0]

    api = state_connection.get_api()
    methods = api.android_hooking_get_class_methods(classname, False)

    if len(methods) <= 0:
        click.secho('No class / methods found')
        return

    # nasty! :D
    unique_methods = set([x.split('(')[0].split('.')[-1] for x in methods])

    for method in unique_methods:
        hook = """
Java.perform(function() {
    var clazz = Java.use('{clazz}');
    clazz.{method}.implementation = function() {

        //

        return clazz.{method}.apply(this, arguments);
    }
});
    """.replace('{clazz}', classname).replace('{method}', method)

        click.secho(hook, dim=True)
