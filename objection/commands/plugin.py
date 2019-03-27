import os
import importlib.util
import click

import objection.console.commands


def load_plugin(args: list = None) -> None:
    """
        Documentation is a //TODO

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho(
            'Usage: plugin load <plugin path> [<plugin namespace>]', bold=True)
        return

    path = os.path.abspath(args[0])
    if os.path.isdir(path):
        path = os.path.join(path, '__init__.py')

    spec = importlib.util.spec_from_file_location('', path)
    plugin = spec.loader.load_module()
    spec.loader.exec_module(plugin)

    namespace = plugin.namespace
    if len(args) >= 2:
        namespace = args[1]

    plugin.__name__ = namespace
    instance = plugin.plugin(namespace)

    objection.console.commands.COMMANDS['plugin']['commands'][instance.namespace] = instance.implementation

    click.secho('Loaded plugin: ' + plugin.__name__)
