import importlib.util
import os
import traceback
import uuid

import click

from ..utils.plugin import Plugin as PluginType


def load_plugin(args: list = None) -> None:
    """
        Loads an objection plugin.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: plugin load <plugin path> (<plugin namespace>)', bold=True)
        return

    path = os.path.abspath(args[0])
    if os.path.isdir(path):
        path = os.path.join(path, '__init__.py')

    if not os.path.exists(path):
        click.secho('[plugin] {0} does not appear to be a valid plugin. Missing __init__.py'.format(
            os.path.dirname(path)), fg='red', dim=True)
        return

    spec = importlib.util.spec_from_file_location(str(uuid.uuid4())[:8], path)
    plugin = spec.loader.load_module()
    spec.loader.exec_module(plugin)

    namespace = plugin.namespace
    if len(args) >= 2:
        namespace = args[1]

    plugin.__name__ = namespace

    # try and load the plugin (aka: run its __init__)
    try:

        instance = plugin.plugin(namespace)
        assert isinstance(instance, PluginType)

    except AssertionError:
        click.secho('Failed to load plugin \'{0}\'. Invalid plugin type.'.format(namespace), fg='red', bold=True)
        return

    except Exception as e:
        click.secho('Failed to load plugin \'{0}\' with error: {1}'.format(namespace, str(e)), fg='red', bold=True)
        click.secho('{0}'.format(traceback.format_exc()), dim=True)
        return

    from ..console import commands
    commands.COMMANDS['plugin']['commands'][instance.namespace] = instance.implementation
    click.secho('Loaded plugin: {0}'.format(plugin.__name__), bold=True)
