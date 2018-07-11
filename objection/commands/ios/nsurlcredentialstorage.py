import click
from tabulate import tabulate

from objection.utils.frida_transport import FridaRunner
from objection.utils.templates import ios_hook


def dump(args: list = None) -> None:
    """
        Dumps credentials stored in NSURLCredentialStorage

        :param args:
        :return:
    """

    hook = ios_hook('nsurlcredentialstorage/dump')

    runner = FridaRunner(hook=hook)
    api = runner.rpc_exports()

    data = api.dump()

    runner.unload_script()

    if not data:
        click.secho('No credentials found using NSURLCredentialStorage')

    click.secho('')
    click.secho(tabulate(data, headers="keys"))
    click.secho('')
    click.secho('Found {count} credentials'.format(count=len(data)), bold=True)
