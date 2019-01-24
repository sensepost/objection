import json

import click
from tabulate import tabulate

from objection.state.connection import state_connection


def _should_dump_json(args: list) -> bool:
    """
        Check if --json is part of the arguments.

        :param args:
        :return:
    """

    return '--json' in args


def get(args: list) -> None:
    """
        Gets cookies using the iOS NSHTTPCookieStorage sharedHTTPCookieStorage
        and prints them to the screen.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    cookies = api.ios_cookies_get()

    if _should_dump_json(args):
        print(json.dumps(cookies, indent=4))
        return

    if len(cookies) <= 0:
        click.secho('No cookies found')
        return

    click.secho(tabulate(
        [[
            cookie['name'],
            cookie['value'],
            cookie['expiresDate'],
            cookie['domain'],
            cookie['path'],
            cookie['isSecure'],
            cookie['isHTTPOnly']
        ] for cookie in cookies], headers=['Name', 'Value', 'Expires', 'Domain', 'Path', 'Secure', 'HTTPOnly'],
    ))
