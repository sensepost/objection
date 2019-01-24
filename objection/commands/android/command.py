import click

from objection.state.connection import state_connection


def execute(args: list) -> None:
    """
        Runs a shell command on an Android device.

        :param args:
        :return:
    """

    command = ' '.join(args)
    click.secho('Running shell command: {0}\n'.format(command), dim=True)

    api = state_connection.get_api()
    response = api.android_shell_exec(command)

    if 'stdOut' in response and len(response['stdOut']) > 0:
        click.secho(response['stdOut'], bold=True)

    if 'stdErr' in response and len(response['stdErr']) > 0:
        click.secho(response['stdErr'], bold=True, fg='red')
