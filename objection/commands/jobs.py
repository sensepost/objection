import click
from tabulate import tabulate

from objection.state.connection import state_connection


def show(args: list = None) -> None:
    """
        Show all of the jobs that are currently running

        :return:
    """

    api = state_connection.get_api()
    jobs = api.jobs_get()

    click.secho(tabulate(
        [[
            entry['identifier'],
            sum([
                len(entry[x]) for x in [
                    'invocations', 'replacements', 'implementations'
                ] if x in entry
            ]),
            entry['type'],
        ] for entry in jobs], headers=['Job ID', 'Hooks', 'Type'],
    ))


def kill(args: list) -> None:
    """
        Kills a specific objection job.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: jobs kill <uuid>', bold=True)
        return

    job_uuid = args[0]

    api = state_connection.get_api()
    api.jobs_kill(job_uuid)
