import click
from tabulate import tabulate

from objection.state.connection import state_connection
from ..state.jobs import job_manager_state, Job


def show(args: list = None) -> None:
    """
        Show all of the jobs that are currently running

        :return:
    """

    sync_job_manager()
    jobs = job_manager_state.jobs

    # click.secho(tabulate(
    #     [[
    #         entry['uuid'],
    #         sum([
    #             len(entry[x]) for x in [
    #                 'invocations', 'replacements', 'implementations'
    #             ] if x in entry
    #         ]),
    #         entry['type'],
    #     ] for entry in jobs], headers=['Job ID', 'Hooks', 'Name'],
    # ))
    click.secho(tabulate(
        [[
            uuid,
            job.job_type,
            job.name,
        ] for uuid, job in jobs.items()], headers=['Job ID', 'Type', 'Name'],
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

    job_uuid = int(args[0])

    job_manager_state.remove_job(job_uuid)


def list_current_jobs() -> dict:
    """
        Return a list of the currently listed objection jobs.
        Used for tab completion in the repl.
    """

    sync_job_manager()
    resp = {}

    for uuid, job in job_manager_state.jobs.items():
        resp[str(uuid)] = str(uuid)

    return resp


def sync_job_manager() -> dict[int, Job]:
    try:
        api = state_connection.get_api()
        jobs = api.jobs_get()

        for job in jobs:
            job_uuid = int(job['identifier'])
            job_name = job['type']
            if job_uuid not in job_manager_state.jobs:
                job_manager_state.jobs[job_uuid] = Job(job_name, 'hook', None, job_uuid)

        return job_manager_state.jobs
    except:
        print("REPL not ready")

