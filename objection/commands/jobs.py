import click
from tabulate import tabulate

from ..state.jobs import job_manager_state


def show(args: list = None) -> None:
    """
        Show all of the jobs that are currently running

        :return:
    """

    if len(job_manager_state.jobs) <= 0:
        click.secho('No jobs are currently running.', bold=True)
        return

    jobs = []
    for job in job_manager_state.jobs:
        jobs.append([
            job.id, job.name, job.started, ' '.join(job.args) if job.args else 'n/a'
        ])

    click.secho(tabulate(jobs, headers=['UUID', 'Name', 'Started', 'Arguments']))


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

    for job in job_manager_state.jobs:

        if str(job.id) == str(job_uuid):
            # run the end() method for the queued job so that any
            # cleanup operations that need to be run happen.
            click.secho('Job: {0} - Stopping'.format(job.id))
            job.end()

            # remove the job from the global job state manager
            job_manager_state.remove_job(job)
            click.secho('Job: {0} - Stopped'.format(job.id), fg='green')

            return

    click.secho('No job matched the UUID of: {0}'.format(job_uuid))
