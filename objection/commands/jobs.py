import click
from tabulate import tabulate

from ..state.jobs import job_manager_state


def show(args=None):
    """
        Show all of the jobs that are currently running

        :return:
    """

    if len(job_manager_state.jobs) <= 0:
        click.secho('No running jobs', bold=True)
        return

    jobs = []
    for job in job_manager_state.jobs:
        jobs.append([
            job.id,
            job.name,
            job.started
        ])

    click.secho(tabulate(jobs, headers=['UUID', 'Name', 'Started']))


def kill(args):
    if len(args) <= 0:
        click.secho('Usage: jobs kill <uuid>', bold=True)
        return

    job_uuid = args[0]

    for job in job_manager_state.jobs:
        if str(job.id) == str(job_uuid):
            click.secho('Stopping job: {0}'.format(job.id))
            job.end()
            job_manager_state.remove_job(job)
            click.secho('Job {0} stopped'.format(job.id), fg='green')

            return

    click.secho('No job matched the UUID of: {0}'.format(job_uuid))
