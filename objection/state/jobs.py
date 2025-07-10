import atexit
from random import randint

import click
import frida

from objection.state.connection import state_connection


class Job(object):
    """  A class representing a REPL Job or agent Job with one or more hooks. """

    def __init__(self, name, job_type, handle, uuid: int = None) -> None:
        """
            Init a new job. This requires the job_type to know how to manage the job as well as a handle
            to manage and kill the job.

            :param name:
            :param job_type:
            :param handle:
            :return:
        """
        if uuid is not None:
            self.uuid = int(uuid)
        else:
            self.uuid = randint(100000, 999999)
        self.name = name
        self.job_type = job_type
        self.handle = handle

    def end(self):
        """
            Revert hooks that the job created.

            :return:
        """
        if self.job_type == "script":

            click.secho("[job manager] Killing job {0}. Name: {1}. Type: {2}"
                        .format(self.uuid, self.name, self.job_type), dim=True)
            self.handle.unload()
        elif self.job_type == "hook":
            api = state_connection.get_api()
            api.jobs_kill(self.uuid)
        else:
            click.secho(('[job {0}] - Unknown job type {1}'.format(self.uuid, self.job_type)), fg='red', dim=True)


class JobManagerState(object):
    """  A class representing the current Job manager. """

    def __init__(self) -> None:
        """
            Init a new job state manager. This method will also
            register an atexit(), ensuring that cleanup operations
            are performed on jobs when this class is GC'd.
        """

        self.jobs: dict[int, Job] = {}

        atexit.register(self.cleanup)

    def add_job(self, new_job: Job) -> None:
        """
            Adds a job to the job state manager.

            :param new_job:
            :return:
        """

        # avoid duplicate jobs.
        if new_job.uuid not in self.jobs:
            self.jobs[new_job.uuid] = new_job

    def remove_job(self, job_uuid: int):
        """
            Removes a job from the job state manager.

            :param job_uuid:
            :return Job:
        """
        if job_uuid not in self.jobs:
            click.secho(f"Error: Job with ID {job_uuid} does not exist.", fg='red')
            return

        job_to_remove = self.jobs.pop(job_uuid)
        job_to_remove.end()

    def cleanup(self) -> None:
        """
            Clean up all the jobs in the job manager.

            This method is typical called when at the end of an
            objection session.

            :return:
        """

        for uuid in list(self.jobs.keys()):
            try:
                job = self.jobs.pop(uuid)
                job.end()

            except frida.InvalidOperationError:
                click.secho(('[job manager] Job: {0} - An error occurred stopping job. Device may '
                             'no longer be available.'.format(uuid)), fg='red', dim=True)


job_manager_state = JobManagerState()
