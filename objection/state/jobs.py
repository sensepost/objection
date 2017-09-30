import atexit

import click
import frida


class JobManagerState(object):
    """  A class representing the current Job manager. """

    def __init__(self) -> None:
        """
            Init a new job state manager. This method will also
            register an atexit(), ensuring that cleanup operations
            are performed on jobs when this class is GC'd.
        """

        self.jobs = []

        atexit.register(self.cleanup)

    def add_job(self, job) -> None:
        """
            Adds a job to the job state manager.

            :param job:
            :return:
        """

        self.jobs.append(job)

    def remove_job(self, job) -> None:
        """
            Removes a job from the job state manager.

            :param job:
            :return:
        """

        self.jobs.remove(job)

    def cleanup(self) -> None:
        """
            Clean up all of the job in the job manager.

            This method is typical called when at the end of an
            objection session.

            :return:
        """

        for job in self.jobs:

            try:

                click.secho('[job manager] Job: {0} - Stopping'.format(job.id), dim=True)
                job.end()

            except frida.InvalidOperationError:

                click.secho(('[job manager] Job: {0} - An error occured stopping job. Device may '
                             'no longer be available.'.format(job.id)), fg='red', dim=True)


job_manager_state = JobManagerState()
