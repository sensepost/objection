import atexit

import click


class JobManagerState(object):
    def __init__(self):
        self.jobs = []

        atexit.register(self.cleanup)

    def add_job(self, job):
        self.jobs.append(job)

    def remove_job(self, job):
        self.jobs.remove(job)

    def cleanup(self):
        for job in self.jobs:
            click.secho('[job manager] Ending job: {0}'.format(job.id), dim=True)
            job.end()


job_manager_state = JobManagerState()
