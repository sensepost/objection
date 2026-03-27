import unittest

from objection.state.jobs import job_manager_state, Job


class TestJobManager(unittest.TestCase):
    def tearDown(self):
        job_manager_state.jobs = {}

    def test_job_manager_starts_with_empty_jobs(self):
        self.assertEqual(len(job_manager_state.jobs), 0)

    def test_adds_jobs(self):
        job = Job('foo', 'test', None)
        job_manager_state.add_job(job)

        self.assertEqual(len(job_manager_state.jobs), 1)

    def test_removes_jobs(self):
        job1 = Job('foo', 'test', None)
        job2 = Job('bar', 'test', None)
        job_manager_state.add_job(job1)
        job_manager_state.add_job(job2)

        job_manager_state.remove_job(job1.uuid)
        job_manager_state.remove_job(job2.uuid)

        self.assertEqual(len(job_manager_state.jobs), 0)
