import unittest

from objection.state.jobs import job_manager_state


class TestJobManager(unittest.TestCase):
    def tearDown(self):
        job_manager_state.jobs = []

    def test_job_manager_starts_with_empty_jobs(self):
        self.assertEqual(len(job_manager_state.jobs), 0)

    def test_adds_jobs(self):
        job_manager_state.add_job('foo')

        self.assertEqual(len(job_manager_state.jobs), 1)

    def test_removes_jobs(self):
        job_manager_state.add_job('foo')
        job_manager_state.add_job('bar')

        job_manager_state.remove_job('foo')
        job_manager_state.remove_job('bar')

        self.assertEqual(len(job_manager_state.jobs), 0)
