import unittest

from objection.commands.jobs import show, kill
from objection.state.jobs import job_manager_state
from ..helpers import capture


class MockJob:
    """
        A mock job for testing purposes
    """

    def __init__(self):
        self.id = '3c3c65c7-67d2-4617-8fba-b96b6d2130d7'
        self.started = '2017-10-14 09:21:01'
        self.name = 'test'
        self.args = ['--foo', 'bar']

    def end(self):
        pass


class TestJobs(unittest.TestCase):
    def setUp(self):
        self.mock_job = MockJob()

    def tearDown(self):
        job_manager_state.jobs = []

    def test_displays_empty_jobs_message(self):
        with capture(show) as o:
            output = o

        self.assertEqual(output, 'No jobs are currently running.\n')

    def test_displays_list_of_jobs(self):
        job_manager_state.jobs = [self.mock_job]

        with capture(show, []) as o:
            output = o

        expected_outut = """UUID                                  Name    Started              Arguments
------------------------------------  ------  -------------------  -----------
3c3c65c7-67d2-4617-8fba-b96b6d2130d7  test    2017-10-14 09:21:01  --foo bar
"""

        self.assertEqual(output, expected_outut)

    def test_kill_validates_arguments(self):
        with capture(kill, []) as o:
            output = o

        self.assertEqual(output, 'Usage: jobs kill <uuid>\n')

    def test_cant_find_job_by_uuid(self):
        job_manager_state.jobs = [self.mock_job]

        with capture(kill, ['foo']) as o:
            output = o

        self.assertEqual(output, 'No job matched the UUID of: foo\n')

    def test_kills_job_by_uuid(self):
        job_manager_state.jobs = [self.mock_job]

        with capture(kill, ['3c3c65c7-67d2-4617-8fba-b96b6d2130d7']) as o:
            output = o

        expected_output = """Job: 3c3c65c7-67d2-4617-8fba-b96b6d2130d7 - Stopping
Job: 3c3c65c7-67d2-4617-8fba-b96b6d2130d7 - Stopped
"""

        self.assertEqual(output, expected_output)
