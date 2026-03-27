import unittest
from unittest import mock

from objection.commands.jobs import show, kill
from objection.state.jobs import job_manager_state, Job
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
        job_manager_state.jobs = {}

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_displays_empty_jobs_message(self, mock_api):
        mock_api.return_value.jobs_get.return_value = []
        with capture(show) as o:
            output = o

        expected_output = """Job ID  Type  Name
------  ----  ----
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_displays_list_of_jobs(self, mock_api):
        mock_api.return_value.jobs_get.return_value = [
            {'identifier': '123456', 'invocations': [{}], 'type': 'ios-jailbreak-disable'}]

        with capture(show, []) as o:
            output = o

        expected_outut = """Job ID  Type  Name
------  ----  ---------------------
123456  hook  ios-jailbreak-disable
"""

        self.assertEqual(output, expected_outut)

    def test_kill_validates_arguments(self):
        with capture(kill, []) as o:
            output = o

        self.assertEqual(output, 'Usage: jobs kill <uuid>\n')

    def test_cant_find_job_by_uuid(self):
        # Attempting to kill a job that doesn't exist just removes it from state
        # If it wasn't there, nothing happens
        kill(['123'])
        # Job was not in manager, so nothing happened
        self.assertEqual(len(job_manager_state.jobs), 0)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_kills_job_by_uuid(self, mock_api):
        # Add a job and then kill it
        mock_handle = mock.MagicMock()
        job = Job('test', 'hook', mock_handle, 123)
        job_manager_state.add_job(job)
        self.assertEqual(len(job_manager_state.jobs), 1)
        
        kill(['123'])
        
        self.assertEqual(len(job_manager_state.jobs), 0)

