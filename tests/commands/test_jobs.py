import unittest
from unittest import mock

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

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_displays_empty_jobs_message(self, mock_api):
        mock_api.return_value.jobs_get.return_value = []
        with capture(show) as o:
            output = o

        expected_output = """Job ID    Hooks    Type
--------  -------  ------
"""

        self.assertEqual(output, expected_output)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_displays_list_of_jobs(self, mock_api):
        mock_api.return_value.jobs_get.return_value = [
            {'identifier': 'rdcjq16g8xi', 'invocations': [{}], 'type': 'ios-jailbreak-disable'}]

        with capture(show, []) as o:
            output = o

        expected_outut = """Job ID         Hooks  Type
-----------  -------  ---------------------
rdcjq16g8xi        1  ios-jailbreak-disable
"""

        self.assertEqual(output, expected_outut)

    def test_kill_validates_arguments(self):
        with capture(kill, []) as o:
            output = o

        self.assertEqual(output, 'Usage: jobs kill <uuid>\n')

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_cant_find_job_by_uuid(self, mock_api):
        kill('foo')

        self.assertTrue(mock_api.return_value.jobs_kill.called)

    @mock.patch('objection.state.connection.state_connection.get_api')
    def test_kills_job_by_uuid(self, mock_api):
        kill('foo')

        self.assertTrue(mock_api.return_value.jobs_kill.called)
