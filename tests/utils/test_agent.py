import unittest

from objection.utils.agent import OutputHandlers


class FakeScript(object):
    def __init__(self):
        self.posted = []

    def post(self, message):
        self.posted.append(message)


class TestBridgeRequests(unittest.TestCase):
    def test_ignores_messages_without_a_script(self):
        message = {'type': 'send', 'payload': {'type': 'frida:load-bridge', 'name': 'java'}}

        self.assertFalse(OutputHandlers.try_handle_bridge_request(message, None))

    def test_ignores_messages_that_are_not_bridge_requests(self):
        script = FakeScript()

        self.assertFalse(OutputHandlers.try_handle_bridge_request(
            {'type': 'send', 'payload': {'type': 'something-else'}}, script))
        self.assertEqual(script.posted, [])

    def test_posts_bridge_source(self):
        script = FakeScript()
        message = {'type': 'send', 'payload': {'type': 'frida:load-bridge', 'name': 'Java'}}

        self.assertTrue(OutputHandlers.try_handle_bridge_request(message, script))
        self.assertEqual(script.posted[0]['type'], 'frida:bridge-loaded')
        self.assertEqual(script.posted[0]['filename'], 'java.js')
        self.assertTrue(script.posted[0]['source'])

    def test_ignores_unknown_bridges(self):
        script = FakeScript()
        message = {'type': 'send', 'payload': {'type': 'frida:load-bridge', 'name': 'nope'}}

        self.assertFalse(OutputHandlers.try_handle_bridge_request(message, script))
        self.assertEqual(script.posted, [])
