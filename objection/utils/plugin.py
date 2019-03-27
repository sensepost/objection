import os
from objection.state.connection import state_connection


class Plugin(object):
    """ Plugin object to extend for development of custom functionality """

    def __init__(self, file, namespace: str, implementation: dict):
        self.namespace = namespace
        self.implementation = implementation
        self.script_path = os.path.abspath(
            os.path.join(os.path.abspath(os.path.dirname(file)), 'index.js'))
        self.script_src = "\n".join(open(self.script_path, 'r').readlines())
        self.agent = None
        self.session = None
        self.script = None
        self.api = None

    def _inject(self) -> None:
        if (not self.agent):
            self.agent = state_connection.get_agent()
        if (not self.session):
            self.session = self.agent._get_session()
        if (not self.script):
            self.script = self.session.create_script(source=self.script_src)

        self.script.on('message', self.agent._on_message)
        self.script.load()
        self.api = self.script.exports
