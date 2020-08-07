import os
from abc import ABC

from objection.state.connection import state_connection
from objection.utils.helpers import debug_print
from ..state.api import api_state


class Plugin(ABC):
    """ Plugin object to extend for development of custom functionality """

    def __init__(self, plugin_file: str, namespace: str, implementation: dict):
        """
            Start a new plugin instance.

            :param plugin_file:
            :param namespace:
            :param implementation:
        """

        self.namespace = namespace
        self.implementation = implementation
        self.plugin_file = plugin_file

        # plugin properties
        if not hasattr(self, 'script_src'):
            self.script_src = None
        if not hasattr(self, 'script_path'):
            self.script_path = None
        if not hasattr(self, 'on_message_handler'):
            self.on_message_handler = None

        self.agent = None
        self.session = None
        self.script = None
        self.api = None

        self._prepare_source()
        self._append_to_api()

    def _prepare_source(self):
        """
            Prepares the self.script_src attribute based on a few rules.

            If the script source is already set, simply return as there is
                nothing for us to do.
            If the script path is set, read that and populate the script_src
                attribute.
            If neither script_src not script_path is set, attempt to read the
                index.js that lives next to the plugin file.

            If all of the above fail, simply return, writing a debug warning
                no script source could be found.

            :return:
        """

        if self.script_src:
            return

        if self.script_path:
            self.script_path = os.path.abspath(self.script_path)
            with open(self.script_path, 'r', encoding='utf-8') as f:
                self.script_src = '\n'.join(f.readlines())
            return

        possible_src = os.path.abspath(os.path.join(
            os.path.abspath(os.path.dirname(self.plugin_file)), 'index.js'))
        if os.path.exists(possible_src):
            self.script_path = possible_src
            with open(self.script_path, 'r', encoding='utf-8') as f:
                self.script_src = '\n'.join(f.readlines())
            return

        debug_print('[warning] No Fridascript could be found for plugin {0}'.format(self.namespace))

    def inject(self) -> None:
        """
            Injects the script sources in a new Frida session.

            :return:
        """

        if not self.script_src:
            raise Exception('Unable to discover Frida script source to inject')

        if not self.agent:
            self.agent = state_connection.get_agent()

        if not self.session:
            self.session = self.agent.get_session()

        if not self.script:
            self.script = self.session.create_script(source=self.script_src)

        # check for a custom message handler, otherwise fallback
        # to the default objection handler
        self.script.on('message', self.on_message_handler if self.on_message_handler else self.agent.on_message)

        self.script.load()
        self.api = self.script.exports

    def _append_to_api(self):
        """
            If the http_api() function is defined in the child class, take
            it's return (it should always return a flask.Blueprint) and append
            it to the existing blueprints in objections core API.

            The ApiState class will handle the loading and starting of the API
            with them included.

            :return:
        """

        if not hasattr(self, 'http_api'):
            return

        if not callable(getattr(self, 'http_api')):
            raise Exception('The http_api property must be a function returning a Flask Blueprint')

        api_state.append_api_blueprint(getattr(self, 'http_api')())
