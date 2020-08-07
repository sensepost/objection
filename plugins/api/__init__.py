from flask import Blueprint

from objection.utils.plugin import Plugin


class ApiLoader(Plugin):
    """
        ApiLoader is a plugin that includes an API.

        This is just an example plugin to demonstrate how you
        could extend the objection API add your own endpoints.

        Since this plugins namespace is called api, the urls in
        our http_api method will therefore be:
            http://localhost/api/ping
            http://localhost/api/pong

        For more information on Flask blueprints, check out the
        documentation here:
            https://flask.palletsprojects.com/en/1.1.x/blueprints/
    """

    def __init__(self, ns):
        """
            Creates a new instance of the plugin

            :param ns:
        """

        implementation = {}

        super().__init__(__file__, ns, implementation)

        self.inject()

    def http_api(self) -> Blueprint:
        """
            The API endpoints for this plugin.

            :return:
        """

        # sets the uri path to /api in this case
        bp = Blueprint(self.namespace, __name__, url_prefix='/' + self.namespace)

        # the endpoint with this function as the logic will be
        # /api/ping.
        # that's because the url_prefix is the namespace name,
        # and the endpoint is /ping
        @bp.route('/ping', methods=('GET', 'POST'))
        def ping():
            return 'pong'

        @bp.route('/version', methods=('GET', 'POST'))
        def version():
            # call getVersion via the Frida RPC for this plugins
            # agent, defined in index.js
            return self.api.get_version()

        return bp


namespace = 'api'
plugin = ApiLoader
