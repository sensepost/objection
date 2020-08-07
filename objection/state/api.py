from ..api.app import create_app


class ApiState(object):
    """ A class representing the state API for this app """

    def __init__(self):
        self.core_api = create_app()
        self.blueprints = []

    def append_api_blueprint(self, blueprint):
        """
            Add extra blueprints to the API.

            This method would typically be called by the
            plugin loader to slot in endpoints that plugins
            may expose.

            :param blueprint:
            :return:
        """

        self.blueprints.append(blueprint)

    def start(self, host: str, port: int, debug: bool = False):
        """
            Starts the Flask-based API server after
            registering any extra blueprints that would
            typically have been sources from plugins.

            :param host:
            :param port:
            :param debug:
            :return:
        """

        for bp in self.blueprints:
            self.core_api.register_blueprint(bp)

        self.core_api.run(host=host, port=port, debug=debug)


api_state = ApiState()
