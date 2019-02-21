from flask import Flask
from . import rpc


def create_app() -> Flask:
    """
        Creates a new Flask instance for the objection API

        :return:
    """

    app = Flask(__name__)
    app.register_blueprint(rpc.bp)

    return app
