from flask import Flask
from . import frida


def create_app() -> Flask:
    """
        Creates a new Flask instance for the objection API

        :return:
    """

    app = Flask(__name__)
    app.register_blueprint(frida.bp)

    return app
