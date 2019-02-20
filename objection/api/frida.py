from flask import Blueprint, jsonify, request, abort

from objection.state.connection import state_connection

bp = Blueprint('frida', __name__, url_prefix='/frida')

available_rpc_calls = {
    'ios_nsuser_defaults_get': {'arguments': []},
    'ios_cookies_get': {'arguments': []},
}


@bp.route('/endpoints', methods=('GET',))
def endpoints():
    """
        Return a list of available endpoints

        :return:
    """

    return jsonify(available_rpc_calls)


@bp.route('/invoke/<string:method>', methods=('GET', 'POST'))
def invoke(method):
    """
        Bridge a call to the Frida RPC

        :param method:
        :return:
    """

    if method not in available_rpc_calls:
        abort(jsonify(message='Method {m} is not a valid bridge endpoint.'.format(m=method)))

    if request.method == 'GET':
        rpc = state_connection.get_api()

        return jsonify(getattr(rpc, method)())
