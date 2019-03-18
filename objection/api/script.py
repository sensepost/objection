from flask import Blueprint, jsonify, request, abort

from objection.state.connection import state_connection

bp = Blueprint('script', __name__, url_prefix='/script')


@bp.route('/runonce', methods=('POST',))
def runonce():
    """
        Run an arbitrary script in the connected frida
        enabled device.

        Responses are JSON encoded by default, but can be raw by adding
        ?json=false as a query string parameter.

        :return:
    """

    source = request.data.decode('utf-8')

    if len(source) <= 0:
        return abort(jsonify(message='Missing or empty script received'))

    try:

        # run the script
        response = state_connection.get_agent().single(source)

        if 'json' in request.args and request.args.get('json').lower() == 'false':
            return response

    except Exception as e:
        return abort(jsonify(message='Script failed to run: {e}'.format(e=str(e))))

    return jsonify(response)
