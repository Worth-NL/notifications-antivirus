from clamd import ClamdError
from flask import Blueprint, current_app, jsonify, request
from flask_httpauth import HTTPTokenAuth

from app.clamav_client import ClamavClient

main_blueprint = Blueprint("main", __name__, url_prefix="")

auth = HTTPTokenAuth()


def get_clamav_client():
    return ClamavClient(
        current_app.config["ANTIVIRUS_MODE"],
        current_app.config["ANTIVIRUS_HOST"],
        current_app.config["ANTIVIRUS_PORT"],
        current_app.config["ANTIVIRUS_SOCKET_TIMEOUT"],
    )


@main_blueprint.route("/_status")
def status():
    # Liveness/readiness of this app only. It deliberately doesn't check ClamAV: every pod depends on the
    # same clamd, so restarting or unreadying them during a ClamAV outage fixes nothing. /scan answers
    # 503 then instead, and /_status/clamav reports ClamAV's own health.
    return jsonify(message="Antivirus API is running."), 200


@main_blueprint.route("/_status/clamav")
def clamav_status():
    if get_clamav_client().ping():
        return jsonify(message="Antivirus service is running."), 200
    else:
        return jsonify(error="Failed to connect to antivirus service."), 500


@auth.verify_token
def verify_token(token):
    return token == current_app.config["ANTIVIRUS_API_KEY"]


@main_blueprint.route("/scan", methods=["POST"])
@auth.login_required
def scan_document():
    if "document" not in request.files:
        current_app.logger.error("No document uploaded.")
        return jsonify(error="No document uploaded."), 400

    try:
        result = get_clamav_client().scan(request.files["document"])
    except ClamdError:
        # Not a verdict: tell the caller to try again later rather than that the file is infected.
        # Returned explicitly because the app-wide error handler answers 200.
        return jsonify(error="Antivirus service unavailable."), 503

    response = jsonify(ok=result)

    current_app.logger.info("Response :: %s", response)

    return response
