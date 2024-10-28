from flask import Blueprint, current_app, jsonify, request
from flask_httpauth import HTTPTokenAuth

from app.clamav_client import ClamavClient

main_blueprint = Blueprint("main", __name__, url_prefix="")

auth = HTTPTokenAuth()

cli = ClamavClient()


@main_blueprint.route("/_status")
def status():
    current_app.logger.debug("/_status")
    if cli.ping():
        return "ok", 200
    else:
        return "", 500


@auth.verify_token
def verify_token(token):
    api_key = current_app.config["ANTIVIRUS_API_KEY"]
    is_valid = token == api_key
    current_app.logger.info("Token verification :: %s :: %s :: %s", token, api_key, is_valid)
    return is_valid


@main_blueprint.route("/scan", methods=["POST"])
@auth.login_required
def scan_document():
    current_app.logger.info("/scan")
    if "document" not in request.files:
        current_app.logger.error("No document uploaded.")
        return jsonify(error="No document upload"), 400

    result = cli.scan(request.files["document"])
    response = jsonify(ok=result)

    current_app.logger.info("Response :: %s", response)

    return response
