from flask import Blueprint, current_app, jsonify, request
from flask_httpauth import HTTPTokenAuth

from app.clamav_client import ClamavClient

main_blueprint = Blueprint("main", __name__, url_prefix="")

auth = HTTPTokenAuth()

cli = ClamavClient()


@main_blueprint.route("/_status")
def status():
    current_app.logger.info("/_status")
    if cli.ping():
        return "ok", 200
    else:
        return "", 500


@auth.verify_token
def verify_token(token):
    current_app.logger.info("Token verification")
    return token == current_app.config["ANTIVIRUS_API_KEY"]


@main_blueprint.route("/scan", methods=["POST"])
@auth.login_required
def scan_document():
    current_app.logger.info("/scan")
    if "document" not in request.files:
        return jsonify(error="No document upload"), 400

    result = cli.scan(request.files["document"])
    response = jsonify(ok=result)

    current_app.logger.info(response)

    return response
