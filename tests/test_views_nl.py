import io
import json

import clamd
import pytest
from flask import jsonify, url_for


def test_status_when_clamd_is_running(mocker, client):
    mocker.patch("app.clamav_client.ClamavClient.ping", return_value="PONG")

    response = client.get(url_for("main.clamav_status"))
    assert response.status_code == 200
    assert response.get_data() == jsonify(message="Antivirus service is running.").get_data()


def test_status_when_clamd_returns_error(mocker, client):
    mocker.patch("app.clamav_client.ClamavClient.ping", return_value="")

    response = client.get(url_for("main.clamav_status"))
    assert response.status_code == 500
    assert response.get_data() == jsonify(error="Failed to connect to antivirus service.").get_data()


def test_scan_document_no_auth(client, mocker):
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)

    response = client.post(
        "/scan",
        content_type="multipart/form-data",
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 401


def test_scan_document_invalid_auth(client, mocker):
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)

    response = client.post(
        "/scan",
        content_type="multipart/form-data",
        headers={
            "Authorization": "Bearer invalid-key",
        },
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 401


def test_scan_document(client, mocker):
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)

    response = client.post(
        "/scan",
        content_type="multipart/form-data",
        headers={
            "Authorization": "Bearer test-key",
        },
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True)) == {"ok": True}


def test_scan_virus_document(client, mocker):
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=False)

    response = client.post(
        "/scan",
        content_type="multipart/form-data",
        headers={
            "Authorization": "Bearer test-key",
        },
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True)) == {"ok": False}


def test_status_does_not_depend_on_clamav(mocker, client):
    mock_ping = mocker.patch("app.clamav_client.ClamavClient.ping", return_value=False)

    response = client.get(url_for("main.status"))

    assert response.status_code == 200
    mock_ping.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [clamd.ConnectionError("Error connecting to clamav:3310"), clamd.ResponseError("ERROR")],
)
def test_scan_document_returns_503_when_clamav_fails(client, mocker, error):
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=error)

    response = client.post(
        "/scan",
        headers={"Authorization": "Bearer test-key"},
        content_type="multipart/form-data",
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 503
    assert response.get_json() == {"error": "Antivirus service unavailable."}


def test_scan_document_returns_503_when_clamav_unreachable(client, mocker):
    mocker.patch("socket.socket.connect", side_effect=ConnectionRefusedError(111, "Connection refused"))

    response = client.post(
        "/scan",
        headers={"Authorization": "Bearer test-key"},
        content_type="multipart/form-data",
        data={"document": (io.BytesIO(b"pdf file contents"), "file.pdf")},
    )

    assert response.status_code == 503
