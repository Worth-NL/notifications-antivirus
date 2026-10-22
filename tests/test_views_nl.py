import io

import clamd
import pytest
from flask import url_for


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
