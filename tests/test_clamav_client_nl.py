from io import BytesIO

import clamd
import pytest

from app.clamav_client import AV_MODE_NETWORK, ClamavClient


@pytest.fixture
def network_client(notify_antivirus):
    return ClamavClient(AV_MODE_NETWORK, "clamav", 3310, timeout=5)


def test_timeout_is_passed_to_the_socket(network_client):
    assert network_client.cli.timeout == 5


def test_scan_raises_when_clamav_unreachable(network_client, mocker):
    mocker.patch("socket.socket.connect", side_effect=ConnectionRefusedError(111, "Connection refused"))

    with pytest.raises(clamd.ConnectionError):
        network_client.scan(BytesIO(b"pdf"))


def test_scan_raises_connection_error_when_stream_breaks(network_client, mocker):
    mocker.patch.object(network_client.cli, "instream", side_effect=BrokenPipeError(32, "Broken pipe"))

    with pytest.raises(clamd.ConnectionError):
        network_client.scan(BytesIO(b"pdf"))


def test_scan_raises_connection_error_on_timeout(network_client, mocker):
    mocker.patch.object(network_client.cli, "instream", side_effect=TimeoutError("timed out"))

    with pytest.raises(clamd.ConnectionError):
        network_client.scan(BytesIO(b"pdf"))


@pytest.mark.parametrize("response", [None, {}, {"stream": None}])
def test_scan_raises_on_empty_response(network_client, mocker, response):
    mocker.patch.object(network_client.cli, "instream", return_value=response)

    with pytest.raises(clamd.ResponseError):
        network_client.scan(BytesIO(b"pdf"))


def test_scan_raises_when_clamav_reports_an_error(network_client, mocker):
    mocker.patch.object(network_client.cli, "instream", return_value={"stream": ("ERROR", "Can't allocate memory")})

    with pytest.raises(clamd.ResponseError):
        network_client.scan(BytesIO(b"pdf"))


def test_scan_raises_when_file_too_large(network_client, mocker):
    error = clamd.BufferTooLongError("INSTREAM size limit exceeded. ERROR")
    mocker.patch.object(network_client.cli, "instream", side_effect=error)

    with pytest.raises(clamd.BufferTooLongError):
        network_client.scan(BytesIO(b"pdf"))


@pytest.mark.parametrize(("response", "expected"), [(("OK", None), True), (("FOUND", "Eicar-Test-Signature"), False)])
def test_scan_returns_verdict(network_client, mocker, response, expected):
    mocker.patch.object(network_client.cli, "instream", return_value={"stream": response})

    assert network_client.scan(BytesIO(b"pdf")) is expected
