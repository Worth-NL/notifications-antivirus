# NotifyNL: unlike the other upstream test files, this one is edited in place instead of being listed in
# superseded_tests_nl.toml. Upstream's version imports `clamav_scan`, which NotifyNL replaced with the ClamavClient
# class, so it fails at import and the superseded-tests plugin, which only sees collected tests, can't hide it. The
# edits are kept to the minimum (ClamavClient().scan instead of clamav_scan): re-apply them when an upstream sync
# changes this file.
from io import BytesIO

import clamd

from app.clamav_client import ClamavClient

clamav = ClamavClient()


def test_scan_virus_found(notify_antivirus, mocker):
    found = {"stream": ["FOUND", "Eicar-Test-Signature"]}

    mocker.patch("app.clamav_client.ClamdUnixSocket.instream", return_value=found)

    result = clamav.scan(BytesIO(clamd.EICAR))

    assert result is False


def test_scan_no_virus_found(notify_antivirus, mocker):
    found = {"stream": ["OK", None]}

    mocker.patch("app.clamav_client.ClamdUnixSocket.instream", return_value=found)

    result = clamav.scan(BytesIO(clamd.EICAR))

    assert result
