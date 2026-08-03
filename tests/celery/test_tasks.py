from contextlib import contextmanager
from unittest.mock import patch

from botocore.exceptions import ClientError as BotoClientError
from celery.exceptions import MaxRetriesExceededError
from clamd import ClamdError

from app.celery.tasks import scan_file, scan_letter_parts
from app.config import QueueNames, TaskNames

TEST_FILENAME = "EXAMPLE-SCAN-LETTER.pdf"
TEST_MESSAGE_GROUP_ID = "test-message-group-id"
TEST_FILENAMES = [
    "EXAMPLE-SCAN-LETTER.pdf",
    "EXAMPLE-SCAN-LETTER.PART2.pdf",
    "EXAMPLE-SCAN-LETTER.PART3.pdf",
]


@contextmanager
def _with_message_group_id(value: str):
    with patch("notifications_utils.celery.NotifyTask.message_group_id", new=value, create=True):
        yield


def test_scan_no_virus(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_file(TEST_FILENAME)

    mock_send_task.assert_called_once_with(
        name=TaskNames.SANITISE_LETTER,
        kwargs={"filename": TEST_FILENAME},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )


def test_scan_virus_detected(notify_antivirus, mocker, caplog):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=False)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_file(TEST_FILENAME)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED,
        kwargs={"filename": TEST_FILENAME},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )

    assert "VIRUS FOUND for file: EXAMPLE-SCAN-LETTER.pdf" in caplog.messages


def test_scan_virus_clamav_error(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mock_retry = mocker.patch("app.celery.tasks.scan_file.retry")

    scan_file(TEST_FILENAME)

    assert mock_retry.called


def test_scan_virus_boto_error(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", side_effect=BotoClientError({}, "S3 Error"))
    mock_retry = mocker.patch("app.celery.tasks.scan_file.retry")

    scan_file(TEST_FILENAME)

    assert mock_retry.called


def test_scan_virus_max_retries(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", side_effect=BotoClientError({}, "S3 Error"))
    mocker.patch("app.celery.tasks.scan_file.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_file(TEST_FILENAME)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_ERROR,
        kwargs={"filename": TEST_FILENAME},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )


def test_scan_letter_parts_all_clean(notify_antivirus, mocker):
    mock_get_pdf = mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mock_scan = mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_parts(TEST_FILENAMES)

    assert mock_get_pdf.call_args_list == [mocker.call(f) for f in TEST_FILENAMES]
    assert mock_scan.call_count == len(TEST_FILENAMES)
    mock_send_task.assert_called_once_with(
        name=TaskNames.SANITISE_LETTER_PARTS,
        kwargs={"filenames": TEST_FILENAMES},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )


def test_scan_letter_parts_virus_on_middle_part(notify_antivirus, mocker, caplog):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=[True, False, True])
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_parts(TEST_FILENAMES)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED_LETTER_PARTS,
        kwargs={"filenames": TEST_FILENAMES},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )

    assert f"VIRUS FOUND for letter part: {TEST_FILENAMES[1]}" in "\n".join(caplog.messages)


def test_scan_letter_parts_clamav_error(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mock_retry = mocker.patch("app.celery.tasks.scan_letter_parts.retry")

    scan_letter_parts(TEST_FILENAMES)

    assert mock_retry.called


def test_scan_letter_parts_boto_error(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", side_effect=BotoClientError({}, "S3 Error"))
    mock_retry = mocker.patch("app.celery.tasks.scan_letter_parts.retry")

    scan_letter_parts(TEST_FILENAMES)

    assert mock_retry.called


def test_scan_letter_parts_max_retries(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_pdf", side_effect=BotoClientError({}, "S3 Error"))
    mocker.patch("app.celery.tasks.scan_letter_parts.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_parts(TEST_FILENAMES)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_ERROR_LETTER_PARTS,
        kwargs={"filenames": TEST_FILENAMES},
        queue=QueueNames.LETTERS,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )
