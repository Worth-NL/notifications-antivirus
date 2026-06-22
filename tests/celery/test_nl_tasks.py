from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError as BotoClientError
from celery.exceptions import MaxRetriesExceededError
from clamd import ClamdError

from app.celery.tasks import _get_messagebox_attachments, scan_messagebox_attachments
from app.config import QueueNamesNL, TaskNames

TEST_FILENAME_1 = "EXAMPLE-SCAN-LETTER.pdf"
TEST_FILENAME_2 = "EXAMPLE-SCAN-LETTER-2.pdf"
TEST_MESSAGE_GROUP_ID = "test-message-group-id"
NOTIFICATION_ID = "299754b9-0dd3-4151-9480-31af8bbc5ddb"
TEST_ATTACHMENT_KEY_1 = f"{NOTIFICATION_ID}/attachment1.pdf"
TEST_ATTACHMENT_KEY_2 = f"{NOTIFICATION_ID}/attachment2.pdf"
TEST_DIRECTORY_KEY = f"{NOTIFICATION_ID}/"


@contextmanager
def _with_message_group_id(value: str):
    with patch("notifications_utils.celery.NotifyTask.message_group_id", new=value, create=True):
        yield


def test_messagebox_scan_single_no_virus(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.SEND_MESSAGEBOX,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_messagebox_scan_virus_detected(notify_antivirus, mocker, caplog):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=False)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )

    assert any("VIRUS FOUND" in message for message in caplog.messages)


def test_messagebox_scan_clamav_error_with_retry(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mock_retry = mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry")

    scan_messagebox_attachments(NOTIFICATION_ID)

    assert mock_retry.called
    mock_retry.assert_called_once_with(queue=QueueNamesNL.ANTIVIRUS)


def test_messagebox_scan_max_retries_exceeded(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    assert mock_send_task.call_count == 2

    mock_send_task.assert_any_call(
        name=TaskNames.PROCESS_VIRUS_SCAN_ERROR,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )

    mock_send_task.assert_any_call(
        name=TaskNames.SEND_MESSAGEBOX,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_messagebox_scan_multiple_attachments_mixed_results(notify_antivirus, mocker, caplog):
    mock_attachment1 = MagicMock()
    mock_attachment1.key = TEST_ATTACHMENT_KEY_1
    mock_attachment1.get.return_value = {"Body": MagicMock(read=lambda: b"clean content")}

    mock_attachment2 = MagicMock()
    mock_attachment2.key = TEST_ATTACHMENT_KEY_2
    mock_attachment2.get.return_value = {"Body": MagicMock(read=lambda: b"infected content")}

    def scan_side_effect(content_bytes):
        content = content_bytes.read()
        if b"infected" in content:
            return False
        return True

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment1, mock_attachment2])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=scan_side_effect)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )

    assert any("status :: PASSED" in message for message in caplog.messages)
    assert any("status !! VIRUS FOUND" in message for message in caplog.messages)


def test_messagebox_scan_no_attachments(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[])
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.SEND_MESSAGEBOX,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_get_messagebox_attachments_happy_path(notify_antivirus, mocker):
    mock_bucket = MagicMock()
    mock_s3_resource = MagicMock()
    mock_s3_resource.Bucket.return_value = mock_bucket

    mock_file_obj = MagicMock()
    mock_file_obj.key = TEST_ATTACHMENT_KEY_1

    mock_dir_obj = MagicMock()
    mock_dir_obj.key = TEST_DIRECTORY_KEY

    mock_bucket.objects.filter.return_value = [mock_file_obj, mock_dir_obj]

    mocker.patch("boto3.resource", return_value=mock_s3_resource)

    with notify_antivirus.app_context():
        notify_antivirus.config["MESSAGEBOX_SCAN_BUCKET_NAME"] = "test-bucket"

        result = _get_messagebox_attachments(NOTIFICATION_ID)

    assert len(result) == 1
    assert result[0].key == TEST_ATTACHMENT_KEY_1


def test_get_messagebox_attachments_empty_bucket(notify_antivirus, mocker):
    mock_bucket = MagicMock()
    mock_s3_resource = MagicMock()
    mock_s3_resource.Bucket.return_value = mock_bucket

    mock_bucket.objects.filter.return_value = []

    mocker.patch("boto3.resource", return_value=mock_s3_resource)

    with notify_antivirus.app_context():
        notify_antivirus.config["MESSAGEBOX_SCAN_BUCKET_NAME"] = "test-bucket"

        result = _get_messagebox_attachments(NOTIFICATION_ID)

    assert len(result) == 0
    assert result == []


def test_get_messagebox_attachments_s3_error(notify_antivirus, mocker):
    mocker.patch("boto3.resource", side_effect=BotoClientError({}, "S3 Error"))

    with notify_antivirus.app_context():
        notify_antivirus.config["MESSAGEBOX_SCAN_BUCKET_NAME"] = "test-bucket"

        with pytest.raises(BotoClientError):
            _get_messagebox_attachments(NOTIFICATION_ID)
