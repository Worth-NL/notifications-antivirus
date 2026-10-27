from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import clamd
import pytest
from botocore.exceptions import ClientError as BotoClientError
from celery.exceptions import MaxRetriesExceededError
from clamd import ClamdError

from app.celery.tasks import (
    CLAMAV_UNAVAILABLE_MAX_RETRIES,
    _get_letter_attachment_objects,
    _get_messagebox_attachments,
    scan_file,
    scan_letter_attachments,
    scan_letter_parts,
    scan_messagebox_attachments,
)
from app.config import QueueNames, QueueNamesNL, TaskNames

TEST_MESSAGE_GROUP_ID = "test-message-group-id"
NOTIFICATION_ID = "299754b9-0dd3-4151-9480-31af8bbc5ddb"
TEST_ATTACHMENT_KEY_1 = f"{NOTIFICATION_ID}/EXAMPLE-SCAN-LETTER.pdf"
TEST_ATTACHMENT_KEY_2 = f"{NOTIFICATION_ID}/EXAMPLE-SCAN-LETTER-2.pdf"
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
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_SUCCESS,
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
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_FAILED,
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
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    scan_messagebox_attachments(NOTIFICATION_ID)

    assert mock_retry.called
    mock_retry.assert_called_once_with(queue=QueueNamesNL.ANTIVIRUS)
    mock_send_task.assert_called_once_with(
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_SUCCESS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


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

    mock_send_task.assert_called_once_with(
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_ERROR,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_messagebox_scan_listing_boto_error_with_retry(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_messagebox_attachments", side_effect=BotoClientError({}, "S3 Error"))
    mock_retry = mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry")
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    scan_messagebox_attachments(NOTIFICATION_ID)

    mock_retry.assert_called_once_with(queue=QueueNamesNL.ANTIVIRUS)
    mock_send_task.assert_not_called()


def test_messagebox_scan_listing_boto_error_max_retries(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_messagebox_attachments", side_effect=BotoClientError({}, "S3 Error"))
    mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_ERROR,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_messagebox_scan_attachment_boto_error_with_retry(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.side_effect = BotoClientError({}, "S3 Error")

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment])
    mock_retry = mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry")
    mocker.patch("app.notify_celery.send_task")

    scan_messagebox_attachments(NOTIFICATION_ID)

    mock_retry.assert_called_once_with(queue=QueueNamesNL.ANTIVIRUS)


def test_messagebox_scan_virus_found_before_later_attachment_errors_out(notify_antivirus, mocker):
    """A confirmed virus must win over a later scan error: MESSAGEBOX_VIRUS_SCAN_FAILED is
    final/quarantining, MESSAGEBOX_VIRUS_SCAN_ERROR just reschedules the scan, so downgrading
    a real detection to "error" would leave infected content un-quarantined."""
    mock_attachment1 = MagicMock()
    mock_attachment1.key = TEST_ATTACHMENT_KEY_1
    mock_attachment1.get.return_value = {"Body": MagicMock(read=lambda: b"infected content")}

    mock_attachment2 = MagicMock()
    mock_attachment2.key = TEST_ATTACHMENT_KEY_2
    mock_attachment2.get.return_value = {"Body": MagicMock(read=lambda: b"errors every time")}

    def scan_side_effect(content_bytes):
        content = content_bytes.read()
        if b"infected" in content:
            return False
        raise ClamdError

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment1, mock_attachment2])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=scan_side_effect)
    mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_FAILED,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_messagebox_scan_error_before_later_virus_found(notify_antivirus, mocker):
    mock_attachment1 = MagicMock()
    mock_attachment1.key = TEST_ATTACHMENT_KEY_1
    mock_attachment1.get.return_value = {"Body": MagicMock(read=lambda: b"errors every time")}

    mock_attachment2 = MagicMock()
    mock_attachment2.key = TEST_ATTACHMENT_KEY_2
    mock_attachment2.get.return_value = {"Body": MagicMock(read=lambda: b"infected content")}

    def scan_side_effect(content_bytes):
        content = content_bytes.read()
        if b"infected" in content:
            return False
        raise ClamdError

    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[mock_attachment1, mock_attachment2])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=scan_side_effect)
    mocker.patch("app.celery.tasks.scan_messagebox_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_FAILED,
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
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_FAILED,
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
        name=TaskNames.MESSAGEBOX_VIRUS_SCAN_SUCCESS,
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


def test_letter_attachments_scan_single_no_virus(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_SUCCESS_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_letter_attachments_scan_virus_detected(notify_antivirus, mocker, caplog):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=False)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )

    assert any("VIRUS FOUND" in message for message in caplog.messages)


def test_letter_attachments_scan_clamav_error_with_retry(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mock_retry = mocker.patch("app.celery.tasks.scan_letter_attachments.retry")
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    scan_letter_attachments(NOTIFICATION_ID)

    assert mock_retry.called
    mock_retry.assert_called_once_with(queue=QueueNames.ANTIVIRUS)
    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_SUCCESS_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_letter_attachments_scan_max_retries_exceeded(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=ClamdError())
    mocker.patch("app.celery.tasks.scan_letter_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_ERROR_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_letter_attachments_scan_listing_boto_error_with_retry(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_attachment_objects", side_effect=BotoClientError({}, "S3 Error"))
    mock_retry = mocker.patch("app.celery.tasks.scan_letter_attachments.retry")
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    scan_letter_attachments(NOTIFICATION_ID)

    mock_retry.assert_called_once_with(queue=QueueNames.ANTIVIRUS)
    mock_send_task.assert_not_called()


def test_letter_attachments_scan_listing_boto_error_max_retries(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_attachment_objects", side_effect=BotoClientError({}, "S3 Error"))
    mocker.patch("app.celery.tasks.scan_letter_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_ERROR_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_letter_attachments_scan_attachment_boto_error_with_retry(notify_antivirus, mocker):
    mock_attachment = MagicMock()
    mock_attachment.key = TEST_ATTACHMENT_KEY_1
    mock_attachment.get.side_effect = BotoClientError({}, "S3 Error")

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment])
    mock_retry = mocker.patch("app.celery.tasks.scan_letter_attachments.retry")
    mocker.patch("app.notify_celery.send_task")

    scan_letter_attachments(NOTIFICATION_ID)

    mock_retry.assert_called_once_with(queue=QueueNames.ANTIVIRUS)


def test_letter_attachments_scan_virus_found_before_later_attachment_errors_out(notify_antivirus, mocker):
    """A confirmed virus must win over a later scan error: PROCESS_VIRUS_SCAN_FAILED_LETTER_ATTACHMENTS is
    final/quarantining, PROCESS_VIRUS_SCAN_ERROR_LETTER_ATTACHMENTS just reschedules the scan, so downgrading
    a real detection to "error" would leave infected content un-quarantined."""
    mock_attachment1 = MagicMock()
    mock_attachment1.key = TEST_ATTACHMENT_KEY_1
    mock_attachment1.get.return_value = {"Body": MagicMock(read=lambda: b"infected content")}

    mock_attachment2 = MagicMock()
    mock_attachment2.key = TEST_ATTACHMENT_KEY_2
    mock_attachment2.get.return_value = {"Body": MagicMock(read=lambda: b"errors every time")}

    def scan_side_effect(content_bytes):
        content = content_bytes.read()
        if b"infected" in content:
            return False
        raise ClamdError

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment1, mock_attachment2])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=scan_side_effect)
    mocker.patch("app.celery.tasks.scan_letter_attachments.retry", side_effect=MaxRetriesExceededError)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_letter_attachments_scan_multiple_attachments_mixed_results(notify_antivirus, mocker, caplog):
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

    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[mock_attachment1, mock_attachment2])
    mocker.patch("app.clamav_client.ClamavClient.scan", side_effect=scan_side_effect)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_FAILED_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )

    assert any("status :: PASSED" in message for message in caplog.messages)
    assert any("status !! VIRUS FOUND" in message for message in caplog.messages)


def test_letter_attachments_scan_no_attachments(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[])
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_letter_attachments(NOTIFICATION_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.PROCESS_VIRUS_SCAN_SUCCESS_LETTER_ATTACHMENTS,
        kwargs={"notification_id": NOTIFICATION_ID},
        queue=QueueNames.LETTERS,
        MessageGroupId=NOTIFICATION_ID,
    )


def test_get_letter_attachment_objects_happy_path(notify_antivirus, mocker):
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
        notify_antivirus.config["LETTERS_SCAN_BUCKET_NAME"] = "test-bucket"

        result = _get_letter_attachment_objects(NOTIFICATION_ID)

    assert len(result) == 1
    assert result[0].key == TEST_ATTACHMENT_KEY_1


def test_get_letter_attachment_objects_empty_bucket(notify_antivirus, mocker):
    mock_bucket = MagicMock()
    mock_s3_resource = MagicMock()
    mock_s3_resource.Bucket.return_value = mock_bucket

    mock_bucket.objects.filter.return_value = []

    mocker.patch("boto3.resource", return_value=mock_s3_resource)

    with notify_antivirus.app_context():
        notify_antivirus.config["LETTERS_SCAN_BUCKET_NAME"] = "test-bucket"

        result = _get_letter_attachment_objects(NOTIFICATION_ID)

    assert len(result) == 0
    assert result == []


def test_get_letter_attachment_objects_s3_error(notify_antivirus, mocker):
    mocker.patch("boto3.resource", side_effect=BotoClientError({}, "S3 Error"))

    with notify_antivirus.app_context():
        notify_antivirus.config["LETTERS_SCAN_BUCKET_NAME"] = "test-bucket"

        with pytest.raises(BotoClientError):
            _get_letter_attachment_objects(NOTIFICATION_ID)


# The tests below run the real ClamavClient with only the clamd socket failing, so an error swallowed
# anywhere between the socket and the task's retry shows up here instead of as a false virus verdict.


class _Retry(Exception):
    pass


def _attachment():
    attachment = MagicMock()
    attachment.key = TEST_ATTACHMENT_KEY_1
    attachment.get.return_value = {"Body": MagicMock(read=lambda: b"test content")}
    return attachment


def _run_scan_task(mocker, task_name):
    mocker.patch("app.celery.tasks._get_letter_pdf", return_value=b"test")
    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[_attachment()])
    mocker.patch("app.celery.tasks._get_letter_attachment_objects", return_value=[_attachment()])
    task, arg = {
        "scan_file": (scan_file, "EXAMPLE-SCAN-LETTER.pdf"),
        "scan_letter_parts": (scan_letter_parts, ["EXAMPLE-SCAN-LETTER.pdf", "EXAMPLE-SCAN-LETTER.PART2.pdf"]),
        "scan_messagebox_attachments": (scan_messagebox_attachments, NOTIFICATION_ID),
        "scan_letter_attachments": (scan_letter_attachments, NOTIFICATION_ID),
    }[task_name]
    # Like the real Task.retry, raise so the task stops where it would in production.
    mock_retry = mocker.patch.object(task, "retry", side_effect=_Retry)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with pytest.raises(_Retry):
        task(arg)

    return mock_retry, mock_send_task


SCAN_TASKS = ["scan_file", "scan_letter_parts", "scan_messagebox_attachments", "scan_letter_attachments"]


@pytest.mark.parametrize("task_name", SCAN_TASKS)
def test_scan_retries_for_a_day_when_clamav_unreachable(notify_antivirus, mocker, task_name):
    mocker.patch("socket.socket.connect", side_effect=ConnectionRefusedError(111, "Connection refused"))

    mock_retry, mock_send_task = _run_scan_task(mocker, task_name)

    assert mock_retry.call_args.kwargs["max_retries"] == CLAMAV_UNAVAILABLE_MAX_RETRIES
    mock_send_task.assert_not_called()


@pytest.mark.parametrize("task_name", SCAN_TASKS)
def test_scan_retries_when_clamav_cannot_scan(notify_antivirus, mocker, task_name):
    # A deterministic clamd error is not an outage: it keeps the task's own retry limit.
    mocker.patch("clamd.ClamdNetworkSocket.instream", side_effect=clamd.BufferTooLongError("size limit exceeded"))
    mocker.patch("clamd.ClamdUnixSocket.instream", side_effect=clamd.BufferTooLongError("size limit exceeded"))

    mock_retry, mock_send_task = _run_scan_task(mocker, task_name)

    assert "max_retries" not in mock_retry.call_args.kwargs
    mock_send_task.assert_not_called()
