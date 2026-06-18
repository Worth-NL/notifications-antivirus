from contextlib import contextmanager
from unittest.mock import patch

from app.celery.tasks import scan_messagebox_attachments
from app.config import QueueNamesNL, TaskNames

TEST_FILENAME_1 = "EXAMPLE-SCAN-LETTER.pdf"
TEST_FILENAME_2 = "EXAMPLE-SCAN-LETTER-2.pdf"
TEST_MESSAGE_GROUP_ID = "test-message-group-id"


@contextmanager
def _with_message_group_id(value: str):
    with patch("notifications_utils.celery.NotifyTask.message_group_id", new=value, create=True):
        yield


def test_messagebox_scan_single_no_virus(notify_antivirus, mocker):
    mocker.patch("app.celery.tasks._get_messagebox_attachments", return_value=[TEST_FILENAME_1])
    mocker.patch("app.clamav_client.ClamavClient.scan", return_value=True)
    mock_send_task = mocker.patch("app.notify_celery.send_task")

    with _with_message_group_id(TEST_MESSAGE_GROUP_ID):
        scan_messagebox_attachments(TEST_MESSAGE_GROUP_ID)

    mock_send_task.assert_called_once_with(
        name=TaskNames.SEND_MESSAGEBOX,
        kwargs={"notification_id": TEST_MESSAGE_GROUP_ID},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=TEST_MESSAGE_GROUP_ID,
    )
