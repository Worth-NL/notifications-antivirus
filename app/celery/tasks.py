from io import BytesIO

import boto3
import clamd
from botocore.exceptions import ClientError as BotoClientError
from flask import current_app

from app import notify_celery
from app.clamav_client import ClamavClient
from app.config import QueueNames

cli = ClamavClient()


@notify_celery.task(bind=True, name="scan-file", max_retries=5, default_retry_delay=300)
def scan_file(self, filename):
    current_app.logger.info("Scanning file: %s", filename)

    try:
        if cli.scan(BytesIO(_get_letter_pdf(filename))):
            task_name = "sanitise-letter"
        else:
            task_name = "process-virus-scan-failed"
            current_app.logger.info("VIRUS FOUND for file: %s", filename, extra={"file_name": filename})

        current_app.logger.info(
            "Calling task: %s to process %s on API",
            task_name,
            filename,
            extra={"celery_task": task_name, "file_name": filename},
        )

        notify_celery.send_task(
            name=task_name,
            kwargs={"filename": filename},
            queue=QueueNames.LETTERS,
            MessageGroupId=self.message_group_id,
        )
    except (clamd.ClamdError, BotoClientError) as e:
        try:
            current_app.logger.exception("Scanning error on file %s: %s", filename, e, extra={"file_name": filename})
            self.retry(queue=QueueNames.ANTIVIRUS)
        except self.MaxRetriesExceededError:
            current_app.logger.exception(
                "MAX RETRY EXCEEDED: Task scan_file failed for file: %s", filename, extra={"file_name": filename}
            )

            notify_celery.send_task(
                name="process-virus-scan-error",
                kwargs={"filename": filename},
                queue=QueueNames.LETTERS,
                MessageGroupId=self.message_group_id,
            )


def _get_letter_pdf(filename):
    bucket_name = current_app.config["LETTERS_SCAN_BUCKET_NAME"]

    s3 = boto3.resource("s3")

    obj = s3.Object(bucket_name=bucket_name, key=filename)

    file_content = obj.get()["Body"].read()

    return file_content


def _get_messagebox_attachments(notification_id: str):
    # Placeholder for actual implementation to retrieve attachments from messagebox
    current_app.logger.info("Retrieving attachments for notification: %s", notification_id)

    bucket_name: str = current_app.config["LETTERS_SCAN_BUCKET_NAME"]

    s3 = boto3.resource("s3")

    files = s3.Bucket(bucket_name).objects.filter(Prefix=f"{notification_id}/")

    return files


@notify_celery.task(name="scan-messagebox-attachments", max_retries=5, default_retry_delay=300)
def scan_messagebox_attachments(self, notification_id: str):
    current_app.logger.info("Scanning messagebox attachments for notification: %s", notification_id)

    attachments: list[str] = _get_messagebox_attachments(notification_id)

    scan_result = True

    for attachment in attachments:
        try:
            if cli.scan(BytesIO(attachment.get()["Body"].read())):
                current_app.logger.info(
                    "✔ Attachment %s for notification %s is clean.",
                    attachment,
                    notification_id,
                    extra={"notification_id": notification_id, "attachment": attachment},
                )
            else:
                current_app.logger.warning(
                    "✗ VIRUS FOUND in attachment %s for notification %s.",
                    attachment,
                    notification_id,
                    extra={"notification_id": notification_id, "attachment_key": attachment},
                )

                scan_result = False
        except clamd.ClamdError as e:
            try:
                current_app.logger.exception(
                    "⛒ Scanning error on attachment %s for notification %s: %s",
                    attachment,
                    notification_id,
                    e,
                    extra={"notification_id": notification_id, "attachment_key": attachment},
                )

                self.retry(queue=QueueNames.ANTIVIRUS)
            except self.MaxRetriesExceededError:
                current_app.logger.exception(
                    "⚠ MAX RETRY EXCEEDED: Task scan_messagebox_attachments failed for attachment %s : notification %s",
                    attachment,
                    notification_id,
                    extra={"notification_id": notification_id, "attachment_key": attachment},
                )

                notify_celery.send_task(
                    name="process-virus-scan-error",
                    kwargs={"notification_id": notification_id},
                    queue=QueueNames.MESSAGEBOX,
                    MessageGroupId=notification_id,
                )

        if scan_result:
            notify_celery.send_task(
                name="send-messagebox",
                kwargs={"notification_id": notification_id},
                queue=QueueNames.MESSAGEBOX,
                MessageGroupId=notification_id,
            )
        else:
            notify_celery.send_task(
                name="process-virus-scan-failed",
                kwargs={"notification_id": notification_id},
                queue=QueueNames.MESSAGEBOX,
                MessageGroupId=notification_id,
            )
