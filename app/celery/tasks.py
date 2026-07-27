from io import BytesIO

import boto3
import clamd
from botocore.exceptions import ClientError as BotoClientError
from flask import current_app

from app import notify_celery
from app.clamav_client import ClamavClient
from app.config import QueueNames, QueueNamesNL, TaskNames


def get_clamav_client(app):
    return ClamavClient(
        mode=app.config["ANTIVIRUS_MODE"],
        host=app.config["ANTIVIRUS_HOST"],
        port=app.config["ANTIVIRUS_PORT"],
    )


@notify_celery.task(bind=True, name=TaskNames.SCAN_FILE, max_retries=5, default_retry_delay=300)
def scan_file(self, filename):
    current_app.logger.info("Scanning file: %s", filename)

    cli = get_clamav_client(current_app)

    try:
        if cli.scan(BytesIO(_get_letter_pdf(filename))):
            task_name = TaskNames.SANITISE_LETTER
        else:
            task_name = TaskNames.PROCESS_VIRUS_SCAN_FAILED
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
                name=TaskNames.PROCESS_VIRUS_SCAN_ERROR,
                kwargs={"filename": filename},
                queue=QueueNames.LETTERS,
                MessageGroupId=self.message_group_id,
            )


@notify_celery.task(bind=True, name=TaskNames.SCAN_LETTER_PARTS, max_retries=5, default_retry_delay=300)
def scan_letter_parts(self, filenames):
    current_app.logger.info("Scanning letter parts: %s", filenames)

    cli = get_clamav_client(current_app)

    try:
        task_name = TaskNames.SANITISE_LETTER_PARTS

        for filename in filenames:
            if cli.scan(BytesIO(_get_letter_pdf(filename))):
                continue

            task_name = TaskNames.PROCESS_VIRUS_SCAN_FAILED_LETTER_PARTS
            current_app.logger.info(
                "VIRUS FOUND for letter part: %s (of %s)",
                filename,
                filenames,
                extra={"file_name": filename, "filenames": filenames},
            )

        current_app.logger.info(
            "Calling task: %s to process %s on API",
            task_name,
            filenames,
            extra={"celery_task": task_name, "filenames": filenames},
        )

        notify_celery.send_task(
            name=task_name,
            kwargs={"filenames": filenames},
            queue=QueueNames.LETTERS,
            MessageGroupId=self.message_group_id,
        )
    except (clamd.ClamdError, BotoClientError) as e:
        try:
            current_app.logger.exception(
                "Scanning error on letter parts %s: %s", filenames, e, extra={"filenames": filenames}
            )
            self.retry(queue=QueueNames.ANTIVIRUS)
        except self.MaxRetriesExceededError:
            current_app.logger.exception(
                "MAX RETRY EXCEEDED: Task scan_letter_parts failed for: %s", filenames, extra={"filenames": filenames}
            )

            notify_celery.send_task(
                name=TaskNames.PROCESS_VIRUS_SCAN_ERROR_LETTER_PARTS,
                kwargs={"filenames": filenames},
                queue=QueueNames.LETTERS,
                MessageGroupId=self.message_group_id,
            )


def _get_letter_pdf(filename):
    bucket_name = current_app.config["LETTERS_SCAN_BUCKET_NAME"]

    s3 = boto3.resource("s3")

    obj = s3.Object(bucket_name=bucket_name, key=filename)

    file_content = obj.get()["Body"].read()

    return file_content


#
# NotifyNL
#
def _get_messagebox_attachments(notification_id: str) -> list:
    bucket_name: str = current_app.config["MESSAGEBOX_SCAN_BUCKET_NAME"]

    current_app.logger.info("[%s] Retrieving attachments from bucket: %s", notification_id, bucket_name)

    s3 = boto3.resource("s3")

    files = list(s3.Bucket(bucket_name).objects.filter(Prefix=f"{notification_id}/"))
    files = [f for f in files if not f.key.endswith("/")]

    current_app.logger.info("[%s] %s attachments found for notification", notification_id, len(files))

    return files


@notify_celery.task(bind=True, name=TaskNames.MESSAGEBOX_SCAN_ATTACHMENTS, max_retries=5, default_retry_delay=300)
def scan_messagebox_attachments(self, notification_id: str):
    notification_id = str(notification_id)
    current_app.logger.info("[%s] scanning messagebox attachments", notification_id)

    cli = get_clamav_client(current_app)

    attachments: list[str] = _get_messagebox_attachments(notification_id)

    next_task_name = TaskNames.MESSAGEBOX_VIRUS_SCAN_SUCCESS

    for attachment in attachments:
        try:
            if cli.scan(BytesIO(attachment.get()["Body"].read())):
                current_app.logger.info(
                    "[%s] attachment [%s] status :: PASSED",
                    notification_id,
                    attachment,
                    extra={"notification_id": notification_id, "attachment": attachment},
                )
            else:
                current_app.logger.warning(
                    "[%s] attachment [%s] status !! VIRUS FOUND",
                    notification_id,
                    attachment,
                    extra={"notification_id": notification_id, "attachment": attachment},
                )

                next_task_name = TaskNames.MESSAGEBOX_VIRUS_SCAN_FAILED
        except clamd.ClamdError as e:
            try:
                current_app.logger.exception(
                    "[%s] error scanning attachment [%s] :: %s",
                    notification_id,
                    attachment,
                    e,
                    extra={"notification_id": notification_id, "attachment": attachment},
                )

                self.retry(queue=QueueNamesNL.ANTIVIRUS)
            except self.MaxRetriesExceededError:
                current_app.logger.exception(
                    "[%s] attachment [%s] MAX RETRY EXCEEDED",
                    notification_id,
                    attachment,
                    extra={"notification_id": notification_id, "attachment": attachment},
                )

                next_task_name = TaskNames.MESSAGEBOX_VIRUS_SCAN_ERROR

    notify_celery.send_task(
        name=next_task_name,
        kwargs={"notification_id": notification_id},
        queue=QueueNamesNL.MESSAGEBOX,
        MessageGroupId=notification_id,
    )
