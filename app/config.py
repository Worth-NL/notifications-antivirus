import os

from kombu import Exchange, Queue


class QueueNames:
    LETTERS = "letter-tasks"
    ANTIVIRUS = "antivirus-tasks"

    @staticmethod
    def all_queues():
        return [
            QueueNames.LETTERS,
            QueueNames.ANTIVIRUS,
        ]

    @staticmethod
    def predefined_queues(prefix, aws_region, aws_account_id, endpoint_url=None):
        base = endpoint_url or f"https://sqs.{aws_region}.amazonaws.com"
        return {
            f"{prefix}{queue}": {"url": f"{base}/{aws_account_id}/{prefix}{queue}"} for queue in QueueNames.all_queues()
        }


class Config:
    # The config option NOTIFY_ENVIRONMENT is purely used for logging.
    # It should not be used for any logical conditionals in the code.
    NOTIFY_ENVIRONMENT = os.environ["NOTIFY_ENVIRONMENT"]

    # Celery log levels
    CELERY_WORKER_LOG_LEVEL = os.getenv("CELERY_WORKER_LOG_LEVEL", "CRITICAL").upper()
    CELERY_BEAT_LOG_LEVEL = os.getenv("CELERY_BEAT_LOG_LEVEL", "INFO").upper()

    NOTIFICATION_QUEUE_PREFIX = os.getenv("NOTIFICATION_QUEUE_PREFIX")
    ENABLE_SQS_MESSAGE_GROUP_IDS = os.environ.get("ENABLE_SQS_MESSAGE_GROUP_IDS", "1") == "1"

    # Logging
    DEBUG = False
    LOGGING_STDOUT_JSON = os.getenv("LOGGING_STDOUT_JSON") == "1"

    ###########################
    # Default config values ###
    ###########################
    NOTIFY_APP_NAME = "antivirus"
    AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")

    NOTIFY_REQUEST_LOG_LEVEL = os.getenv("NOTIFY_REQUEST_LOG_LEVEL", "INFO")

    ANTIVIRUS_API_KEY = os.getenv("ANTIVIRUS_API_KEY")

    AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "123456789012")
    CELERY = {
        "broker_url": "https://sqs.eu-west-1.amazonaws.com",
        "broker_transport": "sqs",
        "broker_transport_options": {
            "region": AWS_REGION,
            "queue_name_prefix": NOTIFICATION_QUEUE_PREFIX,
            "is_secure": True,
            "wait_time_seconds": 20,  # enable long polling, with a wait time of 20 seconds
            "predefined_queues": QueueNames.predefined_queues(NOTIFICATION_QUEUE_PREFIX, AWS_REGION, AWS_ACCOUNT_ID),
        },
        "timezone": "Europe/London",
        "imports": ["app.celery.tasks"],
        "task_queues": [
            Queue(
                QueueNames.ANTIVIRUS,
                Exchange("default"),
                routing_key=QueueNames.ANTIVIRUS,
            )
        ],
    }

    LETTERS_SCAN_BUCKET_NAME = os.environ.get("LETTERS_SCAN_BUCKET_NAME")


######################
# Config overrides ###
######################
class Development(Config):
    SERVER_NAME = os.getenv("SERVER_NAME")

    CELERY_WORKER_LOG_LEVEL = "INFO"

    NOTIFICATION_QUEUE_PREFIX = "development"
    DEBUG = True

    ANTIVIRUS_API_KEY = "test-key"

    LETTERS_SCAN_BUCKET_NAME = "development-letters-scan"

    CELERY = {
        **Config.CELERY,
        "broker_transport_options": {
            key: value for key, value in Config.CELERY["broker_transport_options"].items() if key != "predefined_queues"
        },
    }


class Test(Config):
    DEBUG = True

    ANTIVIRUS_API_KEY = "test-key"

    CELERY_WORKER_LOG_LEVEL = "INFO"

    LETTERS_SCAN_BUCKET_NAME = "test-letters-pdf"

    CELERY = {
        **Config.CELERY,
        "broker_transport_options": {
            key: value for key, value in Config.CELERY["broker_transport_options"].items() if key != "predefined_queues"
        },
    }


##############
# NotifyNL ###
##############
NL_PREFIX = "notifynl"


class QueueNamesNL(QueueNames):
    MESSAGEBOX = "messagebox-tasks"

    @staticmethod
    def all_queues():
        return QueueNames.all_queues() + [QueueNamesNL.MESSAGEBOX]

    @staticmethod
    def predefined_queues(prefix, aws_region, aws_account_id, endpoint_url=None):
        base = endpoint_url or f"https://sqs.{aws_region}.amazonaws.com"
        return {
            f"{prefix}{queue}": {"url": f"{base}/{aws_account_id}/{prefix}{queue}"}
            for queue in QueueNamesNL.all_queues()
        }


class TaskNames:
    # Letters
    SCAN_FILE = "scan-file"
    PROCESS_VIRUS_SCAN_FAILED = "process-virus-scan-failed"
    PROCESS_VIRUS_SCAN_ERROR = "process-virus-scan-error"
    SANITISE_LETTER = "sanitise-letter"
    # Letter parts (precompiled letters submitted as multiple PDFs to be merged)
    SCAN_LETTER_PARTS = "scan-letter-parts"
    SANITISE_LETTER_PARTS = "sanitise-letter-parts"
    PROCESS_VIRUS_SCAN_FAILED_LETTER_PARTS = "process-virus-scan-failed-letter-parts"
    PROCESS_VIRUS_SCAN_ERROR_LETTER_PARTS = "process-virus-scan-error-letter-parts"
    # Letter attachments (ad-hoc PDFs submitted alongside a templated letter send)
    SCAN_LETTER_ATTACHMENTS = "scan-letter-attachments"
    PROCESS_VIRUS_SCAN_SUCCESS_LETTER_ATTACHMENTS = "process-virus-scan-success-letter-attachments"
    PROCESS_VIRUS_SCAN_FAILED_LETTER_ATTACHMENTS = "process-virus-scan-failed-letter-attachments"
    PROCESS_VIRUS_SCAN_ERROR_LETTER_ATTACHMENTS = "process-virus-scan-error-letter-attachments"
    # Messagebox
    MESSAGEBOX_SCAN_ATTACHMENTS = "messagebox.virus-scan"
    MESSAGEBOX_VIRUS_SCAN_SUCCESS = "messagebox.virus-scan-success"
    MESSAGEBOX_VIRUS_SCAN_FAILED = "messagebox.virus-scan-failed"
    MESSAGEBOX_VIRUS_SCAN_ERROR = "messagebox.virus-scan-error"
    MESSAGEBOX_DELIVER = "messagebox.deliver"


class ConfigNL(Config):
    """
    Overrides for NotifyNL usage
    """

    LETTERS_SCAN_BUCKET_NAME = os.getenv("S3_BUCKET_LETTERS_SCAN")
    MESSAGEBOX_SCAN_BUCKET_NAME = os.getenv("S3_BUCKET_MESSAGEBOX_SCAN")

    ANTIVIRUS_MODE = os.getenv("ANTIVIRUS_MODE", "SOCKET")
    ANTIVIRUS_HOST = os.getenv("CLAMAV_SERVICE_HOST", "127.0.0.1")
    ANTIVIRUS_PORT = int(os.getenv("CLAMAV_SERVICE_PORT", 3310))

    TIMEZONE = os.getenv("TZ", "Europe/Amsterdam")

    CELERY = {**Config.CELERY, "timezone": TIMEZONE}


class DevNL(ConfigNL):
    NOTIFY_ENVIRONMENT = "development"
    DEBUG = True
    NOTIFY_LOG_LEVEL = os.getenv("NOTIFY_LOG_LEVEL", "DEBUG")

    ANTIVIRUS_API_KEY = "test-key"

    STATSD_ENABLED = False

    LETTERS_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-letters-scan"
    MESSAGEBOX_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-scan"
    MESSAGEBOX_ATTACHMENTS_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-attachments"

    CELERY_WORKER_LOG_LEVEL = "DEBUG"

    CELERY = {
        "broker_url": "http://ministack:4566",
        "broker_transport": "sqs",
        "broker_transport_options": {
            "region": Config.AWS_REGION,
            "queue_name_prefix": Config.NOTIFICATION_QUEUE_PREFIX,
            "is_secure": False,
            "wait_time_seconds": 20,
            # ministack's default test account ID (000000000000), not
            # Config.AWS_ACCOUNT_ID's real-AWS-shaped default.
            "predefined_queues": QueueNamesNL.predefined_queues(
                Config.NOTIFICATION_QUEUE_PREFIX,
                Config.AWS_REGION,
                "000000000000",
                endpoint_url="http://ministack:4566",
            ),
        },
        "timezone": ConfigNL.TIMEZONE,
        "imports": ["app.celery.tasks"],
        "task_queues": [
            Queue(
                QueueNames.ANTIVIRUS,
                Exchange("default"),
                routing_key=QueueNames.ANTIVIRUS,
            )
        ],
    }

    ANTIVIRUS_MODE = "NETWORK"
    ANTIVIRUS_HOST = "clamav"


class TestNL(ConfigNL):
    NOTIFY_ENVIRONMENT = "test"
    DEBUG = True
    NOTIFY_LOG_LEVEL = "INFO"

    ANTIVIRUS_API_KEY = "test-key"

    STATSD_ENABLED = False

    LETTERS_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-letters-scan"
    MESSAGEBOX_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-scan"
    MESSAGEBOX_ATTACHMENTS_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-attachments"

    CELERY = {
        **Config.CELERY,
        "broker_transport_options": {
            key: value for key, value in Config.CELERY["broker_transport_options"].items() if key != "predefined_queues"
        },
    }

    ANTIVIRUS_MODE = os.getenv("ANTIVIRUS_MODE", "NETWORK")
    ANTIVIRUS_HOST = os.getenv("CLAMAV_SERVICE_HOST", "clamav")
    ANTIVIRUS_PORT = int(os.getenv("CLAMAV_SERVICE_PORT", 3310))


class ProdNL(ConfigNL):
    NOTIFY_ENVIRONMENT = "production"
    DEBUG = False
    NOTIFY_LOG_LEVEL = "INFO"

    ANTIVIRUS_API_KEY = os.getenv("ANTIVIRUS_API_KEY", "test-key")

    STATSD_ENABLED = False

    LETTERS_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-letters-scan"
    MESSAGEBOX_SCAN_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-scan"
    MESSAGEBOX_ATTACHMENTS_BUCKET_NAME = f"{NL_PREFIX}-{NOTIFY_ENVIRONMENT}-messagebox-attachments"

    CELERY = {
        **Config.CELERY,
        "broker_transport_options": {
            key: value for key, value in Config.CELERY["broker_transport_options"].items() if key != "predefined_queues"
        },
    }

    ANTIVIRUS_MODE = os.getenv("ANTIVIRUS_MODE", "NETWORK")
    ANTIVIRUS_HOST = os.getenv("CLAMAV_SERVICE_HOST", "clamav")
    ANTIVIRUS_PORT = int(os.getenv("CLAMAV_SERVICE_PORT", 3310))


configs = {"development": DevNL, "test": TestNL, "production": ProdNL}
