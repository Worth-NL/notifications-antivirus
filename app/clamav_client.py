from clamd import ClamdNetworkSocket, ClamdUnixSocket, ClamdError
from flask import current_app

AV_MODE_NETWORK = "NETWORK"
AV_MODE_SOCKET = "SOCKET"


class ClamavClient:
    def __init__(self):
        self.mode = current_app.config["ANTIVIRUS_MODE"]
        self.host = current_app.config["ANTIVIRUS_HOST"]
        self.port = int(current_app.config["ANTIVIRUS_PORT"])
        self.cli = ClamdNetworkSocket(host=self.host, port=self.port) if self.mode == AV_MODE_NETWORK and self.host and self.port else ClamdUnixSocket()

    def ping(self):
        current_app.logger.debug("Function (ping)")

        try:
            self.cli.ping()
        except ClamdError as err:
            current_app.logger.error("ClamAV error :: %s", err)
            return False
        except Exception as err:
            current_app.logger.error("Unexpected error :: %s", err)
            return False

        return True

    def scan(self, stream):
        current_app.logger.info("Function (scan)")

        try:
            result = self.cli.instream(stream)
            current_app.logger.info("Scan result :: %s", result)
            if result["stream"][0] == "FOUND":
                current_app.logger.warning("VIRUS FOUND %s", result["stream"][1])
                return False
            else:
                return True
        except ClamdError as err:
            current_app.logger.error("ClamAV error :: %s", err)
            return False
        except Exception as err:
            current_app.logger.error("Unexpected error :: %s", err)
            return False
