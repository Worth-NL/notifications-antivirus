from clamd import ClamdNetworkSocket, ClamdUnixSocket, ClamdError
from flask import current_app

AV_MODE_NETWORK = "NETWORK"
AV_MODE_SOCKET = "SOCKET"


class ClamavClient:
    def __init__(self):
        self.mode = current_app.config["ANTIVIRUS_MODE"]
        self.host = current_app.config["ANTIVIRUS_HOST"]
        self.port = current_app.config["ANTIVIRUS_PORT"]

    def get_connection(self):
        if self.mode == AV_MODE_NETWORK and self.host and self.port:
            current_app.logger.info("Returning ClamAV connection :: %s :: %s :: %s", self.mode, self.host, self.port)
            return ClamdNetworkSocket(host=self.host, port=self.port)
        else:
            current_app.logger.info("Returning ClamAV connection :: %s", AV_MODE_SOCKET)
            return ClamdUnixSocket()

    def ping(self):
        current_app.logger.debug("Function (ping)")
        cd = self.get_connection()

        try:
            cd.ping()
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
            cd = self.get_connection()
            result = cd.instream(stream)
            print(result)
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
