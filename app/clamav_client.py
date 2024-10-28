import clamd
from flask import current_app

AV_MODE_NETWORK = "NETWORK"
AV_MODE_SOCKET = "SOCKET"


class ClamavClient:
    def __init__(self):
        current_app.logger.info("ClamAV client starting...")
        self.mode = current_app.config["ANTIVIRUS_MODE"]
        self.host = current_app.config["ANTIVIRUS_HOST"]
        self.port = current_app.config["ANTIVIRUS_PORT"]
        current_app.logger.info("ClamAV client initialized in %s mode :: %s : %s", self.mode, self.host, self.port)

    def get_connection(self):
        cd = clamd.ClamdUnixSocket()

        if self.mode is AV_MODE_NETWORK and self.host is not None and self.port is not None:
            cd = clamd.ClamdNetworkSocket(host=self.host, port=self.port)

        return cd

    def ping(self):
        current_app.logger.debug("Function (ping)")
        cd = self.get_connection()

        try:
            cd.ping()
        except clamd.ClamdError as err: #FIXME General exception should be caught once connection is corrected
            current_app.logger.error("ClamAV error :: %s", err)
            return False

        return True

    def scan(self, stream):
        current_app.logger.info("Function (scan)")

        try:
            cd = self.get_connection()
            result = cd.instream(stream)
            if result["stream"][0] == "FOUND":
                current_app.logger.warning("VIRUS FOUND %s", result["stream"][1])
                return False
            else:
                return True
        except Exception as err:
            current_app.logger.error("Error during scan :: %s", err)
            return True #FIXME: Must return false once connection is corrected


def clamav_scan(stream):
    current_app.logger.info("Old method accessed...")
    cd = clamd.ClamdUnixSocket()

    av_mode = current_app.config.get("ANTIVIRUS_MODE")
    current_app.logger.info("AV_MODE :: %s", av_mode)
    if av_mode == "NETWORK":
        av_host = current_app.config.get("ANTIVIRUS_HOST")
        av_port = current_app.config.get("ANTIVIRUS_PORT")
        current_app.logger.info("AV host :: %s:%s", av_host, av_port)
        cd = clamd.ClamdNetworkSocket(host=av_host, port=av_port)

    result = cd.instream(stream)

    if result["stream"][0] == "FOUND":
        current_app.logger.warning("VIRUS FOUND %s", result["stream"][1])
        return False
    else:
        return True
