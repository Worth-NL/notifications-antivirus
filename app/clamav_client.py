import clamd
from flask import current_app

AV_MODE_NETWORK = "NETWORK"
AV_MODE_SOCKET = "SOCKET"


class ClamavClient:
    def ___init__(self):
        self.mode = current_app.config.get("ANTIVIRUS_MODE")
        self.host = current_app.config.get("ANTIVIRUS_HOST")
        self.port = current_app.config.get("ANTIVIRUS_PORT")

    def get_connection(self):
        cd = clamd.ClamdUnixSocket()

        if self.mode is AV_MODE_NETWORK and self.host is not None and self.port is not None:
            cd = clamd.ClamdNetworkSocket(host=self.host, port=self.port)

        return cd

    def ping(self):
        cd = self.get_connection()

        try:
            cd.ping()
        except clamd.ClamdError:
            return False

        return True

    def scan(self, stream):
        cd = self.get_connection()
        result = cd.instream(stream)

        if result["stream"][0] == "FOUND":
            current_app.logger.info("VIRUS FOUND %s", result["stream"][1])
            return False
        else:
            return True


def clamav_scan(stream):
    cd = clamd.ClamdUnixSocket()

    av_mode = current_app.config.get("ANTIVIRUS_MODE")
    if av_mode == "NETWORK":
        av_host = current_app.config.get("ANTIVIRUS_HOST")
        av_port = current_app.config.get("ANTIVIRUS_PORT")
        cd = clamd.ClamdNetworkSocket(host=av_host, port=av_port)

    result = cd.instream(stream)

    if result["stream"][0] == "FOUND":
        current_app.logger.info("VIRUS FOUND %s", result["stream"][1])
        return False
    else:
        return True
