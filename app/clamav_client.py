import clamd
from clamd import ClamdError, ClamdNetworkSocket, ClamdUnixSocket, ResponseError
from flask import current_app

AV_MODE_NETWORK = "NETWORK"
AV_MODE_SOCKET = "SOCKET"


class ClamavClient:
    def __init__(
        self,
        mode: str = AV_MODE_SOCKET,
        host: str = "127.0.0.1",
        port: int = 3310,
        timeout: float | None = None,
    ):
        self.mode = mode
        self.host = host
        self.port = port
        self.cli = (
            ClamdNetworkSocket(host=self.host, port=self.port, timeout=timeout)
            if self.mode == AV_MODE_NETWORK and self.host and self.port
            else ClamdUnixSocket(timeout=timeout)
        )

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

    def scan(self, stream) -> bool:
        """True if clamd says the stream is clean, False if it found a virus.

        Anything else is not a verdict and raises a ClamdError, so callers can retry or report an
        error instead of treating an unreachable or failing clamd as an infected file:
        ConnectionError when clamd can't be reached or the connection breaks (including a timeout),
        ResponseError when clamd replies with no result or an ERROR status.
        """
        current_app.logger.info("Function (scan) [mode: %s, host: %s, port: %s]", self.mode, self.host, self.port)

        try:
            result = self.cli.instream(stream)
        except ClamdError as err:
            current_app.logger.error("ClamAV error :: %s", err)
            raise
        except OSError as err:
            # clamd wraps connect and receive errors, but not the socket sends that stream the file
            current_app.logger.error("ClamAV connection error :: %s", err)
            raise clamd.ConnectionError(str(err)) from err

        current_app.logger.info("Scan result :: %s", result)

        try:
            status, reason = result["stream"]
        except (KeyError, TypeError, ValueError) as err:
            raise ResponseError(f"Unexpected ClamAV response: {result!r}") from err

        if status == "FOUND":
            current_app.logger.warning("VIRUS FOUND %s", reason)
            return False
        if status == "OK":
            return True

        raise ResponseError(f"ClamAV could not scan the stream: {status} {reason}")
