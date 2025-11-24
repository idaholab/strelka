import time

from . import File, Options, Scanner


class ScanDelay(Scanner):
    """Delays scanner execution."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: float) -> None:
        time.sleep(options.get("delay", 5.0))
