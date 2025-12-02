import subprocess
import time

from . import Options, Scanner
from ..model import Date, File


class ScanDelay(Scanner):
    """Delays scanner execution."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        if options.get("use_subprocess", False):
            try:
                self.run_program(
                    "sleep",
                    [options.get("delay", 5.0)],
                    timeout=options.get("subprocess_timeout", None),
                )
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(options.get("delay", 5.0))
