from . import Expiration, File, Options, Scanner


class ScanException(Scanner):
    def scan(
        self,
        data: bytes,
        file: File,
        options: Options,
        expire_at: Expiration,
    ) -> None:
        exception = options.get("exception", Exception)
        message = options.get("message", "Scanner Exception")
        raise exception(message)
