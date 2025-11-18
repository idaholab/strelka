import entropy

from . import Scanner


class ScanEntropy(Scanner):
    """Calculates entropy of files."""

    def scan(self, data, file, options, expire_at):
        self.event["entropy"] = entropy.shannon_entropy(data)
