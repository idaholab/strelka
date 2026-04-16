import re

from . import Scanner


class ScanStrings(Scanner):
    """Collects strings from files (similar to the output of the Unix 'strings'
    utility).

    Options:
        limit: Maximum number of strings to collect, starting from the
            beginning of the file. If this value is 0, then all strings are
            collected. Defaults to 0 (unlimited).

        min_length: Minimum string length to collect.
            Bounds: [4, 256]. Defaults to 4.
    """

    _DEFAULT_MIN_LENGTH = 4
    _MIN_LENGTH_MIN = 4
    _MIN_LENGTH_MAX = 256

    def init(self):
        self._strings_regex_cache = {}

    def _get_strings_regex(self, min_length):
        try:
            min_length = int(min_length)
        except (TypeError, ValueError):
            min_length = self._DEFAULT_MIN_LENGTH

        min_length = min(max(min_length, self._MIN_LENGTH_MIN), self._MIN_LENGTH_MAX)

        cache = self._strings_regex_cache
        return cache.setdefault(
            min_length,
            re.compile(rb"[^\x00-\x1F\x7F-\xFF]{%d,}" % min_length),
        )

    def scan(self, data, file, options, expire_at):
        limit = options.get("limit", 0)
        min_length = options.get("min_length", self._DEFAULT_MIN_LENGTH)

        strings = self._get_strings_regex(min_length).findall(data)
        if limit:
            strings = strings[:limit]
        self.event["strings"] = strings
