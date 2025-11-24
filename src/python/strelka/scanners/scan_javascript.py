from typing import ClassVar

import esprima
import jsbeautifier

from . import Options, Scanner
from ..model import Date, File
from ..auxiliary import indicators


class ScanJavascript(Scanner):
    """
    This scanner extracts various components from JavaScript files, such as tokens,
    keywords, strings, identifiers, and regular expressions. It also has the option
    to deobfuscate the JavaScript before scanning. URLs within the script are
    extracted and added as indicators of compromise (IOCs).

    Options:
        beautify: Determines if JavaScript should be deobfuscated (default: True).
        max_strings: Maximum number of strings to extract from each category
            (default: 50).
    """

    EVENT_STRING_FIELDS: ClassVar = {
        "tokens",
        "keywords",
        "strings",
        "identifiers",
        "regular_expressions",
        "urls",
        "suspicious_keywords",
    }
    SUSPICIOUS_KEYWORDS: ClassVar = {
        "eval",
        "Function",
        "unescape",
        "execCommand",
        "ActiveXObject",
        "XMLHttpRequest",
        "onerror",
        "onload",
        "onclick",
        "WebSocket",
        "crypto",
        "Worker",
    }

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """
        Scans a Javascript file, tokenizes it, and extracts useful components.

        Args:
            data: Content of the file being scanned.
            file: File metadata.
            options: Scanner options.
            expire_at: Expiry timestamp of the scan task.
        """
        beautify = options.get("beautify", True)
        max_strings = options.get("max_strings", -1)
        encoding = options.get("encoding", "utf-8")
        suspicious_keywords = {
            *self.SUSPICIOUS_KEYWORDS,
            *options.get("suspicious_keywords", ()),
        }

        # initialize our event data
        self.event.update(
            {
                "tokens": set(),
                "keywords": set(),
                "strings": set(),
                "identifiers": set(),
                "regular_expressions": set(),
                "suspicious_keywords": set(),
                "urls": set(),
                "beautified": False,
                "script_length_bytes": len(data),
            }
        )

        # try to decode our file contents from bytes -> string; if we fail to decode,
        # add a flag to show that YMMV with the rest of the processing, then repeat, but
        # this time, ignore any encoding problems
        try:
            source = data.decode(encoding, errors="strict")
        except UnicodeDecodeError as e:
            self.add_flag("js_decode_error", e)
            source = data.decode(encoding, errors="ignore")

        # if requested, try to beautify the javascript we were provided
        if beautify:
            try:
                source = jsbeautifier.beautify(source)
                self.event["beautified"] = True
            except Exception as e:
                self.add_flag("js_beautify_error", e)

        # generate tokens from the (maybe beautified) javascript source
        try:
            tokens = esprima.tokenize(
                source,
                options={
                    "comment": True,
                    "tolerant": True,
                },
            )
        except Exception as e:
            self.add_flag("js_tokenization_error", e)
            tokens = []

        # if tokenization was successful, process the tokens
        for t in tokens:
            # record the type of token we're seeing
            self.event["tokens"].add(t.type)
            # do token-specific handling
            match t.type:
                case "String":
                    value = t.value
                    # trim quotes, but such that we won't accidentally clobbery any
                    # actual quotes that are present at the ends of the string
                    if value[0] in "\"'":
                        value = value.removeprefix(value[0]).removesuffix(value[0])
                    self.event["strings"].add(value)
                    # add any URLs within the string
                    self.event["urls"].update(indicators.url.findall(value))
                case "Keyword":
                    self.event["keywords"].add(t.value)
                case "Identifier":
                    if t.value in suspicious_keywords:
                        self.event["suspicious_keywords"].add(t.value)
                    self.event["identifiers"].add(t.value)
                case "RegularExpression":
                    self.event["regular_expressions"].add(t.value)

        # convert sets to sorted lists, and maybe trim to desired length
        for key in self.EVENT_STRING_FIELDS:
            values = sorted(self.event[key])
            if max_strings >= 0:
                values = values[:max_strings]
            self.event[key] = values

        # add URLs as IOCs
        # FIXME[elleste]: Should this be before trimming-to-max?
        self.add_related(self.event["urls"])
