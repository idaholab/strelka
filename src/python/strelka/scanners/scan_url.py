from itertools import chain, starmap
import re
from typing import Any, Iterator

from . import Options, Scanner
from ..auxiliary import indicators
from ..model import Date, File, Indicator, IndicatorParseError
from ..util import safe_decode


class ScanUrl(Scanner):
    """Collects URLs from files.

    Uses regular expressions (regex) to parse URLs from file data. Multiple
    regexes are supported through the 'regex' option. The default URL regex is
    derived from these resources:
        https://mathiasbynens.be/demo/url-regex
        https://data.iana.org/TLD/tlds-alpha-by-domain.txt

    Attributes:
        regexes: Dictionary of compiled regexes used by the scanner. This
            includes a default regex that is widely scoped.

    Options:
        regex: Dictionary entry that specifies a regex to apply to the scanner.
            This entry is lazy loaded when it is first referenced, compiled, and
            stored in the regexes dictionary. Defaults to using the builtin regexes.
    """

    regexes: dict[int, tuple[Any, Any]]

    def init(self):
        self.regexes = {}

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        # initialize our event with default values
        self.event.update(
            {
                "urls": set(),
            }
        )

        # determine regex pattern to use from options, or use the default
        regex_key = options.get("regex", None)
        # if using the default pattern, check whether or not URIs should also be
        # included in addition to URLs
        include_uris = options.get("include_uris", False)
        # if we are searching for URIs, should we extract the contents of any data URIs
        # we discover?
        extract_data_uris = include_uris and options.get("extract_data_uris", True)

        if regex_key is None:
            if include_uris:
                regex_pair = (indicators.uri, indicators.uri)
            else:
                regex_pair = (indicators.url, indicators.url)
        else:
            if (pattern := options.get(regex_key)) is None:
                raise ValueError("custom regex key, but key not in options")
            if hash(pattern) not in self.regexes:
                self.regexes[hash(pattern)] = (
                    re.compile(pattern),
                    re.compile(pattern.encode()),
                )
            regex_pair = self.regexes[hash(pattern)]

        # normalize data: replace multiple whitespace characters with a single space
        data = re.sub(rb"\s+", b" ", data)

        # try to decode the data if possible, since we're better able to handle
        # extracting URIs from strings than bytes; if we aren't able to, that's fine
        try:
            if isinstance(data, bytes):
                data = data.decode()
        # find all URLs using the regex pattern
        except UnicodeDecodeError:
            regex_iter = regex_pair[1].finditer(data)
        else:
            regex_iter = regex_pair[0].finditer(data)

        # actually generate our results as (pos, match) pairs
        results = {(m.start(), m.group(0)) for m in regex_iter}

        # clean up any matched URIs, then add them to our set and do any extra handling
        for pos, result in chain(*starmap(self.cleanup_uri, results)):
            self.event["urls"].add(result)
            if extract_data_uris and result.startswith("data:"):
                self.extract_data_uri(result, pos)
            self.add_related_uri(result)

    def cleanup_uri(self, pos: int, uri: str | bytes) -> Iterator[tuple[int, str]]:
        # make sure our URI is a string
        uri = safe_decode(uri)
        # strip leading and trailing punctuation characters from the URL
        # FIXME[elleste]: This could remove meaningful characters, no? I'm just reducing
        #       the characters we can remove to "things that might logically follow as
        #       punctuation in plain text" (plus a couple others; this does strip some
        #       cruft sometimes), but I'm not sure that that's worth losing possibly
        #       meaningful characters from the rest of the possible match cases...
        # original character set: r"!\"#$%&'()*+,-./:;<>?@[\\]^_`{|}~"
        uri = uri.rstrip(r"!'),./:;?]}")
        # check to see if there are nonURL chars stil in URL:
        # FIXME[elleste]: ...some of these are valid URL characters, no?! I'm disabling
        #       this because I'd like to see a case where this is actually necessary to
        #       be convinced it's usefulness outweighs its potential forensic harm.
        # nonurl_regex_pattern = r'[\^&\(\)+\[\]{}\|"]'
        # off = pos
        # for part in re.split(nonurl_regex_pattern, url):
        #     if part and validators.url(part):
        #         yield off, part
        #     off += len(part) + 1
        yield pos, uri

    def add_related_uri(self, uri: str) -> None:
        # we do it this way (rather than calling .add_related() with the URI directly)
        # in order to eat parse errors--not every URI can be parsed as an indicator
        try:
            self.add_related(Indicator.parse(uri, self))
        except IndicatorParseError:
            pass

    def extract_data_uri(self, uri: str, offset: int) -> None:
        try:
            mime_type, data = indicators.data_uri.evaluate(uri)
        except (UnicodeDecodeError, ValueError):
            pass
        else:
            self.emit_file(
                data,
                name=f":data-uri@{offset}",
                mime_type=(mime_type,),
                unique_key=(int(offset),),
            )
