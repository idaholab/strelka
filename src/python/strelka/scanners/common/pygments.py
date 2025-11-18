from __future__ import annotations
from abc import abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
import itertools
import fnmatch
import re
from typing import ClassVar, Iterator, Mapping, NamedTuple

import pygments
from pygments import formatters, lexers

from .. import Options, Scanner
from ...model import Date, File
from ...auxiliary import indicators


class IndicatorToken(StrEnum):
    domain = "Strelka.Domain"
    url = "Strelka.Url"
    md5 = "Strelka.Md5"
    sha1 = "Strelka.Sha1"
    sha256 = "Strelka.Sha256"
    email = "Strelka.Email"
    ip = "Strelka.Ip"


@dataclass
class Event:
    token_types: set[str] = field(default_factory=set)
    tokens: dict[str, list[str]] = field(default_factory=dict)
    script_length_bytes: int = -1


class Highlight(NamedTuple):
    token: str
    value: str


class PygmentsScanner(Scanner):
    """Collects metadata/tokens from sourcefiles.

    Pygments is used as a lexer and some of the tokenized data is included in the event,
    depending on the filetype (see specific scanners for details).
    """

    TOKEN_MAPPING: ClassVar[dict[str, set[str]]]
    _lexer: lexers.Lexer
    _token_match_groups: Mapping[re.Pattern, set[str]]

    def init(self) -> None:
        # instantiate the lexer for this specific scanner
        self._lexer = self.get_lexer()
        # convert our forward token mapping to an inverse with globbing patterns, since
        # it's easier for us to use the inverse while processing the highlights; yes,
        # this does allow for a 1:N relationship of token-type:key... is this good? I
        # dunno, but it does seem logical...
        groups = defaultdict(set)
        for k, toks in self.TOKEN_MAPPING.items():
            for t in toks:
                groups[re.compile(fnmatch.translate(t))].add(k)
        self._token_match_groups = groups

    @staticmethod
    def split_highlights(contents: bytes | str) -> Iterator[Highlight]:
        if isinstance(contents, bytes):
            contents = contents.decode()

        for hl in contents.splitlines():
            if len((split := hl.split("\t"))) == 2:
                entry = Highlight(
                    split[0],
                    split[1].strip("'\"").strip(),
                )
                if entry.value:
                    yield entry

    def keys_for_token(self, token: str) -> Iterator[str]:
        for pat, keys in self._token_match_groups.items():
            if pat.match(token):
                yield from keys

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> Event:
        event = Event(
            script_length_bytes=len(data),
        )

        # use pygments to perform the highlighting
        highlight = pygments.highlight(
            data,
            self._lexer,
            formatters.RawTokenFormatter(),
        )

        # we temporarily store tokens in dictionaries of {value: pos} so that we can use
        # hashing for deduplication, but still preserve position-based token ordering in
        # the output
        tokens = {k: {} for k in {"token_types", *self.TOKEN_MAPPING}}
        for i, entry in enumerate(self.split_highlights(highlight)):
            for e in self.process_entry(entry):
                tokens["token_types"].setdefault(e.token, i)
                for key in self.keys_for_token(e.token):
                    tokens[key].setdefault(e.value, i)

        # convert our temporary storage to what we expect in the resulting event,
        #   i.e. {key: [token...], ...}
        tokens = {
            k: [t for t, _ in sorted(v.items(), key=lambda e: e[1])]
            for k, v in tokens.items()
        }

        # update the event with our results
        event.token_types.update(map(str, tokens.pop("token_types", ())))
        event.tokens.update(tokens)

        # add indicators for any items that may have been extracted
        self.add_related(
            itertools.chain(
                *(
                    tokens.get(k, ())
                    for k in set(itertools.chain(*(
                        self.keys_for_token(e.value)
                        for e in IndicatorToken._member_map_.values()
                    )))
                )
            )
        )

        # finally return our event object to populate this scan's results
        return event

    def extract_urls(self, text: str) -> Iterator[Highlight]:
        try:
            urls = indicators.url.findall(text)
            self.add_related(urls)
            yield from (Highlight(IndicatorToken.url, u) for u in urls)
        except Exception:
            self.add_flag("url_extraction_error")

    def process_entry(self, entry: Highlight) -> Iterator[Highlight]:
        yield entry

    @abstractmethod
    def get_lexer(self) -> lexers.Lexer: ...
