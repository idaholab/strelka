import itertools
import re
from typing import Final

from pytest import fixture

from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_ocr: Final = fixtures.scanners.ocr
data_lorem_ipsum_txt = fixtures.results("lorem_ipsum.txt", encoding="bytes")
data_text_jpg: Final = fixtures.data("test_text.jpg")
data_text_png: Final = fixtures.data("test_text.png")
data_text_webp: Final = fixtures.data("test_text.webp")
data_text_gif: Final = fixtures.data("test_text.gif")
data_pdf: Final = fixtures.data("test.pdf")
data_text_thumbnail_webp: Final = fixtures.results(
    "test_text_thumbnail.webp", encoding="base64"
)


# All these tests use some subset of the same page of text encoded in different
# image/document formats. In order to simplify the test events across all the cases,
# let's split a complete block of text (by stripping whitespace, splitting into
# sections, then splitting on groups of whitespace characters) rather than repeating the
# same long list of words in each event.
#
# We generate our two merged wordlists for the different tests; for the image formats,
# we just use the short version, and for the PDF document, we use the full text.


@fixture
def text_sections(data_lorem_ipsum_txt: bytes) -> list[list[bytes]]:
    return [
        re.split(rb"\s+", s) for s in re.split(rb"\n{2,}", data_lorem_ipsum_txt.strip())
    ]


@fixture
def words_short(text_sections: list[list[bytes]]) -> list[bytes]:
    return list(itertools.chain(*text_sections[:2]))


@fixture
def words_full(text_sections: list[list[bytes]]) -> list[bytes]:
    return list(itertools.chain(*text_sections))


def test_scan_ocr_jpg(
    scan_ocr: Scanner,
    data_text_jpg: File,
    words_short: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "render": {
                "dpi": 300,
                "format": "png",
                "height": 590,
                "source": "pdf",
                "width": 928,
            },
            "text": words_short,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_text_jpg,
        expected=test_event,
    )


def test_scan_ocr_png(
    scan_ocr: Scanner,
    data_text_png: File,
    words_short: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "render": {
                "dpi": 300,
                "format": "png",
                "height": 590,
                "source": "pdf",
                "width": 928,
            },
            "text": words_short,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_text_png,
        expected=test_event,
    )


def test_scan_ocr_webp(
    scan_ocr: Scanner,
    data_text_webp: File,
    words_short: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "text": words_short,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_text_webp,
        expected=test_event,
    )


def test_scan_ocr_gif(
    scan_ocr: Scanner,
    data_text_gif: File,
    words_short: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "render": {
                "dpi": 300,
                "format": "png",
                "height": 1844,
                "source": "pdf",
                "width": 2900,
            },
            "text": words_short,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_text_gif,
        expected=test_event,
    )


def test_scan_ocr_pdf(
    scan_ocr: Scanner,
    data_pdf: File,
    words_full: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "render": {
                "dpi": 300,
                "format": "png",
                "height": 3300,
                "source": "pdf",
                "width": 2550,
            },
            "text": words_full,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_pdf,
        expected=test_event,
    )


def test_scan_ocr_thumbnail(
    scan_ocr: Scanner,
    data_text_webp: File,
    data_text_thumbnail_webp: str,
    words_short: list[bytes],
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "text": words_short,
            "base64_thumbnail": data_text_thumbnail_webp,
        },
    )
    run_test_scan(
        scanner=scan_ocr,
        fixture=data_text_webp,
        options={
            "split_words": False,
            "remove_formatting": False,
            "create_thumbnail": True,
        },
        expected=test_event,
    )
