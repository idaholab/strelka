from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_child,
    make_event,
    parse_timestamp,
    run_test_scan,
)


scan_docx = fixtures.scanners.docx
data_docx = fixtures.data("test.docx")


def test_scan_docx(
    scan_docx: Scanner,
    data_docx: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "9396a5f2-5051-5dee-ae19-d06d0a023d71",
                name=":docx-text-contents",
                sha1="1368f530a9ef0d105ec1083ea87a9a9f898d763a",
                mime_type=["text/plain"],
                size=2880,
            ),
        ],
        scan={
            "total": {
                "words": 413,
                "images": 1,
            },
            "author": "Ryan.OHoro",
            "category": "",
            "comments": "",
            "content_status": "",
            "created": parse_timestamp("2022-12-16 16:28:00"),
            "identifier": "",
            "keywords": "",
            "language": "",
            "last_modified_by": "Ryan.OHoro",
            "last_printed": None,
            "modified": parse_timestamp("2022-12-16 16:44:00"),
            "revision": 2,
            "subject": "",
            "title": "",
            "version": "",
            "font_colors": {"000000"},
            "white_text_in_doc": False,
        },
    )
    run_test_scan(
        scanner=scan_docx,
        fixture=data_docx,
        expected=test_event,
        options={
            "extract_text": True,
        },
    )
