from unittest import TestCase

from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_html = fixtures.scanners.html
data_html = fixtures.data("test.html")
data_base_html = fixtures.data("test_base.html")
data_hyperlinks_html = fixtures.data("test_hyperlinks.html")


def test_scan_html(
    scan_html: Scanner,
    data_html: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            (
                "1b079233-f46c-5677-b291-c41f1672af82",
                "448557d61299a81ff7c2765203a9733bf509350f66d24f10f992c4dcb461aa8c",
            ),
            (
                "6fc0c0ef-6bd9-50aa-a8d8-f290229ecc65",
                "8c3e97cc7103eec2f8959b0f27e2011f09f26386131b075a59f2423c791917ff",
            ),
        ],
        scan={
            "total": {
                "data_uris": 1,
                "extracted": 2,
                "forms": 0,
                "frames": 0,
                "inputs": 0,
                "scripts": 2,
                "spans": 35,
                "stylesheets": 0,
                "urls": 1,
            },
            "title": "Lorem Ipsum",
            "base_url": None,
            "data_uris": [
                {
                    "child_id": "1b079233-f46c-5677-b291-c41f1672af82",
                    "encoding": "base64",
                    "media_type": "image/png",
                },
            ],
            "urls": [
                {
                    "url": "https://example.com/example.js",
                    "raw_url": "https://example.com/example.js",
                    "media_type": None,
                },
            ],
            "forms": [],
            "frames": [],
            "inputs": [],
            "scripts": [
                {
                    "url": "https://example.com/example.js",
                    "raw_url": "https://example.com/example.js",
                    "language": None,
                    "type": "text/javascript",
                    "child_id": None,
                },
                {
                    "url": None,
                    "raw_url": None,
                    "language": None,
                    "type": None,
                    "child_id": None,
                },
            ],
            "stylesheets": [
                {
                    "url": None,
                    "raw_url": None,
                    "type": None,
                    "child_id": None,
                },
            ],
            "spans": [
                {
                    "class": None,
                    "style": "font-size:11pt",
                },
                {
                    "class": None,
                    "style": "background-color:white",
                },
                {
                    "class": None,
                    "style": "font-family:Calibri,sans-serif",
                },
                {
                    "class": None,
                    "style": "font-size:52.5pt",
                },
                {
                    "class": None,
                    "style": "color:black",
                },
                {
                    "class": None,
                    "style": "font-size:12pt",
                },
                {
                    "class": None,
                    "style": 'font-family:"Times New Roman",serif',
                },
                {
                    "class": None,
                    "style": "font-size:10.5pt",
                },
                {
                    "class": None,
                    "style": 'font-family:"Arial",sans-serif',
                },
            ],
        },
    )
    run_test_scan(
        scanner=scan_html,
        fixture=data_html,
        expected=test_event,
    )


def test_scan_html_base_uri(
    scan_html: Scanner,
    data_base_html: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            (
                "80cedca9-0b85-52bc-a417-47a23ac553ed",
                "448557d61299a81ff7c2765203a9733bf509350f66d24f10f992c4dcb461aa8c",
            ),
            (
                "abaeb5ed-f23a-5f04-bae8-f4dcbfa0651e",
                "8c3e97cc7103eec2f8959b0f27e2011f09f26386131b075a59f2423c791917ff",
            ),
        ],
        scan={
            "total": {
                "scripts": 5,
                "forms": 0,
                "inputs": 0,
                "frames": 0,
                "extracted": 2,
                "spans": 35,
                "hyperlinks": 7,
                "raw_hyperlinks": 7,
            },
            "title": "Lorem Ipsum",
            "hyperlinks": [
                "http://www.example42.com/http/example%20script%201.js;a=1?b=2&c=3",
                "http://www.example42.com/http/example%20script%202.js;a=1?b=2&c=3",
                "http://www.example42.com/example%20script3.js;a=1?b=2&c=3",
                "ftp:///../example%20script4.js",
                "http://www.ping-domain-1.com/page1",
                "http://www.ping-domain-2.com/page2",
                "http://www.example42.com/http/other_page.html",
            ],
            "raw_hyperlinks": [
                "example%20script%201.js;a=1?b=2&c=3",
                "http:./example%20script%202.js;a=1?b=2&c=3",
                "http:/./example%20script3.js;a=1?b=2&c=3",
                "ftp:../example%20script4.js",
                "http://www.ping-domain-1.com/page1",
                "http://www.ping-domain-2.com/page2",
                "other_page.html",
            ],
            "forms": [],
            "frames": [],
            "inputs": [],
            "scripts": [
                {
                    "language": None,
                    "raw_src": "example%20script%201.js;a=1?b=2&c=3",
                    "src": "http://www.example42.com/http/example%20script%201.js;a=1?b=2&c=3",
                    "type": "text/javascript",
                },
                {
                    "language": None,
                    "raw_src": "http:./example%20script%202.js;a=1?b=2&c=3",
                    "src": "http://www.example42.com/http/example%20script%202.js;a=1?b=2&c=3",
                    "type": "text/javascript",
                },
                {
                    "language": None,
                    "raw_src": "http:/./example%20script3.js;a=1?b=2&c=3",
                    "src": "http://www.example42.com/example%20script3.js;a=1?b=2&c=3",
                    "type": "text/javascript",
                },
                {
                    "language": None,
                    "raw_src": "ftp:../example%20script4.js",
                    "src": "ftp:///../example%20script4.js",
                    "type": "text/javascript",
                },
                {
                    "language": None,
                    "raw_src": None,
                    "src": None,
                    "type": None,
                },
            ],
            "spans": [
                {
                    "class": None,
                    "style": "font-size:11pt",
                },
                {
                    "class": None,
                    "style": "background-color:white",
                },
                {
                    "class": None,
                    "style": "font-family:Calibri,sans-serif",
                },
                {
                    "class": None,
                    "style": "font-size:52.5pt",
                },
                {
                    "class": None,
                    "style": "color:black",
                },
                {
                    "class": None,
                    "style": "font-size:12pt",
                },
                {
                    "class": None,
                    "style": 'font-family:"Times New Roman",serif',
                },
                {
                    "class": None,
                    "style": "font-size:10.5pt",
                },
                {
                    "class": None,
                    "style": 'font-family:"Arial",sans-serif',
                },
            ],
        },
    )
    run_test_scan(
        scanner=scan_html,
        fixture=data_base_html,
        expected=test_event,
    )


def test_scan_html_max_hyperlinks(
    scan_html: Scanner,
    data_hyperlinks_html: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    MAX_HYPERLINKS_OPTION = 5
    test_event = make_event(
        files=[
            (
                "80cedca9-0b85-52bc-a417-47a23ac553ed",
                "cdb4d88dca0bef8defe13d71624a46e7e851750a750a5467d53cb1bf273ab973",
            ),
        ],
        scan={
            "total": {
                "scripts": 0,
                "forms": 0,
                "inputs": 0,
                "frames": 0,
                "extracted": 1,
                "spans": 0,
                "hyperlinks": 7,
                "raw_hyperlinks": 7,
            },
            "title": "Sample HTML File",
            "hyperlinks": [
                "https://www.example.com/",
                "https://www.example2.com/",
                "https://www.example3.com/",
                "https://www.example4.com/",
                "https://www.example5.com/",
                "https://www.example.com/downloads/example.pdf",
                "https://www.example.com/images/example.jpg",
            ][:MAX_HYPERLINKS_OPTION],
            "raw_hyperlinks": [
                "https://www.example.com",
                "https://www.example2.com",
                "https://www.example3.com",
                "https://www.example4.com",
                "https://www.example5.com",
                "https://www.example.com/downloads/example.pdf",
                "https://www.example.com/images/example.jpg",
            ][:MAX_HYPERLINKS_OPTION],
            "forms": [],
            "frames": [],
            "inputs": [],
            "scripts": [],
            "spans": [],
        },
    )
    scanner_event = run_test_scan(
        scanner=scan_html,
        fixture=data_hyperlinks_html,
        options={
            "max_hyperlinks": MAX_HYPERLINKS_OPTION,
        },
        expected=test_event,
    )
    TestCase().assertLessEqual(
        len(scanner_event["scan"]["hyperlinks"]),
        MAX_HYPERLINKS_OPTION,
    )
