from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_footer = fixtures.scanners.footer
data_txt = fixtures.data("test.txt")
data_exe = fixtures.data("test.exe")


def test_scan_footer_txt(
    scan_footer: Scanner,
    data_txt: File,
) -> None:
    """
    Pass:   Sample event matches output of the scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "footer": b"itae. Et tortor consequat id porta nibh venenatis.",
            "backslash": "itae. Et tortor consequat id porta nibh venenatis.",
            "hex": (
                b"697461652e20457420746f72746f7220636f6e73657175617420696420706f727461"
                b"206e6962682076656e656e617469732e"
            ),
            "raw": b"itae. Et tortor consequat id porta nibh venenatis.",
        },
    )
    run_test_scan(
        scanner=scan_footer,
        fixture=data_txt,
        options={
            "encodings": ["classic", "raw", "hex", "backslash"],
        },
        expected=test_event,
    )


def test_scan_footer_exe(
    scan_footer: Scanner,
    data_exe: File,
) -> None:
    """
    Pass:   Sample event matches output of the scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "footer": (
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "backslash": (
                r"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                r"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                r"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "hex": (
                b"00000000000000000000000000000000000000000000000000000000000000000000"
                b"00000000000000000000000000000000"
            ),
            "raw": (
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
        },
    )
    run_test_scan(
        scanner=scan_footer,
        fixture=data_exe,
        options={
            "encodings": ["classic", "raw", "hex", "backslash"],
        },
        expected=test_event,
    )
