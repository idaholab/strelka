from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_header = fixtures.scanners.header
data_txt = fixtures.data("test.txt")
data_exe = fixtures.data("test.exe")


def test_scan_header(
    scan_header: Scanner,
    data_txt: File,
) -> None:
    """
    Pass:   Sample event matches output of the scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "header": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
            "backslash": "Lorem ipsum dolor sit amet, consectetur adipiscing",
            "hex": (
                b"4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e736563"
                b"74657475722061646970697363696e67"
            ),
            "raw": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
        },
    )
    run_test_scan(
        scanner=scan_header,
        fixture=data_txt,
        options={
            "encodings": ["classic", "raw", "hex", "backslash"],
        },
        expected=test_event,
    )


def test_scan_header_exe(
    scan_header: Scanner,
    data_exe: File,
) -> None:
    """
    Pass:   Sample event matches output of the scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "header": (
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00"
                b"\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "backslash": (
                r"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00"
                r"\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                r"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            "hex": (
                b"4d5a90000300000004000000ffff0000b80000000000000040000000000000000000"
                b"00000000000000000000000000000000"
            ),
            "raw": (
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00"
                b"\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
        },
    )
    run_test_scan(
        scanner=scan_header,
        fixture=data_exe,
        options={
            "encodings": ["classic", "raw", "hex", "backslash"],
        },
        expected=test_event,
    )
