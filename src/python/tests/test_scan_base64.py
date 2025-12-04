from strelka.testing import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_base64 = fixtures.scanners.base64
data_b64 = fixtures.data("test.b64")
data_pe_b64 = fixtures.data("test_pe.b64")


def test_scan_base64(
    scan_base64: Scanner,
    data_b64: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "b472d1e8-a4c1-5566-88df-3027228550f3",
                name=":base64-decoded",
                sha1="d271bc4a0353bb2e22c953c212ef1058c49a791a",
                size=4007,
                mime_type={"text/plain"},
            ),
        ],
        scan={
            "decoded_header": b"Lorem ipsum dolor sit amet, consectetur adipiscing",
        },
    )
    run_test_scan(
        scanner=scan_base64,
        fixture=data_b64,
        expected=test_event,
    )


def test_scan_base64_pe(
    scan_base64: Scanner,
    data_pe_b64: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "b472d1e8-a4c1-5566-88df-3027228550f3",
                name=":base64-decoded",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                size=4096,
                mime_type={"application/vnd.microsoft.portable-executable"},
            ),
        ],
        scan={
            "decoded_header": (
                b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00"
                b"\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00"
            ),
        },
    )
    run_test_scan(
        scanner=scan_base64,
        fixture=data_pe_b64,
        expected=test_event,
    )
