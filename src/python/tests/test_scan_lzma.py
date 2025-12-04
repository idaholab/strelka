from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan, make_child


scan_lzma = fixtures.scanners.lzma
data_xz = fixtures.data("test.xz")


def test_scan_lzma(
    scan_lzma: Scanner,
    data_xz: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "03fd5fdd-8401-53bd-a38b-c5a739c6421c",
                name=":lzma-contents",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                mime_type=["text/plain"],
                size=4015,
            ),
        ],
    )
    run_test_scan(
        scanner=scan_lzma,
        fixture=data_xz,
        expected=test_event,
    )
