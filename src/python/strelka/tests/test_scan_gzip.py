from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_gzip = fixtures.scanners.gzip
data_gz = fixtures.data("test.gz")


def test_scan_gzip(
    scan_gzip: Scanner,
    data_gz: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "5c5aa24e-6489-51f2-b460-c427bfea69ab",
                name=":gzip-contents",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                mime_type={"text/plain"},
                size=4015,
            ),
        ],
    )
    run_test_scan(
        scanner=scan_gzip,
        fixture=data_gz,
        expected=test_event,
    )
