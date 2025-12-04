from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_zstd = fixtures.scanners.zstd
data_zst = fixtures.data("test.zst")


def test_scan_zstd(
    scan_zstd: Scanner,
    data_zst: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "3e88d5a5-6404-5a8e-8865-a03cdaa5c9a0",
                name=":zstd-contents",
                sha1="5030560d3a8f7e363d802cb9b1e1c82a65d60de7",
                mime_type={"text/plain"},
                size=4015,
            ),
        ],
    )
    run_test_scan(
        scanner=scan_zstd,
        fixture=data_zst,
        expected=test_event,
    )
