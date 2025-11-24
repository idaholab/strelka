from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan


scan_delay = fixtures.scanners.delay


def test_scan_delay(
    scan_delay: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   Scanner throws a ScannerTimeout exception, and adds a timed_out flag.
    Fail:   ScannerTimeout is not caught.
    """
    test_event = make_event(
        flags={"delay:timed_out"},
    )
    run_test_scan(
        scanner=scan_delay,
        fixture=empty_file,
        options={
            "scanner_timeout": 1,
        },
        expected=test_event,
    )
