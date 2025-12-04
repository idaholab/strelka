from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_delay = fixtures.scanners.delay


def test_scan_delay_timeout(
    scan_delay: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   Scanner adds a timed_out flag.
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


def test_scan_delay_subprocess(
    scan_delay: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   Scanner adds a timed_out flag.
    Fail:   ScannerTimeout is not caught.
    """
    test_event = make_event(
        flags={
            "delay:timed_out",
            "delay:subprocess_killed",
        },
    )
    run_test_scan(
        scanner=scan_delay,
        fixture=empty_file,
        options={
            "scanner_timeout": 1,
            "use_subprocess": True,
        },
        expected=test_event,
    )


def test_scan_delay_subprocess_timeout(
    scan_delay: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   Scanner and adds a subprocess_timed_out flag.
    Fail:   ScannerTimeout is not caught.
    """
    test_event = make_event(
        flags={
            "delay:subprocess_timed_out",
            "delay:subprocess_killed",
        },
    )
    run_test_scan(
        scanner=scan_delay,
        fixture=empty_file,
        options={
            "scanner_timeout": 2.0,
            "use_subprocess": True,
            "subprocess_timeout": 1.0,
        },
        expected=test_event,
    )
