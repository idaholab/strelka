from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_entropy = fixtures.scanners.entropy
data_exe = fixtures.data("test.exe")


def test_scan_entropy(
    scan_entropy: Scanner,
    data_exe: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "entropy": 4.314502621279276,
        },
    )
    run_test_scan(
        scanner=scan_entropy,
        fixture=data_exe,
        expected=test_event,
    )
