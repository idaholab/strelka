from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_ccn = fixtures.scanners.ccn
data_pii_csv = fixtures.data("test_pii.csv")


def test_scan_ccn(
    scan_ccn: Scanner,
    data_pii_csv: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={"ccn:luhn_match"},
    )
    run_test_scan(
        scanner=scan_ccn,
        fixture=data_pii_csv,
        expected=test_event,
    )
