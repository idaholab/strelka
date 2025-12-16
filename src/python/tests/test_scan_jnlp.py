from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_jnlp = fixtures.scanners.jnlp
data_jnlp = fixtures.data("test.jnlp")


def test_scan_jnlp(
    scan_jnlp: Scanner,
    data_jnlp: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "resource": "https://example.com/uplib.jar",
        },
    )
    run_test_scan(
        scanner=scan_jnlp,
        fixture=data_jnlp,
        expected=test_event,
    )
