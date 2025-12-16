from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    make_indicator,
    run_test_scan,
)


scan_iqy = fixtures.scanners.iqy
data_iqy = fixtures.data("test.iqy")


def test_scan_iqy(
    scan_iqy: Scanner,
    data_iqy: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        related=[
            make_indicator(
                "domain-name",
                "github.com",
            ),
            make_indicator(
                "url",
                "https://github.com/target/strelka/blob/master/docs/index.html",
            ),
        ],
        scan={
            "address_found": True,
        },
    )
    run_test_scan(
        scanner=scan_iqy,
        fixture=data_iqy,
        expected=test_event,
    )
