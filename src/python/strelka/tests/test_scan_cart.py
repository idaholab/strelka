from strelka.tests import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_cart = fixtures.scanners.cart
data_cart = fixtures.data("test.cart")


def test_scan_cart(
    scan_cart: Scanner,
    data_cart: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "d07ff447-38d7-5f56-bce0-f9cb0f43324f",
                name="test.exe",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                mime_type={"application/vnd.microsoft.portable-executable"},
                size=4096,
                metadata={
                    "file": {
                        "timestamp": "2025-12-04T20:14:00Z",
                        "some_other_field": True,
                    },
                },
            ),
        ],
    )
    run_test_scan(
        scanner=scan_cart,
        fixture=data_cart,
        expected=test_event,
    )
