from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_exception,
    make_event,
    run_test_scan,
)


scan_exception = fixtures.scanners.exception


class ShouldBeUncaught(BaseException):
    pass


def test_scan_exception(
    scan_exception: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   The scanner catches the exception, adds a flag, and stores
            exception/traceback information.
    Fail:   The exception is uncaught, no flag is added, or no
            exception/traceback information is present.
    """
    test_event = make_event(
        exceptions=[
            make_exception(
                "builtins.Exception",
                message="this exception should be caught",
                flag="exception:uncaught_exception",
            ),
        ],
    )
    run_test_scan(
        scanner=scan_exception,
        fixture=empty_file,
        expected=test_event,
        options={
            "exception": Exception,
            "message": "this exception should be caught",
        },
    )


def test_scan_exception_uncaught(
    scan_exception: Scanner,
    empty_file: File,
) -> None:
    """
    Pass:   The scanner doesn't catch the exception, which means that
            BaseException instances (such as ScannerTimeout) isn't caught by the
            base scanner class/wrapper method.
    Fail:   The exception is caught.
    """
    run_test_scan(
        scanner=scan_exception,
        fixture=empty_file,
        options={
            "exception": ShouldBeUncaught,
            "message": "this exception should not be caught",
        },
        raises=ShouldBeUncaught,
    )
