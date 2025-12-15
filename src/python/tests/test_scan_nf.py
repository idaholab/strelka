from strelka.testing import File, Scanner, fixtures, make_event, run_test_scan


scan_nf = fixtures.scanners.nf
data_jpg = fixtures.data("test.jpg")
data_embed_rar_jpg = fixtures.data("test_embed_rar.jpg")
data_png = fixtures.data("test.png")
data_embed_rar_png = fixtures.data("test_embed_rar.png")


def test_scan_nf_jpg(
    scan_nf: Scanner,
    data_jpg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "percentage": 0.0,
            "threshold": 0.25,
            "noise_floor": True,
        },
    )
    run_test_scan(
        scanner=scan_nf,
        fixture=data_jpg,
        expected=test_event,
    )


def test_scan_nf_jpg_embed_rar(
    scan_nf: Scanner,
    data_embed_rar_jpg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "percentage": 0.0007500390456161762,
            "threshold": 0.25,
            "noise_floor": True,
        },
    )
    run_test_scan(
        scanner=scan_nf,
        fixture=data_embed_rar_jpg,
        expected=test_event,
    )


def test_scan_nf_png(
    scan_nf: Scanner,
    data_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "percentage": 0.0,
            "threshold": 0.25,
            "noise_floor": True,
        },
    )
    run_test_scan(
        scanner=scan_nf,
        fixture=data_png,
        expected=test_event,
    )


def test_scan_nf_png_embed_rar(
    scan_nf: Scanner,
    data_embed_rar_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "percentage": 0.0,
            "threshold": 0.25,
            "noise_floor": True,
        },
    )
    run_test_scan(
        scanner=scan_nf,
        fixture=data_embed_rar_png,
        expected=test_event,
    )
