from strelka.testing import File, Scanner, fixtures, make_child, make_event, run_test_scan


scan_donut = fixtures.scanners.donut
data_donut = fixtures.data("test_donut.bin")
data_donut_compressed = fixtures.data("test_donut_compressed.bin")


def test_scan_donut(
    scan_donut: Scanner,
    data_donut: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "b23144fc-8b3b-554c-9a44-5befe120c7b8",
                name=":donut-10196",
                sha1="f3530e41e1130ea0c025aa912e2fb89c4da32ad5",
                mime_type=["application/vnd.microsoft.portable-executable"],
                size=5432,
            ),
        ],
        scan={
            "total": {
                "donuts": 1,
                "files": 1,
            },
            "donuts": [
                {
                    "compression_type": "DONUT_COMPRESS_NONE",
                    "decoy_module": "",
                    "entropy_type": "DONUT_ENTROPY_DEFAULT",
                    "instance_type": "DONUT_INSTANCE_EMBED",
                    "module_type": "DONUT_MODULE_NET_DLL",
                    "instance_version": "1.0",
                    "loader_version": "1.0_64",
                    "offset_loader_start": 10196,
                    "offsets": {
                        "size_instance": 4744,
                        "encryption_start": 572,
                    },
                }
            ],
        },
    )
    run_test_scan(
        scanner=scan_donut,
        fixture=data_donut,
        expected=test_event,
    )


def test_scan_donut_compressed(
    scan_donut: Scanner,
    data_donut_compressed: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "cc04a994-2470-5b1f-9f86-54629e951f64",
                name=":donut-7913",
                sha1="67198a3ca72c49fb263f4a9749b4b79c50510155",
                mime_type=["application/vnd.microsoft.portable-executable"],
                size=4096,
            ),
        ],
        scan={
            "total": {
                "donuts": 1,
                "files": 1,
            },
            "donuts": [
                {
                    "compression_type": "DONUT_COMPRESS_APLIB",
                    "decoy_module": "",
                    "entropy_type": "DONUT_ENTROPY_DEFAULT",
                    "instance_type": "DONUT_INSTANCE_EMBED",
                    "module_type": "DONUT_MODULE_NET_DLL",
                    "instance_version": "1.0",
                    "loader_version": "1.0_64",
                    "offset_loader_start": 7913,
                    "offsets": {
                        "size_instance": 4744,
                        "encryption_start": 572,
                    },
                }
            ],
        },
    )
    run_test_scan(
        scanner=scan_donut,
        fixture=data_donut_compressed,
        expected=test_event,
    )
