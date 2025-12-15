from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    make_exception,
    run_test_scan,
)


scan_yara = fixtures.scanners.yara
data_txt = fixtures.data("test.txt")
helper_yara = fixtures.helpers("test.yara")
helper_bad_yara = fixtures.helpers("test_elk_linux_torte.yara")


def test_scan_yara(
    scan_yara: Scanner,
    data_txt: File,
    helper_yara: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_yara.path is not None
    test_event = make_event(
        scan={
            "matches": {"hex_extraction_test", "meta_test", "test"},
            "tags": set(),
            "categories": {},
            "meta": ...,
            "hex": [],
        },
    )
    run_test_scan(
        scanner=scan_yara,
        fixture=data_txt,
        options={
            "location": helper_yara.path,
        },
        expected=test_event,
    )


def test_scan_bad_yara(
    scan_yara: Scanner,
    data_txt: File,
    helper_bad_yara: File,
) -> None:
    """
    This test was implemented to test a more complex and unsupported rule. A bug was
    observed that was not triggered by the basic YARA test.
    Src:    https://github.com/target/strelka/issues/410
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_bad_yara.path is not None
    test_event = make_event(
        flags={
            "yara:no_rules_loaded",
            "yara:syntax_error",
        },
        exceptions=[
            make_exception(
                "yara.SyntaxError",
                f'{helper_bad_yara.path}(31): undefined identifier "is__elf"',
                flag="yara:syntax_error",
            ),
        ],
        scan={
            "matches": set(),
            "tags": set(),
            "categories": {},
            "hex": [],
            "meta": ...,
        },
    )
    run_test_scan(
        scanner=scan_yara,
        fixture=data_txt,
        options={
            "location": helper_bad_yara.path,
        },
        expected=test_event,
    )


def test_scan_yara_hex_extraction(
    scan_yara: Scanner,
    data_txt: File,
    helper_yara: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_yara.path is not None
    test_event = make_event(
        scan={
            "matches": {"hex_extraction_test", "meta_test", "test"},
            "tags": set(),
            "categories": {},
            "hex": [
                {
                    "dump": [
                        "000002ff  74 20 6d 69 20 70 72 6f 69 6e 20 73 65 64 2e 20  t mi proin sed. ",
                        "0000030f  56 65 6e 65 6e 61 74 69 73 20 74 65 6c 6c 75 73  Venenatis tellus",
                        "0000031f  20 69 6e 20 6d 65 74 75 73 20 76 75 6c 70 75 74   in metus vulput",
                        "0000032f  61 74 65 2e 20 44 69 63 74 75 6d 73 74 20 76 65  ate. Dictumst ve",
                        "0000033f  73 74 69 62 75 6c 75 6d 20 72 68 6f 6e 63 75 73  stibulum rhoncus",
                    ],
                    "rule": "hex_extraction_test",
                },
            ],
            "meta": [],
        },
    )
    run_test_scan(
        scanner=scan_yara,
        fixture=data_txt,
        options={
            "location": helper_yara.path,
            "show_all_meta": False,
            "store_offset": True,
            "offset_meta_key": "StrelkaHexDump",
            "offset_padding": 32,
        },
        expected=test_event,
    )


def test_scan_yara_meta(
    scan_yara: Scanner,
    data_txt: File,
    helper_yara: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    assert helper_yara.path is not None
    test_event = make_event(
        scan={
            "matches": {"hex_extraction_test", "meta_test", "test"},
            "tags": set(),
            "categories": {
                "collection": [],
                "detection": [
                    {
                        "name": "meta_test",
                        "ruleset": "default",
                        "author": "John Doe",
                    },
                ],
                "information": [],
            },
            "hex": [],
            "meta": [
                {
                    "identifier": "StrelkaHexDump",
                    "rule": "hex_extraction_test",
                    "value": True,
                },
                {
                    "identifier": "author",
                    "rule": "meta_test",
                    "value": "John Doe",
                },
                {
                    "identifier": "scope",
                    "rule": "meta_test",
                    "value": "detection",
                },
            ],
        },
    )
    run_test_scan(
        scanner=scan_yara,
        fixture=data_txt,
        options={
            "location": helper_yara.path,
            "category_key": "scope",
            "categories": {
                "collection": {},
                "detection": {
                    "show_meta": True,
                },
                "information": {},
            },
            "meta_fields": {
                "name": "",
                "ruleset": "",
                "author": "",
            },
            "show_all_meta": True,
        },
        expected=test_event,
    )
