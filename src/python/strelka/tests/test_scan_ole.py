from strelka.tests import File, Scanner, fixtures, make_event, run_test_scan, make_child


scan_ole = fixtures.scanners.ole
data_doc = fixtures.data("test.doc")
data_classic_doc = fixtures.data("test_classic.doc")
data_pe_object_doc = fixtures.data("test_pe_object.doc")
data_pe_object_classic_doc = fixtures.data("test_pe_object_classic.doc")


def test_scan_ole_doc(
    scan_ole: Scanner,
    data_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "1b9b5864-af47-5935-9aca-941d87278eee",
                sha1="a6a0374bc10bb87a3c8b95c5cf3fe05fe1d93ab2",
                metadata={"ole:raw_stream_id": ["\x01CompObj"]},
                mime_type=["application/octet-stream"],
                path="CompObj",
                size=114,
            ),
            make_child(
                "80c40115-8e87-5231-a6bf-a6f084e1efae",
                sha1="2ac3adc36725d375e7eb2fe9f4bdc1c3cfbd946d",
                metadata={"ole:raw_stream_id": ["\x05DocumentSummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="DocumentSummaryInformation",
                size=4096,
            ),
            make_child(
                "c8ede1fb-398b-5bc1-a0f9-a68cd4e16a6e",
                sha1="3c384b079038817bb8f640044862dd267f4597bf",
                metadata={"ole:raw_stream_id": ["\x05SummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="SummaryInformation",
                size=4096,
            ),
            make_child(
                "4bbc4ef6-1c5f-56b2-9ef9-94e8bbed8092",
                sha1="5ca61114bc7c4a4625b8dab8e8214fc9e88097a1",
                metadata={"ole:raw_stream_id": ["1Table"]},
                mime_type=["application/octet-stream"],
                path="1Table",
                size=11562,
            ),
            make_child(
                "71cca37e-cd32-54e8-8520-72faf027db33",
                sha1="84ef217543666b1ddf44eaf2dadd11f51ab73d50",
                metadata={"ole:raw_stream_id": ["Data"]},
                mime_type=["application/octet-stream"],
                path="Data",
                size=21275,
            ),
            make_child(
                "eed897c5-7c2d-512d-8df8-5a5b1fdc7624",
                sha1="1ae1f8e26fbc4df825c3b4c2b015b34684024e3d",
                metadata={"ole:raw_stream_id": ["WordDocument"]},
                mime_type=["application/octet-stream"],
                path="WordDocument",
                size=6196,
            ),
        ],
        scan={
            "total": {
                "streams": 6,
                "extracted": 6,
            },
        },
    )
    run_test_scan(
        scanner=scan_ole,
        fixture=data_doc,
        expected=test_event,
    )


def test_scan_ole_doc_classic(
    scan_ole: Scanner,
    data_classic_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "1b9b5864-af47-5935-9aca-941d87278eee",
                sha1="6b77c883318dfd0ad6183f0861ca0d239a410351",
                metadata={"ole:raw_stream_id": ["\x01CompObj"]},
                mime_type=["application/octet-stream"],
                path="CompObj",
                size=106,
            ),
            make_child(
                "6231c215-0d3c-5303-87c1-c2436bbac14b",
                sha1="d3d1cde9eb43ed4b77d197af879f5ca8b8837577",
                metadata={"ole:raw_stream_id": ["\x01Ole"]},
                mime_type=["application/octet-stream"],
                path="Ole",
                size=20,
            ),
            make_child(
                "80c40115-8e87-5231-a6bf-a6f084e1efae",
                sha1="3662aa81d1a5b942b8d9efc565fa7d287e64d302",
                metadata={"ole:raw_stream_id": ["\x05DocumentSummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="DocumentSummaryInformation",
                size=116,
            ),
            make_child(
                "c8ede1fb-398b-5bc1-a0f9-a68cd4e16a6e",
                sha1="0b85370de6267efe855fcf853c02b4cc44f60068",
                metadata={"ole:raw_stream_id": ["\x05SummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="SummaryInformation",
                size=256,
            ),
            make_child(
                "4bbc4ef6-1c5f-56b2-9ef9-94e8bbed8092",
                sha1="49194616bbf0c2da5a49eb0fd6f3bd2d61892174",
                metadata={"ole:raw_stream_id": ["1Table"]},
                mime_type=["application/octet-stream"],
                path="1Table",
                size=3115,
            ),
            make_child(
                "71cca37e-cd32-54e8-8520-72faf027db33",
                sha1="699dd0f14734afb6e0c8376d222d84e0d15695f5",
                metadata={"ole:raw_stream_id": ["Data"]},
                mime_type=["application/octet-stream"],
                path="Data",
                size=21289,
            ),
            make_child(
                "eed897c5-7c2d-512d-8df8-5a5b1fdc7624",
                sha1="3fa475261f4df0ebe86fea8a6f04b50b576a0a81",
                metadata={"ole:raw_stream_id": ["WordDocument"]},
                mime_type=["application/octet-stream"],
                path="WordDocument",
                size=9277,
            ),
        ],
        scan={
            "total": {
                "streams": 7,
                "extracted": 7,
            },
        },
    )
    run_test_scan(
        scanner=scan_ole,
        fixture=data_classic_doc,
        expected=test_event,
    )


def test_scan_ole_doc_pe(
    scan_ole: Scanner,
    data_pe_object_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "1b9b5864-af47-5935-9aca-941d87278eee",
                sha1="a6a0374bc10bb87a3c8b95c5cf3fe05fe1d93ab2",
                metadata={"ole:raw_stream_id": ["\x01CompObj"]},
                mime_type=["application/octet-stream"],
                path="CompObj",
                size=114,
            ),
            make_child(
                "80c40115-8e87-5231-a6bf-a6f084e1efae",
                sha1="2864d8d731108d15fdd67da47eebdcf6c2407b84",
                metadata={"ole:raw_stream_id": ["\x05DocumentSummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="DocumentSummaryInformation",
                size=296,
            ),
            make_child(
                "c8ede1fb-398b-5bc1-a0f9-a68cd4e16a6e",
                sha1="4aec7d778bd5e133b0fe4bb13168d553fff27fd4",
                metadata={"ole:raw_stream_id": ["\x05SummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="SummaryInformation",
                size=420,
            ),
            make_child(
                "4bbc4ef6-1c5f-56b2-9ef9-94e8bbed8092",
                sha1="2cd586cfd3abfbeeb6ab991ed264ca293ec61877",
                metadata={"ole:raw_stream_id": ["1Table"]},
                mime_type=["application/octet-stream"],
                path="1Table",
                size=11580,
            ),
            make_child(
                "71cca37e-cd32-54e8-8520-72faf027db33",
                sha1="3fcee513ad357d8e9d87616c5ee6c4575a94f202",
                metadata={"ole:raw_stream_id": ["Data"]},
                mime_type=["application/octet-stream"],
                path="Data",
                size=23985,
            ),
            make_child(
                "b68ca255-9818-558e-9c98-ab2b292ce03f",
                sha1="77508c20aecddbe406c06113995bb30cb83f98df",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_1735466229", "\x01CompObj"]
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__1735466229_CompObj",
                size=76,
            ),
            make_child(
                "8bbb483b-3631-58e3-982a-5d5c375521c2",
                sha1="9cdb607292a03ff1b536effc88342c1ecca30c4a",
                metadata={
                    "ole:raw_stream_id": [
                        "ObjectPool",
                        "_1735466229",
                        "\x01Ole10Native",
                    ]
                },
                mime_type=["application/vnd.microsoft.portable-executable"],
                path="ObjectPool__1735466229_Ole10Native/test.exe",
                size=12288,
            ),
            make_child(
                "a5dcae15-965d-5fd8-8821-0b31ae6f9a91",
                sha1="1f11b6e48f5fd394b488975157746fedd2be79a5",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_1735466229", "\x03EPRINT"]
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__1735466229_EPRINT",
                size=4980,
            ),
            make_child(
                "df3017d4-97ba-5cbf-af1c-218c54eecdba",
                sha1="fa3b201a6325b85b5b36ad5e07f5242d34cffd76",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_1735466229", "\x03ObjInfo"]
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__1735466229_ObjInfo",
                size=6,
            ),
            make_child(
                "eed897c5-7c2d-512d-8df8-5a5b1fdc7624",
                sha1="55bddc155cb58f0037bfd12b4ff0d12c138eb55a",
                metadata={"ole:raw_stream_id": ["WordDocument"]},
                mime_type=["application/octet-stream"],
                path="WordDocument",
                size=6196,
            ),
        ],
        scan={
            "total": {
                "streams": 10,
                "extracted": 10,
            },
        },
    )
    run_test_scan(
        scanner=scan_ole,
        fixture=data_pe_object_doc,
        expected=test_event,
    )


def test_scan_ole_doc_pe_classic(
    scan_ole: Scanner,
    data_pe_object_classic_doc: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "1b9b5864-af47-5935-9aca-941d87278eee",
                sha1="6b77c883318dfd0ad6183f0861ca0d239a410351",
                metadata={"ole:raw_stream_id": ["\x01CompObj"]},
                mime_type=["application/octet-stream"],
                path="CompObj",
                size=106,
            ),
            make_child(
                "6231c215-0d3c-5303-87c1-c2436bbac14b",
                sha1="d3d1cde9eb43ed4b77d197af879f5ca8b8837577",
                metadata={"ole:raw_stream_id": ["\x01Ole"]},
                mime_type=["application/octet-stream"],
                path="Ole",
                size=20,
            ),
            make_child(
                "80c40115-8e87-5231-a6bf-a6f084e1efae",
                sha1="3662aa81d1a5b942b8d9efc565fa7d287e64d302",
                metadata={"ole:raw_stream_id": ["\x05DocumentSummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="DocumentSummaryInformation",
                size=116,
            ),
            make_child(
                "c8ede1fb-398b-5bc1-a0f9-a68cd4e16a6e",
                sha1="f7755c1fdb05c6bc84f1c07e37924d90702c9cca",
                metadata={"ole:raw_stream_id": ["\x05SummaryInformation"]},
                mime_type=["application/octet-stream"],
                path="SummaryInformation",
                size=256,
            ),
            make_child(
                "4bbc4ef6-1c5f-56b2-9ef9-94e8bbed8092",
                sha1="1909bab05feb875b91e1876eb342b47a5d789bdf",
                metadata={"ole:raw_stream_id": ["1Table"]},
                mime_type=["application/octet-stream"],
                path="1Table",
                size=3137,
            ),
            make_child(
                "71cca37e-cd32-54e8-8520-72faf027db33",
                sha1="f05903c1870c7d59bf42f272dcdc4e66bef5874d",
                metadata={"ole:raw_stream_id": ["Data"]},
                mime_type=["application/octet-stream"],
                path="Data",
                size=23973,
            ),
            make_child(
                "92fcac26-d79e-5f83-b4e6-02fe5e99f778",
                sha1="77508c20aecddbe406c06113995bb30cb83f98df",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_2147483647", "\x01CompObj"],
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__2147483647_CompObj",
                size=76,
            ),
            make_child(
                "e725c5b3-375f-55d7-9fda-c0747b54f61d",
                sha1="9cdb607292a03ff1b536effc88342c1ecca30c4a",
                metadata={
                    "ole:raw_stream_id": [
                        "ObjectPool",
                        "_2147483647",
                        "\x01Ole10Native",
                    ],
                },
                mime_type=["application/vnd.microsoft.portable-executable"],
                path="ObjectPool__2147483647_Ole10Native/test.exe",
                size=12288,
            ),
            make_child(
                "4fa79811-2165-5a20-b854-06ba3c9be392",
                sha1="1f11b6e48f5fd394b488975157746fedd2be79a5",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_2147483647", "\x03EPRINT"],
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__2147483647_EPRINT",
                size=4980,
            ),
            make_child(
                "acf0b8dd-e8e9-50dd-a8d7-6230ab4c2a69",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_2147483647", "\x03OCXNAME"],
                },
                mime_type=["application/x-empty"],
                path="ObjectPool__2147483647_OCXNAME",
                size=0,
            ),
            make_child(
                "d83dac69-7ef2-5d2b-86ab-2c49d10d509e",
                sha1="fa3b201a6325b85b5b36ad5e07f5242d34cffd76",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_2147483647", "\x03ObjInfo"],
                },
                mime_type=["application/octet-stream"],
                path="ObjectPool__2147483647_ObjInfo",
                size=6,
            ),
            make_child(
                "c6e6c398-53c2-5df0-9b6b-46ba17e26ec4",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                metadata={
                    "ole:raw_stream_id": ["ObjectPool", "_2147483647", "contents"],
                },
                mime_type=["application/x-empty"],
                path="ObjectPool__2147483647_contents",
                size=0,
            ),
            make_child(
                "eed897c5-7c2d-512d-8df8-5a5b1fdc7624",
                sha1="cffd803fe7f512471ce0ffa8368f2de02fe52cd7",
                metadata={"ole:raw_stream_id": ["WordDocument"]},
                mime_type=["application/octet-stream"],
                path="WordDocument",
                size=9277,
            ),
        ],
        scan={
            "total": {
                "streams": 13,
                "extracted": 13,
            },
        },
    )
    run_test_scan(
        scanner=scan_ole,
        fixture=data_pe_object_classic_doc,
        expected=test_event,
    )
