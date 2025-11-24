from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_child,
    make_event,
    parse_timestamp,
    run_test_scan,
)


scan_msi = fixtures.scanners.msi
data_msi = fixtures.data("test.msi")


def test_scan_msi(
    scan_msi: Scanner,
    data_msi: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "10d8a2e3-2c8e-5561-b2c5-d75b4ea35ce4",
                name="lorem.txt",
                sha1="26cfc9e1782a7f4471e75b3ab4bf9b974ceafb4a",
                mtime="2022-12-12T11:12:56+00:00",
                size=4015,
                mime_type={"application/octet-stream"},
            ),
            make_child(
                "f59efc79-8876-5766-903d-31940263daa0",
                name="loremhidden.txt",
                sha1="26cfc9e1782a7f4471e75b3ab4bf9b974ceafb4a",
                mtime="2022-12-12T11:12:56+00:00",
                size=4015,
                mime_type={"application/octet-stream"},
            ),
            make_child(
                "b74977f3-b2e8-588f-b6e4-96d98ce92db4",
                name="loremreadonly.txt",
                sha1="26cfc9e1782a7f4471e75b3ab4bf9b974ceafb4a",
                mtime="2022-12-12T11:12:56+00:00",
                size=4015,
                mime_type={"application/octet-stream"},
            ),
        ],
        scan={
            "totals": {
                "cab_files": 3,
                "components": 3,
                "directories": 4,
                "extracted": 3,
                "files": 3,
                "icons": 0,
                "media": 1,
                "registry_keys": 0,
                "shortcuts": 0,
            },
            "cab_files": [
                {
                    "attributes": ["Arch"],
                    "child_id": "10d8a2e3-2c8e-5561-b2c5-d75b4ea35ce4",
                    "codec": "latin1",
                    "name": "lorem.txt",
                    "size": 4015,
                    "media": 1,
                    "timestamp": parse_timestamp("2022-12-12 11:12:56Z"),
                },
                {
                    "attributes": ["Arch"],
                    "child_id": "f59efc79-8876-5766-903d-31940263daa0",
                    "codec": "latin1",
                    "name": "loremhidden.txt",
                    "size": 4015,
                    "media": 1,
                    "timestamp": parse_timestamp("2022-12-12 11:12:56Z"),
                },
                {
                    "attributes": ["Arch", "ReadOnly"],
                    "child_id": "b74977f3-b2e8-588f-b6e4-96d98ce92db4",
                    "codec": "latin1",
                    "name": "loremreadonly.txt",
                    "size": 4015,
                    "media": 1,
                    "timestamp": parse_timestamp("2022-12-12 11:12:56Z"),
                },
            ],
            "components": [
                {
                    "attributes": [],
                    "condition": None,
                    "guid": "4d0955c7-034f-4b8d-86db-5ad273c12e77",
                    "id": "LoremHiddenTxt",
                    "key_path": "loremhidden.txt",
                    "path": "/SourceDir/MSIStrelkaTests/hidden",
                },
                {
                    "attributes": [],
                    "condition": None,
                    "guid": "5d0955c7-034f-4b8d-86db-5ad273c12e77",
                    "id": "LoremReadOnlyTxt",
                    "key_path": "loremreadonly.txt",
                    "path": "/SourceDir/MSIStrelkaTests/hidden",
                },
                {
                    "attributes": [],
                    "condition": None,
                    "guid": "7d0955c7-034f-4b8d-86db-5ad273c12e77",
                    "id": "LoremHidden",
                    "key_path": "lorem.txt",
                    "path": "/SourceDir/MSIStrelkaTests",
                },
            ],
            "directories": [
                {
                    "id": "HiddenFolder",
                    "path": "/SourceDir/MSIStrelkaTests/hidden",
                },
                {
                    "id": "INSTALLFOLDER",
                    "path": "/SourceDir/MSIStrelkaTests",
                },
                {
                    "id": "ProgramFilesFolder",
                    "path": "/SourceDir",
                },
                {
                    "id": "TARGETDIR",
                    "path": "/SourceDir",
                },
            ],
            "files": [
                {
                    "attributes": ["hidden", "vital"],
                    "component": "LoremHiddenTxt",
                    "id": "loremhidden.txt",
                    "languages": [],
                    "path": "/SourceDir/MSIStrelkaTests/hidden/lorem-hidden.txt",
                    "sequence": 2,
                    "size": 4015,
                    "version": None,
                },
                {
                    "attributes": ["read_only", "vital"],
                    "component": "LoremReadOnlyTxt",
                    "id": "loremreadonly.txt",
                    "languages": [],
                    "path": "/SourceDir/MSIStrelkaTests/hidden/lorem-readonly.txt",
                    "sequence": 3,
                    "size": 4015,
                    "version": None,
                },
                {
                    "attributes": ["hidden", "vital"],
                    "component": "LoremHidden",
                    "id": "lorem.txt",
                    "languages": [],
                    "path": "/SourceDir/MSIStrelkaTests/lorem.txt",
                    "sequence": 1,
                    "size": 4015,
                    "version": None,
                },
            ],
            "icons": [],
            "media": [
                {
                    "disk_prompt": None,
                    "id": 1,
                    "last_sequence": 3,
                    "source": None,
                    "volume_label": None,
                },
            ],
            "registry_keys": [],
            "shortcuts": [],
            "summary": {
                "arch": "Intel",
                "author": "Target",
                "comments": (
                    "This installer database contains the logic and data required to "
                    "install StrelkaMSITest."
                ),
                "creating_application": "Windows Installer XML Toolset (3.11.2.4516)",
                "creation_time": parse_timestamp("2023-08-07 11:59:38Z"),
                "languages": ["en_US"],
                "security": "readonly_enforced",
                "subject": "StrelkaMSITest",
                "title": "Installation Database",
                "uuid": "3f5d9ff7-e061-48cf-95b2-0aa7c9e5de2a",
                "word_count": 2,
            },
        },
    )
    run_test_scan(
        scanner=scan_msi,
        fixture=data_msi,
        expected=test_event,
    )
