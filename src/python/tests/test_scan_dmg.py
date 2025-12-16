from strelka.testing import (
    File,
    Scanner,
    fixtures,
    make_event,
    run_test_scan,
    make_child,
    parse_timestamp,
)


scan_dmg = fixtures.scanners.dmg
data_dmg = fixtures.data("test.dmg")
data_readonly_dmg = fixtures.data("test_readonly.dmg")
data_readwrite_dmg = fixtures.data("test_readwrite.dmg")


def test_scan_dmg_compressed(
    scan_dmg: Scanner,
    data_dmg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "897a9d9b-2f57-5034-b806-0aab345ffd0f",
                path="Install",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 20:38:37Z"),
                type="directory",
            ),
            make_child(
                "d66b90d0-4a28-50da-b262-ca47a8c411d4",
                path="Install/Install Flash Player",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 20:37:45Z"),
                type="directory",
            ),
            make_child(
                "fedac2c4-7968-5412-9477-d506042930ce",
                path="Install/[HFS+ Private Data]",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 20:18:51Z"),
                type="directory",
            ),
            make_child(
                "177c2918-e126-58a3-8a88-fb1c8bccfdba",
                path="Install/Install Flash Player/.background.png",
                sha1="bb60fb6017e1f1cc5811387a6710b20f1697b895",
                mime_type={"image/png"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=70758,
            ),
            make_child(
                "f274941c-07b3-58d0-9847-b4f12a02404c",
                path="Install/Install Flash Player/.DS_Store",
                sha1="7a33a5a7077d2d228a8c9429d614dfa48774bda4",
                mime_type={"application/octet-stream"},
                mtime=parse_timestamp("2022-12-28 16:28:49Z"),
                size=16388,
            ),
            make_child(
                "bfac4ddc-7b32-5486-b794-bcb6c918e0cd",
                path="Install/Install Flash Player/.HFS+ Private Directory Data",
                type="directory",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 16:28:47Z"),
            ),
            make_child(
                "fe5f39c0-6a45-5e44-9fe6-a15caf9bfbf9",
                path="Install/Install Flash Player/.VolumeIcon.icns",
                sha1="a24e99835ae9aaf042ff78370f10ba4f38ed1e59",
                mime_type={"image/x-icns"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=312349,
            ),
            make_child(
                "c9812ebd-a06f-5232-8cee-02156f810b47",
                path="Install/Install Flash Player/[HFS+ Private Data]",
                type="directory",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 16:28:47Z"),
            ),
            make_child(
                "07c2f538-429c-5f5f-9cfe-88ee24a3d729",
                path="Install/Install Flash Player/Install Flash Player",
                sha1="ee9cb164e89687d5a0e041bd3097d4f767f4eca3",
                mime_type={"application/x-mach-binary"},
                mtime=parse_timestamp("2022-12-28 20:31:11Z"),
                size=33016,
            ),
            make_child(
                "ac55bb60-2ca6-500b-9c27-798c5e1f2602",
                path="Install/Install Flash Player/Install Flash Player_rsrc",
                sha1="a5890a03de6b2e48ee813ecb90e7040692bbbbdb",
                mime_type={"application/x-apple-rsr"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=51737,
            ),
        ],
        scan={
            "total": {
                "directories": 5,
                "files": 5,
                "extracted": 5,
            },
            "hidden_dirs": [],
            "meta": {
                "7zip_version": "24.09",
                "partitions": [
                    {
                        "path": ...,
                        "type": "HFS",
                        "created": parse_timestamp("2022-12-29 03:18:31Z"),
                    }
                ],
            },
        },
    )
    run_test_scan(
        scanner=scan_dmg,
        fixture=data_dmg,
        expected=test_event,
    )


def test_scan_dmg_readonly(
    scan_dmg: Scanner,
    data_readonly_dmg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "fff5ee44-6466-5b63-b4cb-54647c1f0520",
                path="Install Flash Player",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 20:37:45Z"),
                type="directory",
            ),
            make_child(
                "99090ee2-2521-5049-aa0b-d02462def0ed",
                path="Install Flash Player/.DS_Store",
                sha1="7a33a5a7077d2d228a8c9429d614dfa48774bda4",
                mime_type={"application/octet-stream"},
                mtime=parse_timestamp("2022-12-28 16:28:49Z"),
                size=16388,
            ),
            make_child(
                "749308c9-79a5-58b0-a637-0a2989c7f8e3",
                path="Install Flash Player/Install Flash Player:rsrc",
                sha1="a5890a03de6b2e48ee813ecb90e7040692bbbbdb",
                mime_type={"application/x-apple-rsr"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=51737,
            ),
            make_child(
                "c1b50df6-fa26-5340-9101-e8ec0822faff",
                path="Install Flash Player/Install Flash Player",
                sha1="ee9cb164e89687d5a0e041bd3097d4f767f4eca3",
                mime_type={"application/x-mach-binary"},
                mtime=parse_timestamp("2022-12-28 20:31:11Z"),
                size=33016,
            ),
            make_child(
                "16d0e92f-0b3e-532a-80ce-5bdb67973b2e",
                path="Install Flash Player/.VolumeIcon.icns",
                sha1="a24e99835ae9aaf042ff78370f10ba4f38ed1e59",
                mime_type={"image/x-icns"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=312349,
            ),
            make_child(
                "3bae9de6-0101-5ff2-9995-6e9dc42af64d",
                path="Install Flash Player/.HFS+ Private Directory Data",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 16:28:47Z"),
                type="directory",
            ),
            make_child(
                "1f13b8d5-c840-5fc0-8f9d-6e42d9682b92",
                path="Install Flash Player/.background.png",
                sha1="bb60fb6017e1f1cc5811387a6710b20f1697b895",
                mime_type={"image/png"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=70758,
            ),
            make_child(
                "d738b6fb-8826-5995-b2fd-87d9254e2780",
                path="Install Flash Player/[HFS+ Private Data]",
                attributes=["directory"],
                mtime="2022-12-28T16:28:47+00:00",
                type="directory",
            ),
        ],
        scan={
            "total": {
                "directories": 3,
                "files": 5,
                "extracted": 5,
            },
            "hidden_dirs": [],
            "meta": {
                "7zip_version": "24.09",
                "partitions": [
                    {
                        "path": ...,
                        "type": "Dmg",
                    },
                    {
                        "path": "4.apfs",
                    },
                    {
                        "path": "4.apfs",
                        "type": "APFS",
                        "created": parse_timestamp("2022-12-29 21:14:51.740808Z"),
                    },
                ],
            },
        },
    )
    run_test_scan(
        scanner=scan_dmg,
        fixture=data_readonly_dmg,
        expected=test_event,
    )


def test_scan_dmg_readwrite(
    scan_dmg: Scanner,
    data_readwrite_dmg: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        files=[
            make_child(
                "747bb113-b99c-566e-8ddb-a768981fa57b",
                path=".DS_Store",
                sha1="2431f70d64258fe04912d8db87fafe0b4860abd0",
                mime_type={"application/octet-stream"},
                mtime=parse_timestamp("2022-12-29 21:02:01Z"),
                size=6148,
            ),
            make_child(
                "ec42d642-b3d0-5b97-8ac4-642e7224f712",
                path="Install Flash Player",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 20:37:45Z"),
                type="directory",
            ),
            make_child(
                "64cba8d8-5b7e-592f-b638-0b455bb0ccd4",
                path=".fseventsd",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-29 21:02:13Z"),
                type="directory",
            ),
            make_child(
                "21d170d1-5dc8-5fbc-a559-de09a91eb2a7",
                path="Install Flash Player/.DS_Store",
                sha1="7a33a5a7077d2d228a8c9429d614dfa48774bda4",
                mime_type={"application/octet-stream"},
                mtime=parse_timestamp("2022-12-28 16:28:49Z"),
                size=16388,
            ),
            make_child(
                "513bf1fa-6940-5125-9d48-edb123399904",
                path="Install Flash Player/Install Flash Player:rsrc",
                sha1="a5890a03de6b2e48ee813ecb90e7040692bbbbdb",
                mime_type={"application/x-apple-rsr"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=51737,
            ),
            make_child(
                "98fd6cc3-93b3-5162-8905-77a4839d8ff6",
                path="Install Flash Player/Install Flash Player",
                sha1="ee9cb164e89687d5a0e041bd3097d4f767f4eca3",
                mime_type={"application/x-mach-binary"},
                mtime=parse_timestamp("2022-12-28 20:31:11Z"),
                size=33016,
            ),
            make_child(
                "23d19e2e-a3b7-5b85-9491-fef406d2089c",
                path="Install Flash Player/.VolumeIcon.icns",
                sha1="a24e99835ae9aaf042ff78370f10ba4f38ed1e59",
                mime_type={"image/x-icns"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=312349,
            ),
            make_child(
                "d10ceb72-e8a4-5e87-9c03-d1de4deaaafe",
                path="Install Flash Player/.HFS+ Private Directory Data",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 16:28:47Z"),
                type="directory",
            ),
            make_child(
                "53ffe8ea-64e6-5355-85d6-b1f883ad36b9",
                path="Install Flash Player/.background.png",
                sha1="bb60fb6017e1f1cc5811387a6710b20f1697b895",
                mime_type={"image/png"},
                mtime=parse_timestamp("2022-12-28 16:28:45Z"),
                size=70758,
            ),
            make_child(
                "eb25d951-0dea-58e6-ab3e-dffe17623c7f",
                path="Install Flash Player/[HFS+ Private Data]",
                attributes={"directory"},
                mtime=parse_timestamp("2022-12-28 16:28:47Z"),
                type="directory",
            ),
            make_child(
                "83592ba3-b157-59d0-a40b-b8b3a7fb080f",
                path=".fseventsd/fseventsd-uuid",
                sha1="9be3a3d02c1b667d878ec5d88b28ef784d12c319",
                mime_type={"text/plain"},
                mtime=parse_timestamp("2022-12-29 21:02:13Z"),
                size=36,
            ),
            make_child(
                "6ac34722-34ac-5ba0-a163-ff35c8e49437",
                path=".fseventsd/0000000014ccc548",
                sha1="f5160f9fd03d7020634035ff20d9ea3bc65251b1",
                mime_type={"application/gzip"},
                mtime=parse_timestamp("2022-12-29 21:02:13Z"),
                size=69,
            ),
            make_child(
                "dc8df4be-1bfa-50f3-bec0-597c89e06df0",
                path=".fseventsd/0000000014ccc549",
                sha1="9e8d6dd06209bbe487f8001168133bd841f41a47",
                mime_type={"application/gzip"},
                mtime=parse_timestamp("2022-12-29 21:02:13Z"),
                size=72,
            ),
        ],
        scan={
            "total": {
                "directories": 4,
                "files": 9,
                "extracted": 9,
            },
            "hidden_dirs": [],
            "meta": {
                "7zip_version": "24.09",
                "partitions": [
                    {
                        "path": ...,
                        "type": "GPT",
                    },
                    {
                        "path": "0.disk image.apfs",
                        "file_system": "APFS",
                    },
                    {
                        "path": "0.disk image.apfs",
                        "type": "APFS",
                        "created": ...,
                    },
                ],
            },
        },
    )
    run_test_scan(
        scanner=scan_dmg,
        fixture=data_readwrite_dmg,
        expected=test_event,
    )
