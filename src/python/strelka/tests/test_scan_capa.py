from strelka.tests import (
    File,
    Scanner,
    fixtures,
    make_event,
    make_rule,
    run_test_scan,
)


def make_capa_rule(name: str, **kw) -> dict:
    return {
        name: {
            "matches": ...,
            "meta": {
                "name": name,
                "attack": ...,
                "authors": ...,
                "description": ...,
                "examples": ...,
                "is_subscope_rule": ...,
                "lib": ...,
                "maec": ...,
                "mbc": ...,
                "references": ...,
                "scopes": ...,
                **kw,
            },
            "source": ...,
        },
    }


scan_capa = fixtures.scanners.capa
data_exe = fixtures.data("test.exe")
data_elf = fixtures.data("test.elf")
data_upx_exe = fixtures.data("test_upx.exe")
data_png = fixtures.data("test.png")


def test_scan_capa_pe(
    scan_capa: Scanner,
    data_exe: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        rules=[
            make_rule(
                name="manipulate console buffer",
                category="host-interaction/console",
                techniques=[
                    "Operating System::Console [C0033]",
                ],
                author=...,
                reference=...,
            ),
            make_rule(
                name="compiled to the .NET platform",
                category="runtime/dotnet",
                author=...,
            ),
            make_rule(
                name="(internal) .NET file limitation",
                category="internal/limitation/dynamic",
                author=...,
                description=...,
            ),
            make_rule(
                name="contains PDB path",
                category="executable/pe/pdb",
                author=...,
            ),
        ],
        scan={
            "meta": {
                "analysis": {
                    "arch": "amd64",
                    "format": "dotnet",
                    "os": "any",
                    "base_address": ...,
                    "extractor": ...,
                    "feature_counts": ...,
                    "layout": ...,
                    "library_functions": ...,
                },
                "flavor": "static",
                "sample": {
                    "md5": "f58ebb5ce3e07a9dfc6dcca556b58291",
                    "sha1": ...,
                    "sha256": ...,
                },
                "version": ...,
            },
            "rules": {
                **make_capa_rule(
                    "(internal) .NET file limitation",
                    namespace="internal/limitation/dynamic",
                ),
                **make_capa_rule(
                    "compiled to the .NET platform",
                    namespace="runtime/dotnet",
                ),
                **make_capa_rule(
                    "contains PDB path",
                    namespace="executable/pe/pdb",
                ),
                **make_capa_rule(
                    "manipulate console buffer",
                    namespace="host-interaction/console",
                ),
            },
        },
    )
    run_test_scan(
        scanner=scan_capa,
        fixture=data_exe,
        expected=test_event,
    )


def test_scan_capa_elf(
    scan_capa: Scanner,
    data_elf: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        scan={
            "meta": {
                "analysis": {
                    "arch": "amd64",
                    "format": "elf",
                    "os": "linux",
                    "base_address": ...,
                    "extractor": ...,
                    "feature_counts": ...,
                    "layout": ...,
                    "library_functions": ...,
                },
                "flavor": "static",
                "sample": {
                    "md5": "bcca4f368cf9554aba7759036589db90",
                    "sha1": ...,
                    "sha256": ...,
                },
                "version": ...,
            },
            "rules": {},
        },
    )
    run_test_scan(
        scanner=scan_capa,
        fixture=data_elf,
        expected=test_event,
    )


def test_scan_capa_upx_exe(
    scan_capa: Scanner,
    data_upx_exe: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        rules=[
            make_rule(
                name="link function at runtime on Windows",
                category="linking/runtime-linking",
                techniques=[
                    "Execution::Shared Modules [T1129]",
                ],
                author=...,
            ),
            make_rule(
                name="change memory protection",
                techniques=[
                    "Memory::Change Memory Protection [C0008]",
                ],
                author=...,
            ),
            make_rule(
                name="allocate or change RW memory",
                techniques=[
                    "Memory::Allocate Memory [C0007]",
                ],
                author=...,
            ),
            make_rule(
                name="contain loop",
                author=...,
            ),
            make_rule(
                name="terminate process",
                category="host-interaction/process/terminate",
                techniques=[
                    "Process::Terminate Process [C0018]",
                ],
                author=...,
            ),
            make_rule(
                name="packed with UPX",
                category="anti-analysis/packer/upx",
                techniques=[
                    "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]",
                    "Anti-Static Analysis::Software Packing::UPX [F0001.008]",
                ],
                author=...,
            ),
            make_rule(
                name="(internal) packer file limitation",
                category="internal/limitation/static",
                author=...,
                description=...,
            ),
        ],
        scan={
            "meta": {
                "analysis": {
                    "arch": "amd64",
                    "format": "pe",
                    "os": "windows",
                    "base_address": ...,
                    "extractor": ...,
                    "feature_counts": ...,
                    "layout": ...,
                    "library_functions": ...,
                },
                "flavor": "static",
                "sample": {
                    "md5": "5a8c702ff1afa54d4fd9a658b6bbd5f4",
                    "sha1": ...,
                    "sha256": ...,
                },
                "version": ...,
            },
            "rules": {
                **make_capa_rule(
                    "(internal) packer file limitation",
                    namespace="internal/limitation/static",
                ),
                **make_capa_rule(
                    "allocate or change RW memory",
                ),
                **make_capa_rule(
                    "change memory protection",
                ),
                **make_capa_rule(
                    "contain loop",
                ),
                **make_capa_rule(
                    "link function at runtime on Windows",
                    namespace="linking/runtime-linking",
                ),
                **make_capa_rule(
                    "packed with UPX",
                    namespace="anti-analysis/packer/upx",
                ),
                **make_capa_rule(
                    "terminate process",
                    namespace="host-interaction/process/terminate",
                ),
            },
        },
    )
    run_test_scan(
        scanner=scan_capa,
        fixture=data_upx_exe,
        expected=test_event,
    )


def test_scan_capa_invalid_format(
    scan_capa: Scanner,
    data_png: File,
) -> None:
    """
    Pass:   Sample event matches output of scanner.
    Fail:   Sample event fails to match.
    """
    test_event = make_event(
        flags={
            "capa:unsupported_executable_format",
        },
    )
    run_test_scan(
        scanner=scan_capa,
        fixture=data_png,
        expected=test_event,
    )
