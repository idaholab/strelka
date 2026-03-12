from __future__ import annotations
from dataclasses import dataclass, field
import datetime
import enum
import io
from itertools import chain
import locale
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Final, Iterable, Sequence
from uuid import UUID

import pymsi
from pymsi.propset import PropertySet
from pymsi.thirdparty.refinery.cab import CabAttr

from . import Options, Scanner
from .. import model
from ..model import Date


PropertyNameAndValue = tuple[int, dict[Any, str]]


PID_SECURITY: Final[PropertyNameAndValue] = (
    19,
    {
        0: "no_restriction",
        1: "readonly_recommended",
        2: "readonly_enforced",
    },
)


class ComponentAttrs(enum.IntFlag):
    # local_only = 0x0
    source_only = 0x1
    optional = 0x2
    registry_key_path = 0x4
    shared_dll_ref_count = 0x8
    permanent = 0x10
    odbc_data_source = 0x20
    transitive = 0x40
    never_overwrite = 0x80
    arch_64bit = 0x100
    registry_reflection = 0x200
    uninstall_on_supersedence = 0x400
    shared = 0x800


class FileAttrs(enum.IntFlag):
    read_only = 0x1
    hidden = 0x2
    system = 0x4
    vital = 0x200
    checksum = 0x400
    patch_added = 0x1000
    noncompressed = 0x2000
    compressed = 0x4000


@dataclass
class Event:
    @dataclass
    class Summary:
        arch: str | None = None
        author: str | None = None
        comments: str | None = None
        creating_application: str | None = None
        creation_time: datetime.datetime | None = None
        languages: Sequence[str | int] = field(default_factory=list)
        subject: str | None = None
        title: str | None = None
        uuid: UUID | None = None
        word_count: int | None = None
        security: str | int | None = None

    @dataclass
    class CabFile:
        name: str
        attributes: CabAttr
        codec: str
        media: int
        timestamp: datetime.datetime | None
        size: int
        child_id: UUID | None

    @dataclass
    class Component:
        id: str
        path: PurePosixPath
        attributes: ComponentAttrs
        condition: str | None
        guid: UUID | None
        key_path: str | None

    @dataclass
    class Directory:
        path: PurePosixPath
        id: str

    @dataclass
    class File:
        path: PurePosixPath
        id: str
        component: str
        attributes: FileAttrs
        languages: Sequence[str | int]
        sequence: int
        size: int
        version: str | None

    @dataclass
    class Icon:
        id: str
        child_id: UUID | None

    @dataclass
    class Media:
        id: int
        last_sequence: int
        disk_prompt: str | None
        source: str | None
        volume_label: str | None

    @dataclass
    class RegistryKey:
        id: str
        component: str
        key: PureWindowsPath
        name: str | None
        value: Any

    @dataclass
    class Shortcut:
        id: str
        path: PurePosixPath
        component: str
        arguments: str | None
        description: str | None
        hotkey: str | None
        icon: str | None
        icon_index: int | None
        show_command: int | None
        target: str
        working_directory: str | None

    @dataclass
    class Totals:
        cab_files: int = 0
        components: int = 0
        directories: int = 0
        files: int = 0
        icons: int = 0
        media: int = 0
        registry_keys: int = 0
        shortcuts: int = 0
        extracted: int = 0

    totals: Totals = field(default_factory=Totals)
    summary: Summary | None = None
    cab_files: list[CabFile] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    directories: list[Directory] = field(default_factory=list)
    files: list[File] = field(default_factory=list)
    icons: list[Icon] = field(default_factory=list)
    media: list[Media] = field(default_factory=list)
    registry_keys: list[RegistryKey] = field(default_factory=list)
    shortcuts: list[Shortcut] = field(default_factory=list)


class ScanMsi(Scanner):
    """Collects metadata parsed by pymsi."""

    def scan(self, data: bytes, file: model.File, options: Options, expire_at: Date) -> Event:
        file_limit = self.evaluate_limit(options.get("limit", -1))

        event = Event()

        with io.BytesIO(data) as data_fh:
            pkg = pymsi.Package(data_fh)
            msi = pymsi.Msi(pkg, load_data=True)

            if s := msi.package.summary:
                event.summary = Event.Summary(
                    arch=s.arch(),
                    author=s.author(),
                    comments=s.comments(),
                    creating_application=s.creating_application(),
                    creation_time=(t.astimezone(datetime.UTC) if (t := s.creation_time()) else None),
                    languages=self.map_windows_locales(s.languages()),
                    subject=s.subject(),
                    title=s.title(),
                    uuid=self.parse_uuid(s.uuid()),
                    word_count=s.word_count(),
                    security=self.lookup_property(s.properties, *PID_SECURITY),
                )
                # Not including these items because they are part of the specific
                # property set header, so they're not global to the MSI file:
                #   codepage: s.properties.codepage.encoding,
                #   os_version: [s.properties.os, s.properties.os_version],
                #   clsid: UUID(bytes=s.properties.clsid),
                #   fmtid: UUID(bytes=s.properties.fmtid),

            event.components.extend(
                Event.Component(
                    id=c.id,
                    path=self.get_object_path(c.directory),
                    attributes=ComponentAttrs(c.attributes),
                    condition=c.condition,
                    guid=self.parse_uuid(c.guid),
                    key_path=c.key_path,
                )
                for c in msi.components.values()
            )
            event.totals.components += len(event.components)

            event.directories.extend(
                Event.Directory(
                    path=self.get_object_path(d),
                    id=d.id,
                )
                for d in msi.directories.values()
            )
            event.totals.directories += len(event.directories)

            event.shortcuts.extend(
                Event.Shortcut(
                    id=s.id,
                    path=self.get_object_path(s),
                    component=s.component.id,
                    arguments=s.arguments,
                    description=s.description,
                    hotkey=s.hotkey,
                    icon=(s.icon.id if s.icon else None),
                    icon_index=s.icon_index,
                    show_command=s.show_command,
                    target=s.target,
                    working_directory=s.working_directory,
                )
                for s in msi.shortcuts.values()
            )
            event.totals.shortcuts += len(event.shortcuts)

            event.registry_keys.extend(
                Event.RegistryKey(
                    id=k.id,
                    component=k.component.id,
                    key=PureWindowsPath(k.root or "?") / k.key,
                    name=k.name,
                    value=k.value,
                )
                for k in msi.registry_keys.values()
            )
            event.totals.registry_keys += len(event.registry_keys)

            event.icons.extend(
                Event.Icon(
                    id=c.id,
                    child_id=self.emit_file(
                        c.data,
                        name=f"icon:{c.id}",
                        unique_key=("icon", i),
                    ),
                )
                for i, c in enumerate(msi.icons.values())
            )
            event.totals.icons += len(event.icons)

            event.files.extend(
                Event.File(
                    path=self.get_object_path(f),
                    id=f.id,
                    component=f.component.id,
                    attributes=FileAttrs(f.attributes),
                    languages=self.map_windows_locales(f.language),
                    sequence=f.sequence,
                    size=f.size,
                    version=f.version,
                )
                for f in msi.files.values()
            )
            event.totals.files += len(event.files)

            for m in msi.medias.values():
                event.totals.media += 1
                event.media.append(
                    Event.Media(
                        id=m.id,
                        disk_prompt=m.disk_prompt,
                        last_sequence=m.last_sequence,
                        source=m.source,
                        volume_label=m.volume_label,
                    )
                )
                if c := m.cabinet:
                    for f in chain(*c.files.values()):
                        file_data = None
                        if event.totals.extracted < file_limit:
                            try:
                                file_data = f.decompress()
                            except Exception:
                                self.add_flag("cab_file_extract_failure")
                            event.totals.extracted += 1

                        event.totals.cab_files += 1
                        event.cab_files.append(
                            Event.CabFile(
                                name=f.name,
                                attributes=f.attributes,
                                codec=f.codec,
                                media=m.id,
                                timestamp=(t.astimezone(datetime.UTC) if (t := f.timestamp) else None),
                                size=f.size,
                                child_id=self.emit_file(
                                    file_data,
                                    name=f.name,
                                    unique_key=("file", m.id, f.offset),
                                    size=f.size,
                                    mtime=(t.astimezone(datetime.UTC) if (t := f.timestamp) else None),
                                ),
                            )
                        )

        return event

    @staticmethod
    def parse_uuid(value: str | None) -> UUID | None:
        if value is None:
            return None
        return UUID(value)

    @staticmethod
    def map_windows_locales(values: Iterable[int | str] | None) -> list[str | int]:
        return [
            (locale.windows_locale.get(int(e), e) if isinstance(e, int) or e.isdigit() else e) for e in (values or ())
        ]

    @staticmethod
    def lookup_property(propset: PropertySet, name: int, values: dict[Any, str]) -> Any:
        if name not in propset:
            return None
        value = propset[name]
        return values.get(value, value)

    def get_object_path(self, what: pymsi.File | pymsi.Shortcut | pymsi.Directory | None) -> PurePosixPath:
        if what is None:
            return PurePosixPath("/")
        elif isinstance(what, pymsi.Directory):
            return self.get_object_path(what.parent) / what.name
        elif isinstance(what, pymsi.File):
            return self.get_object_path(what.component.directory) / what.name
        elif isinstance(what, pymsi.Shortcut):
            return self.get_object_path(what.directory) / what.name
