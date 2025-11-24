"""
[elleste]: This module is based off of the `gifstruct.py` script from qalle2/pygif
(which is archived as of 25/06/22). It uses some of the code, but is rewritten
extensively to provide the parsed information back as structures instead of printed out.

    (c.f. original repository @ https://github.com/qalle2/pygif)
"""

from __future__ import annotations
from io import BytesIO
import struct
from typing import Annotated, Final, IO, Iterator, Self

from pydantic import Field

from ..model import Model


# for Graphic Control Extension
DISPOSAL_METHODS: Final = {
    0: "unspecified",
    1: "leave in place",
    2: "restore to background color",
    3: "restore to previous",
}


class GIF(Model, frozen=True):
    version: bytes
    lsd_info: LogicalScreenDescriptor
    blocks: list[Block]
    total_size: int

    @classmethod
    def parse(cls, image: IO[bytes] | bytes) -> Self:
        if isinstance(image, bytes):
            image = BytesIO(image)

        version = cls._read_header(image)
        lsd_info = cls._read_lsd(image)
        blocks = []
        total_size = 0

        # skip GCT if it exists
        if lsd_info.gct_flag:
            cls._get_bytes(image, 2**lsd_info.gct_size * 3)

        while True:
            match cls._get_bytes(image, 1):
                case b",":
                    image_info = cls._read_image_block(image)
                    # skip LCT if it exists
                    if image_info.lct_flag:
                        cls._get_bytes(image, 2**image_info.lct_size * 3)
                    palette_bits = cls._get_bytes(image, 1)[0]
                    data_blocks = list(cls._get_subblocks(image))
                    data_size = sum(len(d) for d in data_blocks)
                    blocks.append(
                        image_info.model_replace(
                            palette_bits=palette_bits,
                            data_size=data_size,
                            data_blocks=data_blocks,
                        )
                    )
                case b"!":
                    blocks.append(cls._read_extension_block(image))
                case b";":
                    total_size = image.tell()
                    break
                case other:
                    raise ValueError(f"unknown GIF block type: {other!r}")

        return cls(
            version=version,
            lsd_info=lsd_info,
            blocks=blocks,
            total_size=total_size,
        )

    @classmethod
    def _get_bytes(cls, handle: IO[bytes], length):
        # read bytes from file
        assert isinstance(length, int)
        data = handle.read(length)
        if len(data) < length:
            raise EOFError
        return data

    @classmethod
    def _get_subblocks(cls, handle: IO[bytes]) -> Iterator[bytes]:
        # generate data from GIF subblocks
        sbSize = cls._get_bytes(handle, 1)[0]  # subblock size
        while sbSize:
            chunk = cls._get_bytes(handle, sbSize + 1)  # subblock & size of next one
            yield chunk[:-1]
            sbSize = chunk[-1]

    @classmethod
    def _read_header(cls, handle: IO[bytes]) -> bytes:
        # read Header from current file position; return file version

        magic, version = struct.unpack("3s3s", cls._get_bytes(handle, 6))
        if magic != b"GIF":
            raise ValueError("not a GIF file")
        return version

    @classmethod
    def _read_lsd(cls, handle: IO[bytes]) -> LogicalScreenDescriptor:
        # read Logical Screen Descriptor from current file position
        width, height, packed_fields, bgIndex, aspectRatio = struct.unpack(
            "<2H3B", cls._get_bytes(handle, 7)
        )
        return LogicalScreenDescriptor(
            width=width,
            height=height,
            gct_flag=bool(packed_fields & 0b10000000),
            color_resolution=(((packed_fields >> 4) & 0b00000111) + 1),
            sort_flag=bool(packed_fields & 0b00001000),
            gct_size=((packed_fields & 0b00000111) + 1),
            bg_index=bgIndex,
            aspect_ratio=(aspectRatio and (aspectRatio + 15)),
        )

    @classmethod
    def _read_image_block(cls, handle: IO[bytes]) -> ImageDescriptorBlock:
        # read information of one image in GIF file
        # handle position must be at first byte after ',' of Image Descriptor
        x, y, width, height, packed_fields = struct.unpack(
            "<4HB", cls._get_bytes(handle, 9)
        )
        return ImageDescriptorBlock(
            x=x,
            y=y,
            width=width,
            height=height,
            lct_flag=bool(packed_fields & 0b10000000),
            interlace_flag=bool(packed_fields & 0b01000000),
            sort_flag=bool(packed_fields & 0b00100000),
            lct_size=((packed_fields & 0b00000111) + 1),
        )

    @classmethod
    def _read_extension_block(cls, handle: IO[bytes]) -> ExtensionBlock:
        # read Extension block in GIF file;
        # handle position must be at first byte after Extension Introducer ('!')
        match cls._get_bytes(handle, 1)[0]:
            case 0x01:
                # skip contents
                cls._get_bytes(handle, 13)
                list(cls._get_subblocks(handle))
                return PlainTextBlock()
            case 0xF9:
                packed_fields, delay_time, transparent_index = struct.unpack(
                    "<xBHBx", cls._get_bytes(handle, 6)
                )
                disposal = (packed_fields & 0b00011100) >> 2
                return GraphicControlBlock(
                    user_input=bool(packed_fields & 0b00000010),
                    transparent_flag=bool(packed_fields & 0b00000001),
                    delay_time=delay_time,
                    transparent_index=transparent_index,
                    disposal_method=DISPOSAL_METHODS.get(
                        disposal, f"unknown: {disposal}"
                    ),
                )
            case 0xFE:
                return CommentBlock(
                    comment=b"".join(cls._get_subblocks(handle)),
                )
            case 0xFF:
                identifier, auth_code = struct.unpack(
                    "x8s3s", cls._get_bytes(handle, 12)
                )
                # skip contents
                list(cls._get_subblocks(handle))
                return ApplicationBlock(
                    identifier=identifier,
                    auth_code=auth_code,
                )
            case other:
                # skip contents
                list(cls._get_subblocks(handle))
                return UnknownExtensionBlock(
                    type_code=other,
                )


class LogicalScreenDescriptor(Model, frozen=True):
    width: int
    height: int
    gct_flag: bool
    color_resolution: int
    sort_flag: bool
    gct_size: int
    bg_index: int
    aspect_ratio: int


class Block(Model, frozen=True):
    pass


class ImageDescriptorBlock(Block, frozen=True):
    x: int
    y: int
    width: int
    height: int
    lct_flag: bool
    interlace_flag: bool
    sort_flag: bool
    lct_size: int

    palette_bits: int = -1
    data_size: int = -1
    data_blocks: Annotated[list[bytes], Field(repr=False)] = []


class ExtensionBlock(Block, frozen=True):
    pass


class PlainTextBlock(ExtensionBlock, frozen=True):
    pass


class GraphicControlBlock(ExtensionBlock, frozen=True):
    user_input: bool
    transparent_flag: bool
    delay_time: int
    transparent_index: int
    disposal_method: str


class CommentBlock(ExtensionBlock, frozen=True):
    comment: bytes


class ApplicationBlock(ExtensionBlock, frozen=True):
    identifier: bytes
    auth_code: bytes


class UnknownExtensionBlock(ExtensionBlock, frozen=True):
    type_code: int
