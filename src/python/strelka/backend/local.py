from __future__ import annotations
import datetime
import logging

from typing_extensions import override

from . import BaseBackend
from ..config import BackendConfig
from ..model import Date, File


class LocalBackend(BaseBackend):
    __file_data: dict[str, tuple[bytes, Date]]

    def __init__(
        self,
        config: BackendConfig,
    ) -> None:
        super().__init__(config)
        self.__file_data = {}

    @override
    def retrieve_file_data(
        self,
        file: File,
    ) -> bytes | None:
        if file.pointer in self.__file_data:
            data, expire_at = self.__file_data.pop(file.pointer)
            if datetime.datetime.now(datetime.UTC) < expire_at:
                return data
            else:
                logging.warning("file data for %s has expired", file.pointer)
        else:
            logging.warning("no file data for %s", file.pointer)
        return None

    @override
    def store_file_data(
        self,
        file: File,
        data: bytes | bytearray | memoryview[int],
        expire_at: Date,
    ) -> None:
        if file.pointer in self.__file_data:
            raise KeyError(
                f"locally stored data for pointer {file.pointer} already exists"
            )
        self.__file_data[file.pointer] = (bytes(data), expire_at)
