# Authors: Ryan Borre

from construct import Bytes, Int64ul, Struct, this

FileDataStoreObject = "FileDataStoreObject" / Struct(
    "guidHeader" / Bytes(16),
    "cbLength" / Int64ul,
    "_unknown1" / Bytes(4),
    "_unknown2" / Bytes(8),
    "fileData" / Bytes(this.cbLength),
)
