import re

import olefile
import oletools
import oletools.oleobj

from . import Options, Scanner
from ..model import Date, File


class ScanOle(Scanner):
    """Extracts files from OLECF files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        ole = None
        self.event.update(
            {
                "total": {
                    "streams": 0,
                    "extracted": 0,
                },
                #"streams": [],
            }
        )

        try:
            ole = olefile.OleFileIO(data)
            ole_streams = ole.listdir(streams=True)
            self.event["total"]["streams"] = len(ole_streams)
            for stream in ole_streams:
                try:
                    ole_handle = ole.openstream(stream)
                    extract_data = ole_handle.read()
                    stream_name = "_".join(
                        s.decode(errors="ignore") if isinstance(s, bytes) else s
                        for s in stream
                    )
                    extract_name = re.sub(r"[\x00-\x1F]", "", stream_name)
                    if extract_name.endswith("Ole10Native"):
                        native_stream = oletools.oleobj.OleNativeStream(
                            bindata=extract_data,
                        )
                        filename = native_stream.filename
                        extract_data = native_stream.data
                        extract_path = f"{extract_name}/{filename or ':native_data'}"
                    else:
                        extract_path = extract_name

                    #self.event["streams"].append(
                    #    {
                    #        "raw_stream_id": stream,
                    #        "filename": filename,
                    #    }
                    #)
                    self.emit_file(
                        extract_data,
                        path=extract_path,
                        unique_key=(stream_name,),
                        metadata={
                            "ole:raw_stream_id": stream,
                        },
                    )
                    self.event["total"]["extracted"] += 1

                except AttributeError:
                    self.add_flag("attribute_error_in_stream")

        except OSError:
            self.add_flag("os_error")
        finally:
            if ole:
                ole.close()
