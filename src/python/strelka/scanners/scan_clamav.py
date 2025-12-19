import io
import json
from pathlib import Path
import re
import subprocess
from typing import Any, ClassVar, Iterable

import clamd

from . import Options, Scanner
from ..model import Date, File
from ..util.collections import SkipItem, visit


class ScanClamav(Scanner):
    """
    This scanner runs against a given file and returns a ClamAV scan that has a
    determination if the file is infected or not based on the ClamAV signature database.

    Scanner Type: Collection

    Attributes:
        None

    ## Detection Use Cases
    !!! info "Detection Use Cases"
        - **Scan Determination**
            - This scanner provides a inital determination on a file if it is infected
              or not based on the the ClamAV signature database.

    ## Known Limitations
    !!! warning "Known Limitations"
        - **ClamAV Signature Database**
            - This scanner relies on the ClamAV signature database which is not
              necesarily all-encompassing. Though the scanner may return a
              determination, users should be advise that this is not exaustive.

    ## To Do
    !!! question "To Do"
        - The ClamAV signature database currently can be pulled every scan as a POC. This
          could be converted to a signature pull on a cadence, such as every 24 hours,
          or disabled entirely to allow for external signature management.

    ## References
    !!! quote "References"
    - [ClamAV Documentation Source](https://docs.clamav.net/Introduction.html)
    - [BlogPost on ClamAV Scanner](https://simovits.com/strelka-let-us-build-a-scanner/)

    ## Contributors
    !!! example "Contributors"
        - [Sara Kalupa](https://github.com/skalupa)

    """

    DEFAULT_PORT: ClassVar = 3310
    PORT_RE: ClassVar = re.compile(r"^([-A-Za-z0-9_.]+)(?::(\d+))?$")

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        if options.get("clamd_socket", None) is not None:
            self.scan_remote(data, file, options)
        else:
            self.scan_local(data, file, options)

    def signature_matched(self, sig: str) -> None:
        self.add_flag("signature_match")
        self.add_rule_match(name=sig, provider=self.key)

    def scan_remote(self, data: bytes, file: File, options: Options) -> None:
        clamd_socket = options.get("clamd_socket")

        self.add_flag("remote")

        try:
            if clamd_socket and clamd_socket.startswith("/"):
                conn = clamd.ClamdUnixSocket(path=clamd_socket)
            elif clamd_socket and (m := self.PORT_RE.match(clamd_socket)):
                host, port, *_ = *filter(None, m.groups()), self.DEFAULT_PORT
                conn = clamd.ClamdNetworkSocket(host=host, port=int(port))
            else:
                self.fail("invalid_socket_option")
            with io.BytesIO(data) as clam_io:
                result = conn.instream(clam_io)
                if result is None or "stream" not in result:
                    self.add_flag("empty_result")
                _, sig = (result or {}).get("stream", (None, None))
                if sig is not None:
                    self.signature_matched(sig)

        except clamd.ConnectionError:
            self.add_flag("conn_error")
        except clamd.BufferTooLongError:
            self.add_flag("size_error")
        except clamd.ClamdError:
            self.add_flag("other_error")

    def scan_local(self, data: bytes, file: File, options: Options) -> None:
        freshen = options.get("freshen", False)
        freshclam_path = options.get("freshclam")
        clamscan_path = options.get("clamscan")

        self.add_flag("local")

        # if requested (and able), run freshclam to get the newest database
        # signatures; we don't always do this because signatures may be
        # managed/freshened by an outside source
        if freshen:
            try:
                self.run_program(
                    "freshclam",
                    program_path=freshclam_path,
                    output="drop",
                    check=True,
                )
            except FileNotFoundError:
                self.add_flag("freshclam_not_installed", None)
            except subprocess.CalledProcessError:
                self.add_flag("signature_update_failed")

        with (
            self.new_temporary_file(data, named=True) as tmp_data,
            self.new_temporary_dir() as tmp_scan,
        ):
            # run the actual ClamAV scan and report to local temp log file
            try:
                result = self.run_program(
                    "clamscan",
                    [
                        "--disable-cache",
                        f"--tempdir={tmp_scan}",
                        f"--log={tmp_scan}/log.txt",
                        "--leave-temps",
                        "--gen-json",
                        tmp_data.name,
                    ],
                    program_path=clamscan_path,
                    output="capture",
                    encoding="utf-8",
                )
            except FileNotFoundError:
                self.fail("clamscan_not_installed", None)
            if result.returncode == 2:
                self.fail("clamscan_failed", msg=f"Output:\n{result.stderr}")

            for path in Path(tmp_scan).rglob("*/metadata.json"):
                with path.open("r") as fh:
                    metadata = json.load(fh)
                break
            else:
                self.add_flag("missing_metadata")
                metadata = {}

            tmp_data_path = Path(tmp_data.name)

            def _walk_metadata(value, _) -> Any:
                if isinstance(value, tuple) and len(value) == 2:
                    k, v = self.normalize_key(value[0]), value[1]
                    if k == "file_path":
                        raise SkipItem
                    elif k == "file_name":
                        assert isinstance(v, str)
                        if (p := Path(v)).parts[0] == tmp_data_path.name:
                            if file.name:
                                v = Path(file.name, *p.parts[1:])
                            else:
                                v = Path(*p.parts[1:])
                    elif k == "file_md5":
                        self.add_related([v])
                    elif k == "viruses":
                        assert isinstance(v, Iterable)
                        for name in v:
                            self.signature_matched(name)
                    return k, v
                return value

            metadata = visit(metadata, _walk_metadata)
            self.event.update(metadata)
