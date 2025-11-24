import json
import os.path
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Iterable

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

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        freshen = options.get("freshen", False)
        freshclam = self.find_executable("freshclam", options.get("freshclam", None))
        clamscan = self.find_executable("clamscan", options.get("clamscan", None))
        tmp_directory = options.get("tmp_directory", tempfile.gettempdir())

        if not clamscan or not os.path.exists(clamscan):
            self.add_flag("clamav_not_installed_error")
            return

        # if requested, run freshclam to get the newest database
        # signatures; we don't always do this because signatures may be
        # managed/freshened by an outside source
        if freshen:
            if not freshclam or not os.path.exists(freshclam):
                self.add_flag("clamav_maybe_outdated_signatures")
            else:
                try:
                    subprocess.run(
                        [freshclam],
                        capture_output=True,
                        check=True,
                    )
                except Exception as e:
                    self.add_flag("clamav_maybe_outdated_signatures", e)

        try:
            with (
                tempfile.NamedTemporaryFile(dir=tmp_directory, mode="wb") as tmp_data,
                tempfile.TemporaryDirectory(dir=tmp_directory) as tmp_scan,
            ):
                tmp_data_path = Path(tmp_data.name)
                # write our file data out to a tempfile so we can easily scan it
                tmp_data.write(data)
                tmp_data.flush()

                # run the actual ClamAV scan and report to local temp log file
                subprocess.run(
                    [
                        clamscan,
                        "--disable-cache",
                        f"--tempdir={tmp_scan}",
                        f"--log={tmp_scan}/log.txt",
                        "--leave-temps",
                        "--gen-json",
                        tmp_data.name,
                    ],
                    capture_output=True,
                    encoding="utf-8",
                    check=False,
                )

                for path in Path(tmp_scan).rglob("*/metadata.json"):
                    with path.open("r") as fh:
                        metadata = json.load(fh)
                    break
                else:
                    self.add_flag("clamav_missing_metadata")
                    metadata = {}

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
                                self.add_rule_match(name=name, provider=self.key)
                        return k, v
                    return value

                metadata = visit(metadata, _walk_metadata)
                self.event.update(metadata)

        except Exception:
            self.add_flag("clamav_scan_process_error")
