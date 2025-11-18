import json
import os
import tempfile

from donut_decryptor.donut_decryptor import DonutDecryptor

from . import Options, Scanner
from ..model import Date, File


class ScanDonut(Scanner):
    """Extracts configs and modules from donut payloads"""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        tmp_directory = options.get("tmp_directory", tempfile.gettempdir())

        self.event.update(
            {
                "total": {
                    "donuts": 0,
                    "files": 0,
                },
                "donuts": [],
            }
        )

        with (
            tempfile.NamedTemporaryFile(dir=tmp_directory, mode="wb") as tmp_data,
            tempfile.TemporaryDirectory(dir=tmp_directory) as extract_dir,
        ):
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            try:
                donuts = DonutDecryptor.find_donuts(tmp_data.name)
            except Exception as e:
                # Set output flag on error
                self.add_flag("donut_decrypt_find_exception", e)
                return

            self.event["total"]["donuts"] = len(donuts)

            for donut in donuts:
                info = {
                    "instance_version": donut.instance_version,
                    "loader_version": donut.loader_version,
                    "offset_loader_start": donut.offset_loader_start,
                    "offsets": {
                        "size_instance": donut.offsets.get("size_instance"),
                        "encryption_start": donut.offsets.get("encryption_start"),
                    },
                }

                try:
                    donut.parse(extract_dir)
                    base = os.path.basename(tmp_data.name)
                    mod_name = f"mod_{base}"
                    inst_name = f"inst_{base}"

                    # Retrieve module file
                    with open(os.path.join(extract_dir, mod_name), "rb") as mod_file:
                        # send contents to Strelka for processing
                        self.emit_file(
                            mod_file.read(),
                            name=f":donut-{donut.offset_loader_start}",
                            unique_key=(donut.offset_loader_start,),
                        )
                        self.event["total"]["files"] += 1

                    # Retrieve instance metadata file
                    with open(os.path.join(extract_dir, inst_name), "rb") as inst_file:
                        info.update(
                            {
                                self.normalize_key(k): v
                                for k, v in json.load(inst_file).items()
                                if k not in {"File"}
                            }
                        )

                except Exception as e:
                    self.add_flag("donut_decrypt_parse_exception", e)

                self.event["donuts"].append(info)
