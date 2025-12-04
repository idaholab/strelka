import itertools
import json
from pathlib import Path
import subprocess

from . import Options, Scanner
from ..model import Date, File
from ..model.rule import Technique
from ..util.collections import pop_nested


class ScanCapa(Scanner):
    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        capa_path = options.get("capa")
        rules_dir = options.get("rules_dir") or None
        sigs_dir = options.get("signatures_dir") or None

        with self.new_temporary_file(data, named=True) as tmp_data:
            try:
                result = self.run_program(
                    "capa",
                    [
                        "--quiet",
                        "--json",
                        "-v",
                        rules_dir and ("-r", Path(rules_dir)),
                        sigs_dir and ("-s", Path(sigs_dir)),
                        "--color=never",
                        tmp_data.name,
                    ],
                    output="capture",
                    program_path=capa_path,
                    text=True,
                )
            except FileNotFoundError:
                self.fail("not_installed", None)
            except subprocess.CalledProcessError:
                self.fail("runtime_error")
            else:
                # these are pulled from the capa main; since 2021 capa has
                # exited with unique error codes depending on the specific
                # error condition--let's turn those into flags to limit the
                # number of exceptions that are output
                match result.returncode:
                    case 0:
                        pass
                    case 10:
                        if rules_dir:
                            self.fail("missing_rules")
                        else:
                            self.fail("no_embedded_rules")
                    case 11 | 15:
                        self.fail("file_io_error")
                    case 12:
                        self.fail("invalid_rules_in_ruleset")
                    case 13:
                        self.fail("invalid_executable_format")
                    case 14:
                        self.fail("unsupported_file")
                    case 16:
                        self.fail("unsupported_executable_format")
                    case 17:
                        self.fail("unsupported_executable_architecture")
                    case 18:
                        self.fail("unsupported_executable_os")
                    case 19:
                        self.fail("unsupported_ida_version")
                    case _:
                        self.fail(
                            "other_error",
                            msg=f"STDERR:\n{result.stderr}",
                        )

                if not result.stdout:
                    self.fail("empty_output")
                try:
                    event = json.loads(result.stdout)
                except json.JSONDecodeError:
                    self.fail("invalid_json_output")

                # remove some things that contain paths/etc. that are meaningful
                # to only our backend container, or possibly could leak anything
                pop_nested(event, "meta.analysis.rules")
                pop_nested(event, "meta.argv")
                pop_nested(event, "meta.sample.path")
                pop_nested(event, "meta.timestamp")

                # store the result in our event
                self.event.update(event)

                for rule in event.get("rules", {}).values():
                    meta = rule.get("meta", {})
                    self.add_rule_match(
                        name=meta["name"],
                        category=meta.get("namespace") or None,
                        description=meta.get("description") or None,
                        author=meta.get("authors") or None,
                        reference=meta.get("references") or None,
                        techniques=itertools.chain(
                            *(
                                [
                                    Technique(
                                        source=src,
                                        name="::".join(t.get("parts", ())) or None,
                                        id=t.get("id") or None,
                                    )
                                    for t in meta.get(k, ())
                                ]
                                for k, src in (
                                    ("attack", "att&ck"),
                                    ("mbc", "mbc"),
                                )
                            )
                        ),
                    )
