import logging
from pathlib import Path

import yara

from . import Options, Scanner
from ..model import Date, File
from ..util.files import FileCache


class _NotLoaded(Exception):
    pass


class ScanYara(Scanner):
    """Scans files with YARA.

    Attributes:
        compiled_yara: Compiled YARA file derived from YARA rule file(s)
            in location.

    Options:
        location: Location of the YARA rules file or directory.
            Defaults to '/etc/strelka/yara/'.
        meta: List of YARA rule meta identifiers
            (e.g. 'Author') that should be logged.
            Defaults to empty list.
        store_offset: To extract hexacimal offsts.
            If true, YARA metadata will be examined for
            keys. If found, extract out hexadecimal
            reference lines
        offset_meta_key: To extract hexadecimal offsets.
            A string found in a YARA's meta
            (e.g., 'StrelkaHexDump = true')
        offset_padding: Padding length before and after
            offset match for context
    """

    _rules_cache: FileCache[yara.Rules]

    def init(self):
        self._rules_cache = FileCache()

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """Scans the provided data with YARA rules.

        Args:
            data (bytes): The data to scan.
            file (File): An object representing the file being scanned.
            options (dict): Configuration options for the scan.
            expire_at (int): Expiration time for the scan.

        Populates self.event with matches, tags, meta, and hex data
        based on YARA rule matches.
        """

        location = Path(options.get("location", "/etc/strelka/yara"))
        compiled = options.get("compiled", {"enabled": False, "filename": None})
        use_compiled = compiled.get("enabled", False)
        compiled_filename = compiled.get("filename", "rules.compiled")
        rules = None

        self.event.update(
            {
                "matches": set(),
                "tags": set(),
                "categories": {},
                "meta": [],
                "hex": [],
            }
        )

        if use_compiled:
            try:
                rules = self._rules_cache.load(location / compiled_filename, self.load_yara_rules)
            except FileNotFoundError:
                logging.warning("Compiled YARA rules do not exist: %s", location / compiled_filename)
            except _NotLoaded:
                logging.warning("Failed to load compiled YARA rules, trying to compile instead.")

        if not rules:
            try:
                rules = self._rules_cache.load(location, self.compile_yara_rules)
            except FileNotFoundError:
                logging.error("YARA rules do not exist: %s", location)
                self.fail("no_rules_loaded")
            except _NotLoaded:
                logging.error("Failed to compile YARA rules, unable to scan.")
                self.fail("no_rules_loaded", None)

        if len(list(rules)) == 0:
            self.fail("empty_rules")

        hex_dump_cache = {}
        categories = options.get("categories", {})
        category_key = options.get("category_key", "")
        meta_fields = options.get("meta_fields", [])
        show_all_meta = options.get("show_all_meta", False)
        store_offset = options.get("store_offset", False)
        offset_meta_key = options.get("offset_meta_key", "")
        offset_padding = options.get("offset_padding", 32)

        yara_matches = rules.match(data=data)
        for match in yara_matches:
            # add the rule and ruleset name to the category meta
            rule = {
                "name": match.rule,
                "ruleset": match.namespace,
            }
            # include meta if its in the meta_fields list
            for k, v in match.meta.items():
                if k.lower() in meta_fields:
                    rule.update({k.lower(): v})
            for category, params in categories.items():
                cat_matches = self.event["categories"].setdefault(category, [])
                # check if the category matches the category_key
                if category in match.meta.get(category_key, "").lower():
                    # show meta for specific category if enabled
                    if params.get("show_meta", False):
                        cat_matches.append(rule)
                    else:
                        cat_matches.append(match.rule)
                # show meta for specific tag if present
                # if category in list(map(str.lower, match.tags)):
                #     self.event[category].append(rule)

            # Append rule matches and update tags.
            self.event["matches"].add(match.rule)
            self.event["tags"].update(match.tags)
            self.add_rule_match(
                name=match.rule,
                provider=self.key,
                category=match.namespace,
                tags=match.tags if match else None,
            )

            # Extract hex representation if configured to store offsets.
            if store_offset and offset_meta_key:
                if match.meta.get(offset_meta_key):
                    for string_data in match.strings:
                        self.event["hex"].extend(
                            self.extract_match_hex(
                                match.rule,
                                instance.offset,
                                instance.matched_data,
                                data,
                                offset_padding,
                                hex_dump_cache,
                            )
                            for instance in string_data.instances
                        )

            # Append meta information if configured to do so
            if show_all_meta:
                self.event["meta"].extend(
                    {
                        "rule": match.rule,
                        "identifier": k,
                        "value": v,
                    }
                    for k, v in match.meta.items()
                )

    def load_yara_rules(self, path: Path) -> yara.Rules:
        try:
            return yara.load(str(path))
        except yara.Error:
            self.add_flag("load_error")
            logging.exception("Failed to load compiled YARA rules from: %s", path)
        raise _NotLoaded

    def compile_yara_rules(self, path: Path) -> yara.Rules:
        try:
            if path.is_dir():
                return yara.compile(
                    filepaths={f"namespace{i}": str(entry) for i, entry in enumerate(path.glob("**/*.yar*"))},
                )
            elif path.is_file():
                return yara.compile(filepath=str(path))
            else:
                self.add_flag("missing_rules")
                logging.warning("YARA rules do not exist: %s", path)
        except yara.SyntaxError:
            self.add_flag("syntax_error")
            logging.exception("Syntax error in YARA rules at: %s", path)
        except yara.Error:
            self.add_flag("compile_error")
            logging.exception("Failed to compile YARA rules from: %s", path)
        raise _NotLoaded

        # if path.is_dir():
        #            globbed_yara_paths = glob.iglob(
        #                f"{location}/**/*.yar*", recursive=True
        #            )
        #            if not globbed_yara_paths:
        #                self.flags.append("yara_rules_not_found")
        #            yara_filepaths = {
        #                f"namespace_{i}": entry
        #                for (i, entry) in enumerate(globbed_yara_paths)
        #            }
        #            self.compiled_yara = yara.compile(filepaths=yara_filepaths)
        #        # Compile YARA rules from a single file.
        #        elif os.path.isfile(location):
        #            self.compiled_yara = yara.compile(filepath=location)
        #        else:
        #            self.flags.append("yara_location_not_found")
        #            self.warn_user = True
        #            self.warn_message = "YARA Location Not Found"
        # except yara.SyntaxError as e:
        #    self.flags.append(f"compiling_error_syntax_{e}")
        #    self.warn_user = True
        #    self.warn_message = str(e)
        # except yara.Error as e:
        #    self.flags.append(f"compiling_error_general_{e}")
        #    self.warn_user = True
        #    self.warn_message = str(e)
        ## Set the total rules loaded.
        # if self.compiled_yara:
        #    self.rules_loaded = len(list(self.compiled_yara))
        # if not self.compiled_yara:
        #    if not self.warned_user and self.warn_user:
        #        logging.warning(
        #            "\n"
        #            "*************************************************\n"
        #            "* WARNING: YARA File Loading Issue Detected     *\n"
        #            "*************************************************\n"
        #            "There was an issue loading the compiled YARA file. Please check that all YARA rules can be\n"
        #            "successfully compiled. Additionally, verify the 'ScanYara' configuration in Backend.yaml to\n"
        #            "ensure the targeted path is correct. This issue needs to be resolved for proper scanning\n"
        #            "functionality.\n"
        #            "\n"
        #            f"Error: {self.warn_message}\n"
        #            "*************************************************\n"
        #        )
        #        self.warned_user = True

    def extract_match_hex(
        self,
        rule: str,
        offset: int,
        matched_string: str,
        data: bytes,
        offset_padding: int = 32,
        cache: dict[int, tuple[str, str]] | None = None,
    ) -> dict:
        """
        Extracts a hex dump of a matched string in the data, with padding.

        This function retrieves a hex dump of the specified matched string within
        the data. It also provides additional context around the matched string
        by adding padding before and after the match. The total padding (i.e., the
        sum of before and after) is defined by the `offset_padding` parameter, which
        is split evenly on either side of the matched string. If the padding would
        go beyond the start or end of the data, it's adjusted to fit within the data's
        bounds.

        Args:
        - rule (str): Name of the YARA rule that triggered the match
        - offset (int): Start offset of the matched string in the data
        - matched_string (str): The actual string in the data that matched the YARA rule
        - data (bytes): The file data being scanned
        - offset_padding (int, optional): Total number of bytes to include as padding
        - cache (dict, optional): Cache for the current scan
        around the matched string in the hex dump. Defaults to 32.

        Returns:
        - A dictionary containing the rule name and hex dump.
        """

        cache = cache or {}

        # Calculate half of the total padding to distribute evenly on either side of the
        # match to add context. It's recommended to keep this low (16 bytes).
        half_padding = offset_padding // 2

        # Determine the starting and ending offsets for the hex dump, ensuring we stay
        # within data bounds.
        start_offset = max(offset - half_padding, 0)
        end_offset = min(offset + len(matched_string) + half_padding, len(data))

        # Create a list to store the hex representation lines
        hex_lines = []

        # Loop through the data range in 16-byte chunks to generate the hex dump
        for i in range(start_offset, end_offset, 16):
            # If this chunk hasn't been processed before, generate its representations
            if i not in cache:
                chunk = data[i : i + 16]

                # Convert each byte in the chunk to its hexadecimal representation and
                # join them with spaces.
                # E.g., a chunk [65, 66, 67] would become the string "41 42 43"
                hex_values = " ".join([f"{byte:02x}" for byte in chunk])

                # Generate an ASCII representation for each byte in the chunk:
                # - Use the character itself if it's a printable ASCII character
                #   (between 32 and 126 inclusive).
                # - Replace non-printable characters with a period ('.').
                # E.g., a chunk [65, 66, 0] would become the string "AB."
                ascii_values = "".join([chr(byte) if 32 <= byte <= 126 else "." for byte in chunk])

                # Cache the generated hex and ASCII values to avoid redundant
                # computation in the future
                cache[i] = (hex_values, ascii_values)
            else:
                hex_values, ascii_values = cache[i]

            # Generate a formatted string for this chunk and add to our hex_lines list
            hex_lines.append(f"{i:08x}  {hex_values:<47}  {ascii_values}")

        # Append the generated hex dump and rule information to the event
        return {"rule": rule, "dump": hex_lines}
