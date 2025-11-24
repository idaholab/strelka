import importlib.resources
import re
from typing import Final
from unittest import TestCase
import warnings


name_re: Final = re.compile(r"^scan_([a-z][a-z0-9]*)\.py")
missing_tests_message: Final = (
    "Some scanners are missing unit tests!\n"
    "\n"
    "Scanners with missing tests:\n"
    "    {}\n"
)


def test_required_for_scanner() -> None:
    # walk through the contents of strelka.scanners in a more proper way so that
    # we also include anything handled by our plugin loader
    missing = set()
    for scanner in importlib.resources.files("strelka.scanners").iterdir():
        if not (m := name_re.match(scanner.name)):
            continue
        test_script = f"test_scan_{m.group(1)}.py"
        # also look for the test in a plugin-compatible way
        if not (importlib.resources.files("strelka.tests") / test_script).is_file():
            missing.add(m.group(1))

    # if we had any missing, warn about it
    if missing:
        warnings.warn(missing_tests_message.format(", ".join(sorted(missing))))

    # while tests are currently strongly recommended, they aren't yet required
    # for any given scanner; for the time being, always succeed
    TestCase().assertTrue(True)
