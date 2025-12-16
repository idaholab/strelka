from datetime import timedelta
from pathlib import Path
from unittest import TestCase

import pytest

from strelka.backend import BaseBackend
from strelka.backend.local import LocalBackend
from strelka.config import BackendConfig
from strelka.model import File
from strelka.testing import DEFAULT_BACKEND_CONFIG
from strelka.util import now


EMPTY_FILE = File.EMPTY.model_replace(has_data=True)


def pytest_addoption(parser) -> None:
    parser.addoption(
        "--backend-cfg-path",
        metavar="PATH",
        type=Path,
        help="path to Strelka backend configuration file",
    )


@pytest.fixture
def backend_config(pytestconfig) -> BackendConfig:
    config = BackendConfig(pytestconfig.getoption("backend_cfg_path"))
    config.update_if_missing(DEFAULT_BACKEND_CONFIG)
    return config


@pytest.fixture
def backend(backend_config: BackendConfig) -> BaseBackend:
    return LocalBackend(backend_config)


@pytest.fixture
def empty_file(backend: BaseBackend) -> File:
    backend.store_file_data(EMPTY_FILE, b"", now() + timedelta(hours=1))
    return EMPTY_FILE


def pytest_runtest_setup() -> None:
    TestCase.maxDiff = None
