import os
import platform
from typing import Any

from opentelemetry.sdk.resources import Resource

from .. import __namespace__, __version__


def get_resource(meta: dict[str, Any] | None = None):
    return Resource(
        attributes={
            "service.namespace": __namespace__,
            "service.name": "strelka.backend.worker",
            "service.version": __version__,
            "host.name": os.environ.get("HOSTNAME", ""),
            "host.arch": platform.processor(),
            "os.type": platform.system(),
            **(meta or {}),
        },
    )
