from __future__ import annotations
import contextlib
import logging
import os
import sys
from typing import Any, Final, Iterable, Mapping, Protocol, cast, runtime_checkable

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

from .. import __namespace__
from . import get_resource


default_traces_sampling: Final = 0.1


def set_global_provider(traces_config: dict, meta: dict | None = None) -> None:
    exporter_name = traces_config.get("exporter")

    if (
        "PYTEST_CURRENT_TEST" in os.environ
        or "pytest" in sys.modules
        or not exporter_name
    ):
        return

    rate = traces_config.get("sampling")
    if not isinstance(rate, (float, int)) or 0.0 < rate <= 1.0:
        logging.exception(
            "trace sampling value (float) missing/out-of-range, using "
            "default: %s -> %f",
            rate, default_traces_sampling,
        )
        rate = default_traces_sampling

    sampler = TraceIdRatioBased(rate)
    resource = get_resource(meta)
    provider = TracerProvider(resource=resource, sampler=sampler)
    addr = traces_config.get("addr", "")

    if exporter_name == "otlp-grpc":
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )

        # FIXME: this seems to imply that it -can- authenticate using an 'auth'
        #        section in the tracing config, but then doesn't do anything
        #        with that? should this be implemented somewhere?
        exporter = OTLPSpanExporter(
            endpoint=addr,
            insecure=bool(traces_config.get("auth")),
        )

    elif exporter_name == "otlp-http":
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(
            endpoint=addr,
        )

    elif exporter_name == "jaeger-http-thrift":
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter

        exporter = JaegerExporter(
            collector_endpoint=addr,
        )

    elif exporter_name == "jaeger-udp-thrift":
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter

        host, port, *_ = addr.split(":"), 0
        port = int(port)
        if not host or not int(port):
            raise ValueError("invalid host/port for jaeger-udp-thrift exporter")
        exporter = JaegerExporter(
            agent_host_name=host,
            agent_port=port,
            udp_split_oversized_batches=True,
        )

    else:
        logging.info("no exporter for tracer, disabling")
        return

    logging.info("tracer sampling at %f", sampler.rate)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    # set the global default tracer provider
    trace.set_tracer_provider(provider)


def get_tracer(
    traces_config: dict,
    meta: dict | None = None,
    *,
    name: str = __name__,
) -> trace.Tracer:
    # setup the global tracing provider first
    set_global_provider(traces_config, meta)
    # then create a tracer; if no provider/exporter has been specified, tracing
    # will be effectively disabled
    return trace.get_tracer(name)


@runtime_checkable
class HasTraceAttributes(Protocol):
    @property
    def trace_attributes(self) -> Mapping[str, Any] | Iterable[tuple[str, Any]]:
        ...


SpanContextManager = contextlib._GeneratorContextManager[trace.Span]
TraceAttributes = Mapping[str, Any] | Iterable[tuple[str, Any]] | HasTraceAttributes


class SpanCreatorMixin:
    tracer: trace.Tracer

    def start_span(
        self, name: str, *,
        attributes: TraceAttributes = (),
        **kwargs,
    ) -> SpanContextManager:
        def fix_key(key: str) -> str:
            return "{}.{}".format(
                __namespace__,
                key.removeprefix(__namespace__).lstrip("."),
            )

        if isinstance(attributes, HasTraceAttributes):
            attributes = attributes.trace_attributes
        if isinstance(attributes, Mapping):
            attributes = cast(Iterable[tuple[str, Any]], attributes.items())

        return self.tracer.start_as_current_span(
            name,
            attributes={fix_key(k): v for k, v in attributes},
            **kwargs,
        )
