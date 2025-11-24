from __future__ import annotations
import datetime
import io
import json
import logging
import math
import os
import time
from typing import cast
import uuid

import redis
from typing_extensions import override

from . import BaseBackend
from ..config import BackendConfig
from ..exceptions import ConfigError, RequestTimeout
from ..model import Date, File, Tree, serialize
from ..util import chunk_data, match_quantity
from ..util.collections import is_sequence
from ..util.timeout import timeout_after
from .task import Client, Task


class RedisBackend(BaseBackend):
    coordinator: redis.StrictRedis

    __file_data: dict[str, tuple[bytes, Date]]

    def __init__(
        self,
        config: BackendConfig,
        coordinator: redis.StrictRedis | None = None,
    ) -> None:
        super().__init__(config)

        self.__file_data = {}

        # if a coordinator is supplied, just use that
        if coordinator:
            self.coordinator = coordinator

        # if the coordinator isn't provided, try to make one from the connection
        # parameters in the backend config file
        else:
            addr = self.config.get("coordinator.addr", "")
            host, port, *_ = *addr.split(":"), 6379
            if not host:
                raise ConfigError(
                    "coordinator.addr",
                    addr,
                    "<host>[:<port>]",
                )
            self.coordinator = redis.StrictRedis(
                host=host,
                port=int(port),
                db=self.config.get("coordinator.db", 0),
                username=self.config.get("coordinator.username", None),
                password=self.config.get("coordinator.password", None),
                client_name=f"strelka-backend-{os.getpid()}",
            )

        # if we ended up with a coordinator after all that, make sure it's
        # willing to talk to us
        if self.coordinator.ping():
            logging.info("backend started with coordinator")
        else:
            raise RuntimeError("coordinator is unavailable")

    def get_task(self) -> Task:
        # try to request task from Redis coordinator until we get one
        while True:
            task = None
            try:
                timeout = self.config.get("coordinator.blocking_pop_time_sec", 0)
                if timeout > 0:
                    task = self.coordinator.bzpopmin("tasks", timeout=timeout)
                    if task is None:
                        continue
                    assert is_sequence(task, 3)
                    _, task_item, expire_at = task
                else:
                    tasks = self.coordinator.zpopmin("tasks", count=1)
                    if not tasks:
                        time.sleep(0.25)
                        continue
                    assert is_sequence(tasks, 1)
                    assert is_sequence(tasks[0], 2)
                    task_item, expire_at = tasks[0]
            except (AssertionError, ValueError, TypeError):
                logging.exception("invalid item in task list: %r", task)
                continue

            # try to interpret the task as a new-style/JSON task
            try:
                task_info = json.loads(task_item)
            # parsing failed, so the task must be an old-style/ID-only task
            except json.JSONDecodeError:
                logging.warning("got ID-only request: %r", task_item)
                task_info = {"id": task_item.decode()}

            # if what we decoded isn't a dictionary, that's a problem
            if not isinstance(task_info, dict):
                logging.error("invalid item in task list: %r", task_info)
                continue
            # if our decoded task doesn't have an ID field, we can't associate
            # it back to anything in redis, so bail now
            if "id" not in task_info:
                logging.error("task has no ID: %r", task_info)
                continue

            # determine our root ID and/or pointer (which may be different, on
            # the off chance that whatever ID the task has is not a valid UUID)
            task_id = task_info["id"]
            try:
                root = uuid.UUID(task_id)
                pointer = str(root)
            except ValueError:
                root = uuid.uuid4()
                pointer = task_id
                logging.exception(
                    "task ID is not a valid UUID, using ID as pointer and "
                    "generating file UUID: %r -> %r",
                    task_id,
                    root,
                )

            # warn if we didn't get a filename as part of our request
            attrs = task_info.get("attributes", {})
            if "filename" not in attrs:
                logging.warning("request has no filename: %r", task_info)

            metadata = {}
            for key, value in attrs.get("metadata", {}).items():
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    pass
                metadata[key] = value

            # create a new task object with the info extracted from the request
            return Task(
                id=pointer,
                submitted_at=task_info.get("time", time.time()),
                expire_at=datetime.datetime.fromtimestamp(expire_at, datetime.UTC),
                traceparent=task_info.get("tracecontext"),
                client=Client(
                    task_info.get("source"),
                    task_info.get("client"),
                ),
                file=File(
                    pointer=pointer,
                    tree=Tree(root=root),
                    name=attrs.get("filename"),
                    metadata=metadata,
                    source="request",
                    has_data=True,
                    **attrs.get("properties", {}),
                ),
            )

    def work(self) -> None:
        """Process tasks from Redis coordinator"""

        logging.info("beginning main work loop")

        count = 0
        time_to_live = self.config.get("limits.time_to_live")
        max_files = self.config.get("limits.max_files")
        work_start = time.time()
        work_expire = (work_start + time_to_live) if time_to_live else None

        while (not max_files or count < max_files) or (
            not work_expire or time.time() < work_expire
        ):
            # fetch the next task from the coordinator
            task = self.get_task()
            # make sure it hasn't already expired while waiting to be processed
            if task.expired:
                logging.warning("discarding expired task: %s", task)
                continue
            # we have a task, now process it
            try:
                # actually try to perform the scan, but make sure we don't
                # exceed our given time window; push any resulting events back
                # into the coordinator as we receive them
                with timeout_after(task.remaining_seconds, RequestTimeout):
                    for event in self.distribute(task, task.file):
                        with self.coordinator.pipeline(transaction=False) as p:
                            p.rpush(task.event_list, serialize(event))
                            p.expireat(task.event_list, task.expire_at)
                            p.execute()
            except RequestTimeout:
                logging.warning("%s timed out", task)
            except Exception:
                logging.exception("unhandled exception during %s", task)
            else:
                logging.info("task completed: %s", task)
            finally:
                # push completion event back to Redis to complete request
                with self.coordinator.pipeline(transaction=False) as p:
                    p.rpush(task.event_list, "FIN")
                    p.expireat(task.event_list, task.expire_at)
                    p.execute()

            count += 1

        elapsed = math.ceil(time.time() - work_start)
        logging.info(
            "shutdown after servicing %d %s and %d %s",
            *match_quantity(count, "request"),
            *match_quantity(elapsed, "second"),
        )

    @override
    def retrieve_file_data(
        self,
        file: File,
    ) -> bytes | None:
        # if possible, use any locally-attached data first
        if file.pointer in self.__file_data:
            data, expire_at = self.__file_data.pop(file.pointer)
            if datetime.datetime.now(datetime.UTC) < expire_at:
                return data
            else:
                logging.warning("file data for %s has expired", file.pointer)
                return None

        # nope, pull from redis instead
        with self.start_span("redis-lpop", attributes={"pointer": file.pointer}):
            # INFO: we use a BytesIO object to not run into the infamous
            #       Python "adding strings" slowdown, which can easily take
            #       longer than the distribution timeout for "larger" files
            #       (as in, >30MB...)
            with io.BytesIO() as buf:
                lname = f"data:{file.pointer}"
                while True:
                    # INFO: the typing on `.lpop()` is wrong (the non-async
                    #       client will never return an `Awaitable`, and
                    #       even beyond that, it always returns `bytes`
                    #       instead of `str` here), so we need to cast the
                    #       result to make the typing happy
                    pop = cast(bytes | None, self.coordinator.lpop(lname))
                    if pop is None:
                        break
                    buf.write(pop)
                return buf.getvalue()

    @override
    def store_file_data(
        self,
        file: File,
        data: bytes | bytearray | memoryview[int],
        expire_at: Date,
    ) -> None:
        if self.config.get("coordinator.always_upload_file_data", True):
            chunksize = self.config.get("coordinator.data_chunk_size", 16 * 1024)
            with (
                self.start_span("redis-rpush", attributes=file),
                self.coordinator.pipeline(transaction=False) as p,
            ):
                for chunk in chunk_data(data, chunksize):
                    p.rpush(f"data:{file.pointer}", chunk)
                p.expireat(f"data:{file.pointer}", expire_at)
                p.execute()
        else:
            if file.pointer in self.__file_data:
                raise KeyError(
                    f"locally stored data for pointer {file.pointer} already exists"
                )
            self.__file_data[file.pointer] = (bytes(data), expire_at)
