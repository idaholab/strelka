from __future__ import annotations
import contextlib
import datetime
import logging
import signal
import time
from types import FrameType
from typing import Iterator


__all__ = (
    "BaseTimeout",
    "timeout_after",
)


class BaseTimeout(BaseException):
    pass


class TimeoutHandlerContext:
    __start: float
    __duration: float
    __end: float
    __expired: bool

    def __init__(self, duration: float, start: float | None = None) -> None:
        if start is None:
            start = time.time()
        self.__start = start
        self.__duration = duration
        self.__end = start + duration
        self.__expired = False

    def __bool__(self) -> bool:
        return self.expired

    @property
    def start(self) -> float:
        return self.__start

    @property
    def duration(self) -> float:
        return self.__duration

    @property
    def end(self) -> float:
        return self.__end

    @property
    def remaining(self) -> float:
        return self.__end - time.time()

    @property
    def expired(self) -> bool:
        return self.__expired

    def set_expired(self) -> None:
        self.__expired = True


@contextlib.contextmanager
def timeout_after(
    duration: float | datetime.timedelta,
    exc: type[BaseTimeout],
) -> Iterator[TimeoutHandlerContext]:
    if isinstance(duration, datetime.timedelta):
        duration = duration.total_seconds()

    # build our context we'll return; this is entirely so we can check for
    # expiration status within this context, in order to handle "oops, we caught
    # too many exceptions and ate our timeout" semi-sanely
    context = TimeoutHandlerContext(duration)

    # first things first, check to see if any existing timer would expire before
    # us; if so, we won't set a new timer to simulate having multiple timers and
    # the outer one firing first
    remain, _ = signal.getitimer(signal.ITIMER_REAL)
    if remain > 0 and remain <= duration:
        yield context
        return

    def handler(signum: int, frame: FrameType | None) -> None:
        nonlocal context
        context.set_expired()
        raise exc

    # set our new handler/timer info, but store the original so we can
    # restore the timer state at the end of our processing
    old_handler = signal.signal(signal.SIGALRM, handler)
    old_secs, old_interval = signal.setitimer(signal.ITIMER_REAL, duration)

    # we warn about this (which we don't do, but just in case) since it very
    # well may not fire at the expected time, so any repeated action will
    # have a weird offset based on our timer
    if old_interval > 0:
        logging.warning("overwriting itimer with non-zero interval")

    try:
        # pass control out so that whatever timed action can occur
        yield context

    finally:
        # restore the original alarm handler, since we always need to do that
        signal.signal(signal.SIGALRM, old_handler)
        # if we previously had an itimer set, figure out how much time is left
        if old_secs > 0:
            remain = old_secs - (time.time() - context.start)
            # if it's already expired, we will set it to expire almost
            # immediately, that way any exception processing is (hopefully)
            # taken care of and we can raise any new exceptions outside such
            # that they're not nested
            if remain <= 0:
                remain = 0.25
            signal.setitimer(signal.ITIMER_REAL, remain, old_interval)
        # no previous itimer set, clear the timer
        else:
            signal.setitimer(signal.ITIMER_REAL, 0)
