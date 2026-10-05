"""Structured failure logging — never log secrets."""

from __future__ import annotations

import re
from collections import deque
from typing import Callable

from .models import FailureRecord, utc_now_iso

_SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key|token|authorization|password|secret)\s*[:=]\s*\S+", re.I),
    re.compile(r"Bearer\s+\S+", re.I),
]


def redact(message: str) -> str:
    out = message
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(0).split("=")[0].split(":")[0] + "=[REDACTED]", out)
    return out[:2000]


class FailureSink:
    def __init__(self, maxlen: int = 5000, on_failure: Callable[[FailureRecord], None] | None = None) -> None:
        self.records: deque[FailureRecord] = deque(maxlen=maxlen)
        self.on_failure = on_failure

    def record(
        self,
        source: str,
        operation: str,
        error: BaseException | str,
        hostname: str | None = None,
        error_type: str | None = None,
    ) -> FailureRecord:
        if isinstance(error, BaseException):
            et = error_type or type(error).__name__
            msg = redact(str(error))
        else:
            et = error_type or "Error"
            msg = redact(str(error))
        rec = FailureRecord(
            source=source,
            operation=operation,
            hostname=hostname,
            timestamp=utc_now_iso(),
            error_type=et,
            message=msg,
        )
        self.records.append(rec)
        if self.on_failure:
            self.on_failure(rec)
        return rec
