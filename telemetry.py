from __future__ import annotations

import logging
from datetime import datetime
from typing import Any


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        base_extra = dict(self.extra)
        call_extra = kwargs.get("extra")
        if call_extra:
            base_extra.update(call_extra)
        kwargs["extra"] = base_extra
        return msg, kwargs
