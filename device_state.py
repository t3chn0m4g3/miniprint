from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceState:
    fs: Any = None
    ready_msg: str = "Ready"
    variables: dict[str, str] = field(
        default_factory=lambda: {"COPIES": "1", "DUPLEX": "OFF", "FORMLINES": "60", "ORIENTATION": "PORTRAIT"}
    )
    defaults: dict[str, str] = field(
        default_factory=lambda: {"COPIES": "1", "DUPLEX": "OFF", "FORMLINES": "60", "ORIENTATION": "PORTRAIT"}
    )
    lock: Any = field(default_factory=threading.RLock)
    reboot_until: float = 0


class DeviceStateStore:
    def __init__(self, max_entries: int = 256, ttl: float = 86400, clock=time.monotonic):
        self.max_entries, self.ttl, self.clock = max_entries, ttl, clock
        self.entries: OrderedDict[str, tuple[float, DeviceState]] = OrderedDict()
        self.lock = threading.RLock()

    def get(self, source: str) -> DeviceState:
        with self.lock:
            now = self.clock()
            for key, (last_seen, _) in list(self.entries.items()):
                if now - last_seen >= self.ttl:
                    del self.entries[key]
            value = self.entries.pop(source, (now, DeviceState()))[1]
            self.entries[source] = (now, value)
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)
            return value
