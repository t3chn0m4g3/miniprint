"""Passive Brother lure helpers; no outbound network operations.

Password routine follows Metasploit's default salt index 254 (table entry 8).
https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
import uuid
from collections import OrderedDict


def brother_default_password(serial: str) -> str:
    salt = bytes(value - 1 for value in b"7HOLDhk'"[::-1])
    digest = hashlib.sha256(serial[:16].encode("ascii") + salt).digest()
    return base64.b64encode(digest).decode()[:8].translate(str.maketrans("lIzZbqOovy", "#$%&*-:?@>"))


class AuthSessions:
    def __init__(self, ttl: float = 1800, max_sessions: int = 1024, clock=time.monotonic):
        self.ttl, self.max_sessions, self.clock = ttl, max_sessions, clock
        self.sessions: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self.lock = threading.Lock()

    def _expire(self):
        for token, (expiry, _) in list(self.sessions.items()):
            if expiry <= self.clock():
                del self.sessions[token]

    def create(self, source: str) -> str:
        with self.lock:
            self._expire()
            token = str(uuid.uuid4())
            self.sessions[token] = (self.clock() + self.ttl, source)
            while len(self.sessions) > self.max_sessions:
                self.sessions.popitem(last=False)
            return token

    def valid(self, token: str, source: str) -> bool:
        with self.lock:
            self._expire()
            entry = self.sessions.get(token)
            return bool(entry and entry[1] == source)
