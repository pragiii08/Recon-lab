"""Scope enforcement: the lab refuses to touch anything outside authorised ranges.

By default only loopback and private (RFC1918 / ULA) addresses are in scope.
Extra ranges you are *explicitly authorised* to test can be added with --allow.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

DEFAULT_NETS = [
    "127.0.0.0/8", "::1/128",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
]


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope."""


@dataclass
class Scope:
    extra: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.nets = [ipaddress.ip_network(n, strict=False) for n in DEFAULT_NETS + list(self.extra)]

    def resolve(self, target: str) -> list:
        if not target or target.startswith("-"):
            raise ScopeError(f"Invalid target: {target!r}")
        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror as exc:
            raise ScopeError(f"Cannot resolve {target!r}: {exc}") from exc
        return sorted({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}, key=str)

    def check(self, target: str) -> list[str]:
        """Return resolved IPs if *every* one is in scope, else raise ScopeError."""
        addrs = self.resolve(target)
        for a in addrs:
            if not any(a in n for n in self.nets):
                raise ScopeError(
                    f"{target} resolves to {a}, which is OUT OF SCOPE. "
                    "Only loopback/private ranges are allowed unless you pass --allow <CIDR> "
                    "for a range you are authorised to test."
                )
        return [str(a) for a in addrs]
