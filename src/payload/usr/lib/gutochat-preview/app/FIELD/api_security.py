#!/usr/bin/env python3
"""Small defense-in-depth helpers for local GuToChat service APIs."""
from __future__ import annotations

import ipaddress
from typing import Any


def is_loopback_client(client_address: Any) -> bool:
    """Return True only for an IPv4/IPv6 loopback peer address."""
    try:
        host = str(client_address[0])
        return ipaddress.ip_address(host).is_loopback
    except (IndexError, TypeError, ValueError):
        return False
