#!/usr/bin/env python3
"""Boot-safe entrypoint for the network-disabled GuToChat receive-iGate poller.

An expected readiness miss maps to a clean exit so Restart=on-failure cannot
loop around an early-boot APRS DB dependency race.  The boot timer retries
later.  When ready, this process is replaced with the exact C3.2R2 proven
network-disabled engine command.
"""

from __future__ import annotations

import os
import sys

import aprs_igate_boot_readiness_v1 as readiness

ENGINE_ARGV = (
    "/usr/bin/python3",
    "-B",
    "/var/lib/gutochat-preview/legacy-disabled/lorachat-v2/app/aprs_igate_engine_v1.py",
    "run",
    "--aprs-db",
    "/var/lib/gutochat-preview/legacy-disabled/.local/share/gutochat/aprs/aprs.db",
    "--outbox-db",
    "/var/lib/gutochat-aprs-igate/igate_outbox.db",
    "--igate-call",
    "N0CALL",
    "--poll-seconds",
    "2",
    "--scan-limit",
    "100",
    "--dispatch-mode",
    "disabled",
    "--dispatch-limit",
    "0",
)


def main() -> int:
    rc = readiness.main([])

    if rc == readiness.NOT_READY:
        print("IGATE_BOOT_ENTRY=DEFERRED readiness=NOT_READY", flush=True)
        return 0

    if rc != readiness.READY:
        print(f"IGATE_BOOT_ENTRY=ERROR readiness_rc={rc}", file=sys.stderr, flush=True)
        return rc if 0 < rc <= 255 else readiness.PROBE_ERROR

    print("IGATE_BOOT_ENTRY=STARTING_POLLER dispatch_mode=disabled", flush=True)
    os.execv(ENGINE_ARGV[0], list(ENGINE_ARGV))
    return readiness.PROBE_ERROR  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
