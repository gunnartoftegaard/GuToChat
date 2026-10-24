#!/usr/bin/env python3
"""Boot-safe entrypoint for GuToChat APRS-A2 classic RF receive.

The entrypoint maps an expected readiness miss to a clean service exit (0),
so Restart=on-failure cannot create a dependency-loss restart loop. A timer
may safely attempt activation again later. If readiness is satisfied, this
process is replaced with the exact proven A2 pipeline.
"""

from __future__ import annotations

import os
import sys

import aprs_a2_boot_readiness as readiness

PIPELINE = (
    "/usr/bin/stdbuf -oL -eL /usr/bin/direwolf -t 0 "
    "-c /var/lib/gutochat-preview/legacy-disabled/.config/lorachat-v2/direwolf-a2-rx-only.conf | "
    "/usr/bin/python3 -B /var/lib/gutochat-preview/legacy-disabled/lorachat-v2/app/a2_adapter_process_v1_rev3.py "
    "--parser /var/lib/gutochat-preview/legacy-disabled/lorachat-v2/app/a2_ingress_parser_v1.py | "
    "/usr/bin/python3 -B /var/lib/gutochat-preview/legacy-disabled/lorachat-v2/app/aprs_a2_client.py "
    "--socket /run/gutochat-aprs-a2/a2-rx.sock"
)


def main() -> int:
    rc = readiness.main([])

    if rc == readiness.NOT_READY:
        # Expected operational dependency absence (FTX-1/audio/A1H socket).
        # Clean exit prevents Restart=on-failure from looping.
        print("A2_BOOT_ENTRY=DEFERRED readiness=NOT_READY")
        return 0

    if rc != readiness.READY:
        print(f"A2_BOOT_ENTRY=ERROR readiness_rc={rc}", file=sys.stderr)
        return rc if 0 < rc <= 255 else readiness.PROBE_ERROR

    print("A2_BOOT_ENTRY=STARTING_PIPELINE")
    sys.stdout.flush()
    os.execv(
        "/bin/bash",
        ["/bin/bash", "-o", "pipefail", "-c", PIPELINE],
    )
    return readiness.PROBE_ERROR  # pragma: no cover; execv does not return


if __name__ == "__main__":
    raise SystemExit(main())
