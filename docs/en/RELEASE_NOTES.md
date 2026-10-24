# Candidate 18 – upgrade and messaging trial passed

Application `2.5.0~preview20261024.18docs1`; unchanged optional driver
`2.7.9~gutochat20261024.4`. This release is marked as an experimental prerelease.

## Changes

- Earlier fixes for Base startup, non-finite longitude input and early recipient
  acknowledgements are retained.
- Candidate 17 serializes Field sync-cursor validation and page storage.
- Candidate 18 adds the missing nullable `ingested_epoch` before creating a legacy
  position-history index. Initialization is serialized; prior values are retained
  without inventing historical ingestion timestamps.
- Bilingual package guides are included. Driver4 contains additional notices;
  driver libraries are unchanged.

## Acceptance on 24 October 2026

Raspberry Pi 5, Debian13 arm64, Python3.13.5:848 installed payload files verified;
package-manager audit clean. Configurations and both databases retained. Both
core services and the optional X433 adapter are healthy. The user confirms both
GUI windows open and the test Base receives recipient ACK and reply from T433.
NB/EN language settings are retained. This was an upgrade trial, not a fresh
candidate18 install, physical Field sync or new machine reboot trial.

Isolated Windows/Pi checks:18 installer contracts,10 ACK cases,5 storage tests,
3 legacy-position upgrade tests,8 GUI/core tests,10 mesh/process-interruption
tests and5 contention/full synthetic SQLite-restore tests. These are bounded
checks, not exhaustive security or workload coverage. No native recompilation
or general live-installation restoration is claimed.

## Known limitations

- Unattended X433 reconnection after reboot remains unresolved; extra reboot
  retesting was deferred.
- Full installation recovery of packages, ownership, services and radio settings
  is not accepted. Synthetic database restore passed; this is a narrower check.
- Legacy APRS-iGate v1/v2 queue migration has an unfixed `evaluated_epoch` index
  defect. APRS upgrades are outside this preview's supported installer scope.
- Optional unconfigured APRS modules can show degraded/unknown status.
- Remote Base status can display ON with stale details in production Field.
- Some error details remain English in Norwegian; old map rows can remain after
  invalid viewport input.
- Other radio combinations,868,Waveshare,RTL-SDR/APRS and map publication do not
  have equivalent installer acceptance here. The optional driver requires arm64
  and Python3.13. Other Pi models and32-bit systems are not accepted by this trial.

Production installations were not upgraded. All35 development-plan tracks remain;
the preview does not complete the development plan. Larger remaining control/code
review areas are not represented as exhaustively audited.
