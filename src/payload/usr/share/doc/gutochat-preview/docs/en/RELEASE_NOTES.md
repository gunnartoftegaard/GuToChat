# Candidate18 – prepared, not installed

Application2.5.0~preview20261024.18docs1; unchanged driver4.
Legacy position-history tables receive nullable ingested_epoch before index
creation, under a serialized initialization transaction. All prior values are
retained; no synthetic historical ingestion time is backfilled. Three isolated
upgrade/retention tests for both roles pass locally and on Pi. Candidate17
remains the installed, GUI-accepted test baseline.

Updated bilingual GitHub documentation is now included in the application
package. Source/build inputs and the local repository draft are version-aligned.
No new installation, physical RF/sync or reboot acceptance claimed.

Legacy APRS-iGate v1/v2 queues have a separate confirmed evaluated_epoch index
migration defect. APRS upgrades are not accepted in this limited installer scope;
no production database was inspected or modified by the synthetic reproduction.
Remaining code review/operational gates and the public release decision remain open.


## Kandidat 17 / Candidate 17

# Release notes – candidate 17

Application `2.5.0~preview20261024.17sync1`; optional driver `2.7.9~gutochat20261024.4`.
Draft for a limited preview. No public release has been created.

- Candidate 15 fixed non-finite/extreme longitude handling.
- Candidate 16 fixed loss of very early recipient acknowledgements in both roles.
- Candidate 17 serializes Field message-sync cursor validation and page storage.
- Driver 4 includes additional notices; library bytes are unchanged from driver 3.
- The earlier Base startup fix and separate Base/Field storage implementations are retained.

Test platform: Raspberry Pi 5, Debian 13 aarch64, Python 3.13.5. Candidate 17 is installed;
839 payload files and configuration/data retention were verified. Both GUIs open,
Base in Norwegian and Field in English, and display database OK after full checks.
18 installer contracts, five storage tests and ten acknowledgement checks pass locally
and in isolation on the Pi. X433/T433 physical ACK/reply was accepted in candidate 16.
No new 17 RF-message, physical Field-sync or reboot acceptance is claimed.

## Known limitations

- Unattended X433 reconnection after reboot remains unresolved; the user deferred reboot retesting.
- Periodic SQLite contention and complete restart/replay/operational restore are not finally accepted.
- Unconfigured optional test modules may display DEGRADED/unknown rather than OFF/not configured.
- Production Field received Base status ON after refresh but still marked it stale; cause unconfirmed.
- Some error details remain English in Norwegian GUI; old map rows may remain after invalid viewport input.
- Other radio combinations,868,Waveshare,SDR/APRS and map publication lack equivalent installer acceptance.

Production machines are separate installations. Test-Pi functionality does not mean
production has been upgraded. All 35 roadmap tracks and preserved development history
remain; the preview does not complete the full development plan.
