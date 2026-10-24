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
