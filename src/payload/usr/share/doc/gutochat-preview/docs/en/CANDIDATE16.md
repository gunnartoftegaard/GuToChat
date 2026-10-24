Historical candidate note; see README and release notes for current status.

# Candidate 16 – acknowledgements and matching sources

Internal candidate, not published. Application 2.5.0~preview20261024.16ack1;
optional driver 2.7.9~gutochat20261024.4.

Fixed a confirmed ordering defect in both roles' send_text: a response during
message storage could be processed before its pending row existed and be lost.
The callback now sees the packet ID only after pending registration completes;
earlier responses are buffered under the existing lock.

Ten isolated checks pass locally and on the test Pi using Python 3.13.5. Four
failure cases were first reproduced against candidate 15. This is not a new
physical radio trial or proof of the cause of earlier USB failures.

Driver libraries are byte-identical to driver 3; only version and documentation
change. Three additional notices are now installed in the driver package.
The companion kit collects 15 sdists, wheels, protocol definitions, Google
Protobuf sources, libyaml sources and build inputs.

Candidate 15 map/help acceptance remains historical evidence. Candidate 16 is
not installed or physically accepted. No new reboot trial was performed;
unresolved X433 reconnection after reboot and other operational checks remain.
Remaining code review and the final publication decision are still open.
All 35 roadmap tracks and the earlier Base startup fix remain preserved.
