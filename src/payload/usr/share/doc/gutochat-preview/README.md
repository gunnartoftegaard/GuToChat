# GuToChat

GuToChat provides Base and Field roles. The core requires no mandatory radio;
a radio messaging route requires a selected, configured adapter.

Current source draft: candidate 18docs1 with driver 4. Candidate18 is not installed
or publicly released. The last physically checked test build is 17sync1 on
Raspberry Pi 5, Debian 13 aarch64, Python 3.13. See release notes for precise evidence.

- [Installation](docs/en/INSTALLATION.md)
- [Operation and upgrades](docs/en/OPERATION_AND_UPGRADES.md)
- [Troubleshooting](docs/en/TROUBLESHOOTING.md)
- [Release notes and limitations](docs/en/RELEASE_NOTES.md)
- [Build from source](BUILDING.md)
- [Licensing and source delivery](LICENSING.md)
- [Norsk](README_NO.md)

src contains exact candidate 18 project files with a manifest. Public-facing
guides and packaged guides are aligned. Legacy position history receives an
additive upgrade in both roles; driver and other runtime logic remain unchanged
from 17. Legacy APRS-iGate queues have a separate unfixed migration defect and
are not accepted for upgrades here. Remaining code/operational checks and the
concrete publication decision remain open. All 35 roadmap tracks are retained.

Contact: post@gutochat.no. [Website](https://www.gutochat.no/en/).
[Repository](https://github.com/gunnartoftegaard/GuToChat).
PayPal/GitHub Sponsors remain planned, without unverified funding links.
