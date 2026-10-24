# GuToChat

GuToChat provides Base and Field roles. You can install and open the core without
a radio. Radio messaging requires a selected, configured adapter.

Candidate 18 (`2.5.0~preview20261024.18docs1`, driver 4) passed an upgrade trial
on Raspberry Pi 5, Debian 13 arm64, Python 3.13. The user confirmed GUI opening,
recipient acknowledgement and a reply over the test 433-MHz Meshtastic route.
This is a limited experimental preview; see the scope and known limitations.
Download the [prerelease and matching sources](https://github.com/gunnartoftegaard/GuToChat/releases/tag/v2.5.0-preview18).

- [Installation](docs/en/INSTALLATION.md)
- [Operation and upgrades](docs/en/OPERATION_AND_UPGRADES.md)
- [Troubleshooting](docs/en/TROUBLESHOOTING.md)
- [Release notes and tested scope](docs/en/RELEASE_NOTES.md)
- [Build from source](BUILDING.md)
- [Licensing and source delivery](LICENSING.md)
- [Release assets and hashes](RELEASE_ASSETS.json)
- [Norsk](README_NO.md)

`src/` is the exact source snapshot of the tested package. Its manifest and
packaged documentation are preserved as shipped; the repository guides above
record later acceptance. The companion source/build ZIP includes both package
trees and matching upstream sources, wheels, notices and build inputs.

Project-owned files retain MIT permissions. The Meshtastic-enabled combined
program is distributed under GPLv3-only terms; this is not an MIT-only bundle.
See LICENSING.md and the component notices.

All 35 development-plan tracks are retained; this preview does not implement
the whole plan. Contact: post@gutochat.no. [Website](https://www.gutochat.no/en/).
[Repository](https://github.com/gunnartoftegaard/GuToChat).
PayPal/GitHub Sponsors remain planned; no payment destination is supplied.
