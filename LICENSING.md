# Licensing and matching source delivery

Project-owned GuToChat/GuToMap material retains the MIT licence in LICENSE and
original notices. Dependencies keep their component-specific licences.

Meshtastic Python2.7.9 is GPL-3.0-only and is imported in-process by the radio
components. The Meshtastic-enabled combined program is offered under GPLv3-only
terms, with original MIT permissions and all upstream notices preserved. Separate
DEB files do not make the imported library an independent program. The complete
delivery is not described as MIT-only. No third-party code is relicensed.

Full GPL text: [GPLv3](LICENSES/GPL-3.0.txt). Preserve the project MIT notice and
component notices when copying or distributing. Source access is part of the
release, not an optional paid service.

Publish the matching source/build ZIP next to BOTH binary packages, with hashes
and an accessible link from the same release. Do not publish the binaries alone.
RELEASE_ASSETS.json identifies exact files. The source ZIP includes exact project
and driver trees,15 upstream source archives and wheels, matching protocol schemas,
Google Protobuf/libyaml sources, upstream recipes and provenance. Driver4 installs
the additional libyaml,utf8_range and protocol notices.

The supplied tools reconstruct the DEBs; original wheels account for library bytes.
Native-library compilation from source has not been performed. This is not a claim
of complete legal clearance or exhaustive transitive notice review.

References: [GPLv3 sections1,5,6](https://www.gnu.org/licenses/gpl.en.html),
[GNU FAQ on combined modules](https://www.gnu.org/licenses/gpl-faq.en.html#GPLModuleLicense).
