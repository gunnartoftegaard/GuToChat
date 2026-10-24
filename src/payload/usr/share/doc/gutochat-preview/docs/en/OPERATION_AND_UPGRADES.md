# Operation, upgrades and removal

Draft for candidate 17sync1. Private test-machine helper scripts are not general installation tools.

## Before upgrading

Close affected GUI windows. Back up program versions, settings, radio registration and consistent databases. Copying only an active SQLite main file is not a sufficient description of a consistent backup. The internal trial backup was verified; a general operational restore procedure remains an open roadmap item.

Install only verified packages for the intended release. Candidate example, from their directory:

```bash
sudo apt-get --no-remove install ./gutochat-candidate-r18.deb ./gutochat-driver-r4.deb
```

Include the driver only when used and compatible with the machine. The upgrade stops the trial setups. Check that package installation completed successfully before resuming. Do not use the old 13release1/driver2 packages; they had a known unpacking failure.

## Resume

Open the setup wizard on the local desktop, select the correct role and choose “Resume setup”. Resume each installed role separately. Alternatively, for an existing role:

```bash
sudo /usr/bin/python3 -I /usr/lib/gutochat-preview/admin.py resume base
```

Replace the final word with `field` when needed. Check status, retained messages and any radio acknowledgement/reply before normal operation. An active service alone does not establish a working radio connection.

## Deactivate or remove

“Deactivate setup” stops the selected role while retaining settings and data. “Resume setup” activates it again. Removing the program is a separate action:

```bash
sudo apt-get remove gutochat-preview
```

Removal/reinstall retention was tested with the earlier 12radio6 candidate. A complete new removal/reinstall trial has not been performed for 14. Candidate14 upgrade retention was verified. Do not manually delete data directories, use purge/autoremove or downgrade blindly as a routine repair.

Settings: `/etc/gutochat-preview/`. Role data: `/var/lib/gutochat-preview/data/base/` and `/var/lib/gutochat-preview/data/field/`. These may contain private information; do not attach them to public GitHub issues or source distributions.
