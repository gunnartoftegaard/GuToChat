# Installing the preview

Guide for candidate 18docs1 (not installed yet) and driver 4. Material is prepared locally; no public download has been created.

## Requirements

The documented physical trial used a Raspberry Pi 5 with 64-bit Debian 13, Python 3.13, systemd and a local desktop. Use an ordinary account with access to administrator authentication. This trial does not establish support for other Pi models, 32-bit systems or other operating systems. The package also permits Ubuntu 24.04, but this report does not establish equivalent hardware acceptance there.

No Waveshare, Meshtastic or RTL-SDR device is required to install and open the core setup. Without a radio adapter, there is no radio messaging route. Install Base, Field or both; their settings and data are separate. A role does not require a particular radio model.

## Install the core package

Use packages and verified checksums from the same release. Open Terminal in the directory containing the verified package:

```bash
sudo apt-get --no-remove install ./gutochat-candidate-r18.deb
```

This filename belongs to the current candidate. Enter your own administrator password locally. The package manager may obtain declared system dependencies from the operating system's repositories. Investigate unexpected removals or major unrelated changes. Do not copy internal test helpers or production databases into a fresh installation.

## Create a setup

Open “GuToChat Preview Setup” from the applications menu, or run this on the local desktop without sudo:

```bash
/usr/bin/python3 -I /usr/lib/gutochat-preview/setup_ui.py
```

Select Norsk or English and Base or Field. Choose “Install new setup”, check the role in the confirmation dialog and authenticate locally. Wait for “The operation is complete”. Close the wizard yourself afterwards. Repeat for the other role only if wanted.

Do not use “Install new setup” to overwrite an existing setup. Use “Resume setup” after a controlled upgrade or reinstall. See [operation and upgrades](OPERATION_AND_UPGRADES.md).

## Open and check

Open Base or Field from the applications menu. Alternatively:

```bash
/usr/bin/python3 -I /usr/lib/gutochat-preview/gui_entry.py base
```

Replace the final word with `field` for Field. Run the GUI as an ordinary user. Check System status and “Setup and devices”. Background services and GUI windows are separate: automatic service startup does not establish automatic GUI startup.

## Optional Meshtastic radio

The bundled driver candidate targets arm64 and Python 3.13. Install it only for that combination:

```bash
sudo apt-get --no-remove install ./gutochat-driver-r4.deb
```

Physical radio acceptance covers one Base-connected Heltec V3 with a separately verified 433-MHz configuration and a T433 peer. Registering/selecting a device in GuToChat does not flash firmware or automatically configure region, channel, antenna or transmit power. Check those separately before use. Do not copy settings between different bands without separate verification.

Use the stable USB identity in the radio wizard and “Setup and devices”. Register the radio, select it, save the row, check installation and apply through the confirmed action that closes the GUI. Then check recipient acknowledgement and a reply. Avoid another client taking over the Base radio connection concurrently.

Unattended X433 reconnection after reboot is unresolved. See [release notes](RELEASE_NOTES.md). Multiple radios, a Field-local radio, Waveshare, SDR/APRS and map publication do not have equivalent installer acceptance for this candidate.

## Database check

CHECK with “Integrity not_run” means the application has no recorded integrity
result. It does not itself establish database corruption. An external check
and the application's recorded check are different. Under “Operations and
queue”, choose “Run database maintenance” for a full check, wait for completion
and reopen System status. “Run self-test” checks connections and does not
replace the database check.
