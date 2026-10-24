# Troubleshooting

## No password dialog

Run the wizard as an ordinary user in Terminal on the machine's own desktop. Authentication from a remotely launched GUI was previously observed to fail. A missing or cancelled password dialog does not mean the operation completed. Do not send passwords to the project or disable administrator authentication as a workaround.

## “Unsupported file”

Check the exact filename, directory and that the package exists. Use the full path or `./filename.deb` from the correct directory. Do not paste explanatory prose into the command. An earlier trial used a shorter filename; this does not prove that every such error has the same cause.

## Missing USB device

Power does not establish USB data connectivity. Check the USB data cable, port and registered stable identity. Change one part at a time. Verify firmware and the actual hardware band separately; do not automatically flash or change bands to fix USB detection. Generic serial numbers may be shared by several devices.

## Service active but no messages

Check connection status, queue and recipient acknowledgement. Avoid a simultaneous client connection to the Base radio itself. Investigate repeated unacknowledged transmissions before adding more test messages. Acceptance requires both acknowledgement and a reply.

During one test-Pi reboot, X433 failed to reconnect until a button press. Power saving was read as disabled and role as CLIENT. The cause remains unresolved; “disable sleep” is not an established fix. Further reboot testing was deferred at the user's request.

## Local database needs checking

Read the detail text. “not_run” is not the same as detected corruption. For an actual “database disk image is malformed” error, preserve the affected data and identify the files before maintenance or overwriting. A historical map-database incident and today's core-database checks are different evidence.

When reporting an issue, include version, OS, role, hardware, steps and exact error text. Remove message content, precise private positions, databases, keys and passwords from public attachments. Contact: post@gutochat.no. Website: https://www.gutochat.no/en/.
