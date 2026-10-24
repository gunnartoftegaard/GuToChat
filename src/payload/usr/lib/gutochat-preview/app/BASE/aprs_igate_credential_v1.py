#!/usr/bin/env python3
"""C4.2 systemd credential loader for the GuToChat APRS-IS uplink.

The credential value is deliberately never represented in exceptions, status
objects or repr output.  The only supported runtime source is the directory
exported by systemd in CREDENTIALS_DIRECTORY.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

CREDENTIAL_VERSION = "gutochat.aprs.igate.credential.c4.2.v1"
DEFAULT_CREDENTIAL_NAME = "aprs-is-passcode"
MAX_CREDENTIAL_BYTES = 64
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PASS_RE = re.compile(r"^[0-9]{1,5}$")


class CredentialError(RuntimeError):
    pass


def _validate_name(name: str) -> str:
    value = str(name)
    if not _NAME_RE.fullmatch(value):
        raise CredentialError("CREDENTIAL_NAME_INVALID")
    return value


def validate_aprs_is_passcode(value: str) -> str:
    # APRS-IS runtime credential must be a verified-login numeric passcode.
    # -1 is intentionally impossible here.
    text = str(value)
    if not _PASS_RE.fullmatch(text):
        raise CredentialError("CREDENTIAL_VALUE_INVALID_FORMAT")
    number = int(text, 10)
    if not (0 <= number <= 32767):
        raise CredentialError("CREDENTIAL_VALUE_OUT_OF_RANGE")
    return text


def load_systemd_credential(
    name: str = DEFAULT_CREDENTIAL_NAME,
    *,
    environ: dict[str, str] | None = None,
) -> str:
    env = os.environ if environ is None else environ
    checked_name = _validate_name(name)
    directory_text = env.get("CREDENTIALS_DIRECTORY", "")
    if not directory_text:
        raise CredentialError("CREDENTIALS_DIRECTORY_ABSENT")
    directory = Path(directory_text)
    if not directory.is_absolute():
        raise CredentialError("CREDENTIALS_DIRECTORY_NOT_ABSOLUTE")
    try:
        dst = directory / checked_name
        st = dst.lstat()
    except OSError as exc:
        raise CredentialError("CREDENTIAL_FILE_UNAVAILABLE") from exc
    if stat.S_ISLNK(st.st_mode):
        raise CredentialError("CREDENTIAL_FILE_SYMLINK_FORBIDDEN")
    if not stat.S_ISREG(st.st_mode):
        raise CredentialError("CREDENTIAL_FILE_NOT_REGULAR")
    if st.st_size <= 0 or st.st_size > MAX_CREDENTIAL_BYTES:
        raise CredentialError("CREDENTIAL_FILE_SIZE_INVALID")
    try:
        raw = dst.read_bytes()
    except OSError as exc:
        raise CredentialError("CREDENTIAL_FILE_READ_FAILED") from exc
    if b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        raise CredentialError("CREDENTIAL_VALUE_INVALID_FORMAT")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CredentialError("CREDENTIAL_VALUE_NOT_ASCII") from exc
    return validate_aprs_is_passcode(text)


def credential_status(name: str = DEFAULT_CREDENTIAL_NAME, *, environ=None) -> dict[str, object]:
    # Intentionally returns only presence/validity metadata, never the value.
    try:
        load_systemd_credential(name, environ=environ)
    except CredentialError as exc:
        return {"credential_name": str(name), "available": False, "reason": str(exc)}
    return {"credential_name": str(name), "available": True, "reason": "OK"}
