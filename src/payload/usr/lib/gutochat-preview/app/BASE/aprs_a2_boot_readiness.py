#!/usr/bin/env python3
"""Fail-closed readiness probe for GuToChat APRS-A2 boot activation.

Exit status contract for systemd ExecCondition:
  0   readiness satisfied; A2 may start
  1   expected dependency not ready; skip A2 start without failure
  255 internal/probe contract error; fail the unit visibly

The probe intentionally does not write files or alter services/devices.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

READY = 0
NOT_READY = 1
PROBE_ERROR = 255


@dataclass(frozen=True)
class ProbeResult:
    ready: bool
    usb_present: bool
    alsa_card_present: bool
    capture_pcm_present: bool
    a1h_socket_ready: bool
    alsa_card_index: int | None
    reasons: tuple[str, ...]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").strip()


def _usb_matches(sys_root: Path, vendor: str, product: str) -> bool:
    usb_root = sys_root / "bus" / "usb" / "devices"
    if not usb_root.is_dir():
        return False

    vendor = vendor.lower()
    product = product.lower()

    for device in usb_root.iterdir():
        try:
            got_vendor = _read_text(device / "idVendor").lower()
            got_product = _read_text(device / "idProduct").lower()
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            continue
        if got_vendor == vendor and got_product == product:
            return True
    return False


def _alsa_card_index(proc_root: Path, card_name: str) -> int | None:
    cards = proc_root / "asound" / "cards"
    try:
        text = cards.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    except (PermissionError, OSError) as exc:
        raise RuntimeError(f"cannot read {cards}: {exc}") from exc

    # /proc/asound/cards format begins with e.g.:
    # " 2 [Device         ]: USB-Audio - USB Audio Device"
    pattern = re.compile(
        rf"^\s*(\d+)\s+\[{re.escape(card_name)}\s*\]\s*:",
        re.MULTILINE,
    )
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def _capture_pcm_exists(proc_root: Path, card_index: int, device: int) -> bool:
    return (proc_root / "asound" / f"card{card_index}" / f"pcm{device}c" / "info").is_file()


def _socket_ready(run_root: Path, socket_path: str) -> bool:
    path = Path(socket_path)
    if path.is_absolute():
        try:
            rel = path.relative_to("/run")
        except ValueError as exc:
            raise RuntimeError("A1H socket must be below /run") from exc
        path = run_root / rel
    else:
        path = run_root / path

    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return False
    except (PermissionError, OSError) as exc:
        raise RuntimeError(f"cannot stat A1H socket {path}: {exc}") from exc
    return stat.S_ISSOCK(mode)


def probe(
    *,
    sys_root: Path,
    proc_root: Path,
    run_root: Path,
    usb_vendor: str,
    usb_product: str,
    alsa_card: str,
    alsa_device: int,
    a1h_socket: str,
) -> ProbeResult:
    reasons: list[str] = []

    usb_present = _usb_matches(sys_root, usb_vendor, usb_product)
    if not usb_present:
        reasons.append("USB_0D8C_0016_NOT_PRESENT")

    card_index = _alsa_card_index(proc_root, alsa_card)
    card_present = card_index is not None
    if not card_present:
        reasons.append("ALSA_CARD_DEVICE_NOT_PRESENT")

    capture_present = False
    if card_index is not None:
        capture_present = _capture_pcm_exists(proc_root, card_index, alsa_device)
    if not capture_present:
        reasons.append("ALSA_CAPTURE_PCM0_NOT_PRESENT")

    socket_ready = _socket_ready(run_root, a1h_socket)
    if not socket_ready:
        reasons.append("A1H_AF_UNIX_SOCKET_NOT_READY")

    return ProbeResult(
        ready=not reasons,
        usb_present=usb_present,
        alsa_card_present=card_present,
        capture_pcm_present=capture_present,
        a1h_socket_ready=socket_ready,
        alsa_card_index=card_index,
        reasons=tuple(reasons),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sys-root", type=Path, default=Path("/sys"))
    parser.add_argument("--proc-root", type=Path, default=Path("/proc"))
    parser.add_argument("--run-root", type=Path, default=Path("/run"))
    parser.add_argument("--usb-vendor", default="0d8c")
    parser.add_argument("--usb-product", default="0016")
    parser.add_argument("--alsa-card", default="Device")
    parser.add_argument("--alsa-device", type=int, default=0)
    parser.add_argument("--a1h-socket", default="/run/gutochat-aprs-a2/a2-rx.sock")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.alsa_device < 0:
        print("A2_BOOT_READINESS=ERROR reason=INVALID_ALSA_DEVICE", file=sys.stderr)
        return PROBE_ERROR

    try:
        result = probe(
            sys_root=args.sys_root,
            proc_root=args.proc_root,
            run_root=args.run_root,
            usb_vendor=args.usb_vendor,
            usb_product=args.usb_product,
            alsa_card=args.alsa_card,
            alsa_device=args.alsa_device,
            a1h_socket=args.a1h_socket,
        )
    except Exception as exc:  # fail visibly on probe contract/runtime errors
        print(
            f"A2_BOOT_READINESS=ERROR type={type(exc).__name__} detail={exc}",
            file=sys.stderr,
        )
        return PROBE_ERROR

    if args.json:
        payload = asdict(result)
        payload["reasons"] = list(result.reasons)
        print(json.dumps(payload, sort_keys=True))
    elif result.ready:
        print(
            "A2_BOOT_READINESS=READY "
            f"usb=0d8c:0016 alsa_card={args.alsa_card} "
            f"card_index={result.alsa_card_index} capture_device={args.alsa_device} "
            "a1h_socket=READY"
        )
    else:
        print("A2_BOOT_READINESS=NOT_READY reasons=" + ",".join(result.reasons))

    return READY if result.ready else NOT_READY


if __name__ == "__main__":
    raise SystemExit(main())
