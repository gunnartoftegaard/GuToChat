#!/usr/bin/env python3

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_PARSER_SHA256 = (
    "7275935613b6bad8441295b2f7c1885b"
    "159362efd05339c80c4302f82ae34422"
)

EXPECTED_SCHEMA = "gutchat.aprs.rx.v1"
LEGACY_PARSER_DECODER_LABEL = "1.7+dfsg-2build2"
DECODER_MONITOR_CONTRACT = "direwolf-1.7-aprs-monitor-v1"
EXPECTED_DIREWOLF_PACKAGE = "direwolf"
EXPECTED_DIREWOLF_PACKAGE_VERSION = "1.7+dfsg-2+deb13u1"
EXPECTED_DIREWOLF_ARCH = "arm64"
EXPECTED_DIREWOLF_BINARY = Path("/usr/bin/direwolf")
EXPECTED_DIREWOLF_BINARY_SHA256 = (
    "4b7d53b5bd4d7d1fe6819a780bbdd680605d2263539dca36dca7b3d9e3637305"
)
QUARANTINE_SCHEMA = "gutchat.aprs.rx.quarantine.v1"

MAX_INPUT_BYTES = 8192


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def load_pinned_parser(parser_path_text):
    parser_path = Path(parser_path_text)

    try:
        content = parser_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"parser unavailable: {exc}") from exc

    actual = hashlib.sha256(content).hexdigest()

    if actual != EXPECTED_PARSER_SHA256:
        raise RuntimeError(
            "parser SHA256 mismatch: "
            f"expected={EXPECTED_PARSER_SHA256} actual={actual}"
        )

    spec = importlib.util.spec_from_file_location(
        "a2_ingress_parser_v1",
        parser_path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("could not create parser import specification")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if getattr(module, "SCHEMA", None) != EXPECTED_SCHEMA:
        raise RuntimeError("parser schema contract mismatch")

    # The pinned parser still contains a historical distro-version-like label.
    # It is retained only as a parser identity invariant and MUST NOT be used
    # as decoder runtime provenance.  The adapter replaces that event field
    # with collected package/binary provenance below.
    if (
        getattr(module, "DECODER_VERSION_CONTRACT", None)
        != LEGACY_PARSER_DECODER_LABEL
    ):
        raise RuntimeError("parser legacy decoder-label invariant mismatch")

    if not hasattr(module, "parse_direwolf_line"):
        raise RuntimeError("parser entry point missing")

    if not hasattr(module, "ParseError"):
        raise RuntimeError("parser ParseError contract missing")

    return module



def _sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_decoder_runtime_provenance(
    *,
    binary_path=EXPECTED_DIREWOLF_BINARY,
    package_query=None,
):
    """Collect decoder provenance without making A2 receive depend on it.

    Exact-match provenance is marked verified. Any package/hash/metadata
    mismatch becomes unverified evidence for the future iGate policy, while
    classic A2 receive remains available.
    """
    package = EXPECTED_DIREWOLF_PACKAGE
    package_version = None
    architecture = None
    binary_sha256 = None
    reasons = []

    path = Path(binary_path)
    try:
        if path.is_file():
            binary_sha256 = _sha256_file(path)
        else:
            reasons.append("binary_unavailable")
    except Exception as exc:
        reasons.append("binary_hash_error:" + type(exc).__name__)

    if package_query is None:
        def package_query():
            result = subprocess.run(
                [
                    "/usr/bin/dpkg-query",
                    "-W",
                    "-f=${db:Status-Status}\\n${Version}\\n${Architecture}\\n",
                    EXPECTED_DIREWOLF_PACKAGE,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return result.returncode, result.stdout, result.stderr

    try:
        rc, stdout, stderr = package_query()
        if rc != 0:
            reasons.append("package_query_failed")
        else:
            lines = stdout.splitlines()
            if len(lines) < 3:
                reasons.append("package_metadata_incomplete")
            else:
                status = lines[0].strip()
                package_version = lines[1].strip()
                architecture = lines[2].strip()
                if status != "installed":
                    reasons.append("package_not_installed")
    except Exception as exc:
        reasons.append("package_query_error:" + type(exc).__name__)

    if package_version != EXPECTED_DIREWOLF_PACKAGE_VERSION:
        reasons.append("package_version_mismatch")
    if architecture != EXPECTED_DIREWOLF_ARCH:
        reasons.append("architecture_mismatch")
    if binary_sha256 != EXPECTED_DIREWOLF_BINARY_SHA256:
        reasons.append("binary_sha256_mismatch")

    verified = len(reasons) == 0
    return {
        "package": package,
        "package_version": package_version,
        "architecture": architecture,
        "binary_sha256": binary_sha256,
        "monitor_contract": DECODER_MONITOR_CONTRACT if verified else None,
        "provenance_status": "verified" if verified else "unverified",
        "provenance_reasons": tuple(reasons),
    }


def attach_decoder_runtime_provenance(event, runtime):
    """Replace the legacy parser label with collected runtime provenance."""
    if not isinstance(event, dict):
        raise RuntimeError("normalized event is not an object")
    decoder = event.get("decoder")
    if not isinstance(decoder, dict) or decoder.get("name") != "direwolf":
        raise RuntimeError("normalized event decoder metadata invalid")

    out = dict(event)
    dec = dict(decoder)
    dec.pop("version_contract", None)
    dec.update({
        "package": runtime.get("package"),
        "package_version": runtime.get("package_version"),
        "architecture": runtime.get("architecture"),
        "binary_sha256": runtime.get("binary_sha256"),
        "monitor_contract": runtime.get("monitor_contract"),
        "provenance_status": runtime.get("provenance_status", "unverified"),
    })
    reasons = runtime.get("provenance_reasons") or ()
    if reasons:
        dec["provenance_reasons"] = list(reasons)
    out["decoder"] = dec
    return out

def quarantine(reason, line_no, raw_preview=None):
    record = {
        "schema": QUARANTINE_SCHEMA,
        "line_number": line_no,
        "reason": reason,
    }

    if raw_preview is not None:
        record["raw_preview"] = raw_preview[:256]

    sys.stderr.write(canonical_json(record) + "\n")
    sys.stderr.flush()


def disable_stdout_after_broken_pipe():
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, sys.stdout.fileno())
        os.close(fd)
    except Exception:
        pass


def write_event(event):
    try:
        sys.stdout.write(canonical_json(event) + "\n")
        sys.stdout.flush()
        return True
    except BrokenPipeError:
        disable_stdout_after_broken_pipe()
        sys.stderr.write("A2_ADAPTER_ERROR=DOWNSTREAM_BROKEN_PIPE\n")
        sys.stderr.flush()
        return False


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--parser",
        required=True,
        help="Path to hash-pinned approved A2 ingress parser.",
    )

    ap.add_argument(
        "--verification-received-at",
        default=None,
    )

    ap.add_argument(
        "--self-check",
        action="store_true",
    )

    args = ap.parse_args()

    try:
        parser = load_pinned_parser(args.parser)
    except Exception as exc:
        sys.stderr.write(
            "A2_ADAPTER_FATAL=PARSER_CONTRACT_FAILURE "
            + str(exc)
            + "\n"
        )
        return 40

    decoder_runtime = collect_decoder_runtime_provenance()
    if decoder_runtime["provenance_status"] != "verified":
        sys.stderr.write(
            "A2_ADAPTER_DECODER_PROVENANCE=UNVERIFIED reasons="
            + ",".join(decoder_runtime.get("provenance_reasons", ()))
            + "\n"
        )
        sys.stderr.flush()

    if args.self_check:
        print("A2_ADAPTER_SELF_CHECK=PASS")
        print("PARSER_SHA256=" + EXPECTED_PARSER_SHA256)
        print("SCHEMA=" + EXPECTED_SCHEMA)
        print("LEGACY_PARSER_DECODER_LABEL=" + LEGACY_PARSER_DECODER_LABEL)
        print("DECODER_PROVENANCE_STATUS=" + decoder_runtime["provenance_status"])
        print("DIREWOLF_PACKAGE_VERSION=" + str(decoder_runtime["package_version"]))
        print("DIREWOLF_BINARY_SHA256=" + str(decoder_runtime["binary_sha256"]))
        print("DECODER_MONITOR_CONTRACT=" + str(decoder_runtime["monitor_contract"]))
        return 0

    line_no = 0

    for raw_line in sys.stdin.buffer:
        line_no += 1

        if len(raw_line) > MAX_INPUT_BYTES:
            quarantine("input line exceeds byte limit", line_no)
            return 20

        try:
            line = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            quarantine("invalid UTF-8 input", line_no)
            return 20

        received_at = (
            args.verification_received_at
            if args.verification_received_at is not None
            else utc_now_iso()
        )

        try:
            event = parser.parse_direwolf_line(line, received_at)
        except parser.ParseError as exc:
            quarantine(
                str(exc),
                line_no,
                line.rstrip("\r\n"),
            )
            return 21
        except Exception as exc:
            quarantine(
                "unexpected parser exception: " + type(exc).__name__,
                line_no,
                line.rstrip("\r\n"),
            )
            return 22

        if event is None:
            continue

        try:
            event = attach_decoder_runtime_provenance(event, decoder_runtime)
        except Exception as exc:
            quarantine("decoder provenance attachment failure: " + str(exc), line_no)
            return 24

        if event.get("schema") != EXPECTED_SCHEMA:
            quarantine("unexpected normalized schema", line_no)
            return 23

        if event.get("direction") != "rx":
            quarantine("non-RX event rejected", line_no)
            return 23

        if not write_event(event):
            return 32

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
