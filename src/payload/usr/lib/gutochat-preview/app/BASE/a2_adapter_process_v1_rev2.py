#!/usr/bin/env python3

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_PARSER_SHA256 = (
    "7275935613b6bad8441295b2f7c1885b"
    "159362efd05339c80c4302f82ae34422"
)

EXPECTED_SCHEMA = "gutchat.aprs.rx.v1"
EXPECTED_DECODER_VERSION = "1.7+dfsg-2build2"
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

    if (
        getattr(module, "DECODER_VERSION_CONTRACT", None)
        != EXPECTED_DECODER_VERSION
    ):
        raise RuntimeError("parser decoder-version contract mismatch")

    if not hasattr(module, "parse_direwolf_line"):
        raise RuntimeError("parser entry point missing")

    if not hasattr(module, "ParseError"):
        raise RuntimeError("parser ParseError contract missing")

    return module


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

    if args.self_check:
        print("A2_ADAPTER_SELF_CHECK=PASS")
        print("PARSER_SHA256=" + EXPECTED_PARSER_SHA256)
        print("SCHEMA=" + EXPECTED_SCHEMA)
        print("DECODER_VERSION_CONTRACT=" + EXPECTED_DECODER_VERSION)
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
