#!/usr/bin/env python3
"""Fail-closed measurement of the APRS receive-iGate runtime provenance.

This module performs only local file reads.  It does not open network sockets,
modify configuration, or write production state.  The returned provenance is
validated separately by the pinned iGate policy contract.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

from aprs_igate_policy_v1_rev2 import (
    EXPECTED_ADAPTER_SHA256,
    EXPECTED_DIREWOLF_ARCH,
    EXPECTED_DIREWOLF_BINARY_SHA256,
    EXPECTED_DIREWOLF_CONFIG_SHA256,
    EXPECTED_DIREWOLF_PACKAGE,
    EXPECTED_DIREWOLF_PACKAGE_VERSION,
    EXPECTED_PARSER_SHA256,
    RuntimeProvenance,
    runtime_provenance_fingerprint,
    runtime_provenance_matches_expected,
)

DIREWOLF_BINARY = Path('/usr/bin/direwolf')
DIREWOLF_CONFIG = Path('/etc/gutochat/direwolf-a2-rtl-rx-only.conf')
APP = Path('/var/lib/gutochat-preview/legacy-disabled/lorachat-v2/app')
PARSER = APP / 'a2_ingress_parser_v1.py'
ADAPTER = APP / 'a2_adapter_process_v1_rev3.py'
DPKG_QUERY = Path('/usr/bin/dpkg-query')


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _package_metadata(package_query=None) -> tuple[str, str]:
    if package_query is None:
        def package_query():
            result = subprocess.run(
                [
                    str(DPKG_QUERY),
                    '-W',
                    '-f=${db:Status-Status}\n${Version}\n${Architecture}\n',
                    EXPECTED_DIREWOLF_PACKAGE,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            return result.returncode, result.stdout, result.stderr
    rc, stdout, _stderr = package_query()
    if rc != 0:
        raise RuntimeError('DIREWOLF_PACKAGE_QUERY_FAILED')
    lines = stdout.splitlines()
    if len(lines) < 3 or lines[0].strip() != 'installed':
        raise RuntimeError('DIREWOLF_PACKAGE_NOT_INSTALLED_OR_INCOMPLETE')
    return lines[1].strip(), lines[2].strip()


def measure_runtime_provenance(
    *,
    direwolf_binary: Path = DIREWOLF_BINARY,
    direwolf_config: Path = DIREWOLF_CONFIG,
    parser_path: Path = PARSER,
    adapter_path: Path = ADAPTER,
    package_query=None,
) -> RuntimeProvenance:
    """Measure the production runtime identity on every safety boundary.

    The package name is a pinned policy target.  Version and architecture are
    read from dpkg-query, while binary/config/parser/adapter identities are
    measured from the actual local files.  Any missing/unreadable artifact or
    package-metadata failure raises and therefore fails closed.
    """
    package_version, architecture = _package_metadata(package_query)
    return RuntimeProvenance(
        direwolf_package=EXPECTED_DIREWOLF_PACKAGE,
        direwolf_package_version=package_version,
        direwolf_architecture=architecture,
        direwolf_binary_sha256=_sha256_file(Path(direwolf_binary)),
        direwolf_config_sha256=_sha256_file(Path(direwolf_config)),
        parser_sha256=_sha256_file(Path(parser_path)),
        adapter_sha256=_sha256_file(Path(adapter_path)),
    )


def measured_expected_fingerprint(**kwargs) -> str:
    provenance = measure_runtime_provenance(**kwargs)
    if not runtime_provenance_matches_expected(provenance):
        raise RuntimeError('RUNTIME_PROVENANCE_MISMATCH')
    return runtime_provenance_fingerprint(provenance)


def self_check() -> dict[str, object]:
    return {
        'network_access': False,
        'write_access': False,
        'direwolf_binary_expected_sha256': EXPECTED_DIREWOLF_BINARY_SHA256,
        'direwolf_config_expected_sha256': EXPECTED_DIREWOLF_CONFIG_SHA256,
        'parser_expected_sha256': EXPECTED_PARSER_SHA256,
        'adapter_expected_sha256': EXPECTED_ADAPTER_SHA256,
    }
