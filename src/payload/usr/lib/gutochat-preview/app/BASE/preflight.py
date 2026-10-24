"""Write-free beta2 update preflight analysis."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from branding import FORMER_PRODUCT_NAME, PRODUCT_NAME, TECHNICAL_APP_ID
from roles import infer_role_from_config, is_legacy_role


@dataclass(frozen=True)
class PreflightReport:
    """Summary of planned beta2 update without side effects."""

    product_name: str
    former_product_name: str
    technical_app_id: str
    program_dir: str
    config_dir: str
    backup_dir: str
    current_role: str
    proposed_role: str
    legacy_role: bool
    station_name: str
    station_id_present: bool
    retained_services: tuple[str, ...] = field(default_factory=tuple)
    retained_ports: tuple[int, ...] = field(default_factory=tuple)
    writes_files: bool = False
    changes_database: bool = False
    changes_services: bool = False
    changes_radio: bool = False
    changes_gps: bool = False
    changes_security: bool = False
    sends_messages: bool = False
    exports_positions: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable report for CLI, tests, or GUI display."""
        return {
            "product_name": self.product_name,
            "former_product_name": self.former_product_name,
            "technical_app_id": self.technical_app_id,
            "program_dir": self.program_dir,
            "config_dir": self.config_dir,
            "backup_dir": self.backup_dir,
            "current_role": self.current_role,
            "proposed_role": self.proposed_role,
            "legacy_role": self.legacy_role,
            "station_name": self.station_name,
            "station_id_present": self.station_id_present,
            "retained_services": list(self.retained_services),
            "retained_ports": list(self.retained_ports),
            "writes_files": self.writes_files,
            "changes_database": self.changes_database,
            "changes_services": self.changes_services,
            "changes_radio": self.changes_radio,
            "changes_gps": self.changes_gps,
            "changes_security": self.changes_security,
            "sends_messages": self.sends_messages,
            "exports_positions": self.exports_positions,
        }


def build_preflight_report(
    config: dict[str, Any],
    *,
    program_dir: str | Path | None = None,
    config_dir: str | Path | None = None,
    backup_dir: str | Path | None = None,
) -> PreflightReport:
    """Analyze beta2 update effects without writing anything."""
    home = Path.home()
    current_role = str(config.get("role") or "").strip().lower()
    proposed_role = infer_role_from_config(config)
    services = ["lorad-v2.service"]
    ports = [int(config.get("api_port", 8765))]
    if proposed_role == "base":
        services.extend(["meshbridge-v2.service", "meshbridge433-v2.service"])
        ports.extend([8766, 8767])
        for item in config.get("meshtastic_radios", []):
            if not isinstance(item, dict) or not item.get("enabled", True):
                continue
            route = str(item.get("route_key") or item.get("key") or "").strip().lower()
            try:
                api_port = int(item.get("api_port", 0))
            except (TypeError, ValueError):
                api_port = 0
            if route == "mesh433f" or api_port == 8768:
                if "meshbridge433f-v2.service" not in services:
                    services.append("meshbridge433f-v2.service")
                if 8768 not in ports:
                    ports.append(8768)

    station_name = str(
        config.get("station_name") or config.get("node_name") or "GuToChat station"
    )

    return PreflightReport(
        product_name=PRODUCT_NAME,
        former_product_name=FORMER_PRODUCT_NAME,
        technical_app_id=TECHNICAL_APP_ID,
        program_dir=str(program_dir or home / TECHNICAL_APP_ID),
        config_dir=str(config_dir or home / ".config" / TECHNICAL_APP_ID),
        backup_dir=str(backup_dir or home / f"{TECHNICAL_APP_ID}-backups"),
        current_role=current_role,
        proposed_role=proposed_role,
        legacy_role=is_legacy_role(current_role),
        station_name=station_name,
        station_id_present=bool(str(config.get("station_id") or "").strip()),
        retained_services=tuple(services),
        retained_ports=tuple(ports),
    )


def format_preflight_report(report: PreflightReport) -> str:
    """Return a human-readable, sanitized preflight summary."""
    legacy_note = "ja" if report.legacy_role else "nei"
    station_id = "finnes" if report.station_id_present else "mangler, vil foreslås"
    lines = [
        f"{report.product_name} 2.5.0-beta5 dry-run",
        f"Tidligere navn: {report.former_product_name}",
        "",
        "Installasjon:",
        f"- Programmappe: {report.program_dir}",
        f"- Config: {report.config_dir}",
        f"- Backup: {report.backup_dir}",
        "",
        "Rolle:",
        f"- Nåværende: {report.current_role or 'mangler'}",
        f"- Foreslått rolle: {report.proposed_role}",
        f"- Legacy-alias lest: {legacy_note}",
        "",
        "Stasjon:",
        f"- station_name: {report.station_name}",
        f"- station_id: {station_id}",
        "",
        "Tjenester som beholdes:",
        *[f"- {service}" for service in report.retained_services],
        "",
        "Porter som beholdes:",
        *[f"- {port}" for port in report.retained_ports],
        "",
        "Sikkerhet/personvern:",
        "- Radioinnstillinger endres ikke",
        "- Kanaloppsett endres ikke",
        "- PSK/private nøkler leses eller vises ikke",
        "- GPS/Meshtastic-posisjonsinnstillinger endres ikke",
        "- Ingen meldinger sendes",
        "- Ingen posisjon eksporteres",
        "",
        "Dry-run-resultat:",
        f"- Skriver filer: {report.writes_files}",
        f"- Endrer database: {report.changes_database}",
        f"- Endrer tjenester: {report.changes_services}",
        f"- Endrer radio: {report.changes_radio}",
        f"- Endrer GPS: {report.changes_gps}",
        f"- Endrer sikkerhet: {report.changes_security}",
        f"- Sender meldinger: {report.sends_messages}",
        f"- Eksporterer posisjon: {report.exports_positions}",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Run a write-free preflight report from the command line."""
    parser = argparse.ArgumentParser(description="GuToChat beta2 write-free preflight")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--program-dir", help="Program directory to display")
    parser.add_argument("--config-dir", help="Config directory to display")
    parser.add_argument("--backup-dir", help="Backup directory to display")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    args = parser.parse_args(argv)

    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    report = build_preflight_report(
        config,
        program_dir=args.program_dir,
        config_dir=args.config_dir,
        backup_dir=args.backup_dir,
    )
    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_preflight_report(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
