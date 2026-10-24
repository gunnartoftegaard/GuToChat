#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


CONTACT_FORMAT = "lorachat-contacts"
CONTACT_FORMAT_VERSION = 1


class ContactBook:
    """Small local address book layered on top of discovered radio nodes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict[str, dict[str, Any]]] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.data = raw
        except FileNotFoundError:
            self.data = {}
        except Exception:
            self.data = {}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def entry(self, network: str, node_id: str) -> dict[str, Any]:
        return self.data.setdefault(network, {}).setdefault(node_id, {})

    def alias(self, network: str, node_id: str) -> str:
        return str(self.data.get(network, {}).get(node_id, {}).get("alias", ""))

    def favorite(self, network: str, node_id: str) -> bool:
        return bool(
            self.data.get(network, {}).get(node_id, {}).get("favorite", False)
        )

    def set_alias(self, network: str, node_id: str, alias: str) -> None:
        self.entry(network, node_id)["alias"] = alias.strip()
        self.save()

    def set_favorite(self, network: str, node_id: str, favorite: bool) -> None:
        self.entry(network, node_id)["favorite"] = bool(favorite)
        self.save()

    def rows(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for network, nodes in sorted(self.data.items()):
            if not isinstance(nodes, dict):
                continue
            for node_id, entry in sorted(nodes.items()):
                if not isinstance(entry, dict):
                    continue
                result.append(
                    {
                        "network": str(network),
                        "node_id": str(node_id),
                        "alias": str(entry.get("alias", "")),
                        "favorite": bool(entry.get("favorite", False)),
                    }
                )
        return result

    def export_payload(
        self, node_metadata: Iterable[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        metadata: dict[tuple[str, str], dict[str, Any]] = {}
        for item in node_metadata or []:
            network = str(item.get("network", ""))
            node_id = str(item.get("node_id", ""))
            if network and node_id:
                metadata[(network, node_id)] = dict(item)
        contact_rows = {
            (row["network"], row["node_id"]): row for row in self.rows()
        }
        # A manually entered node is a contact even before the user assigns an
        # alias or favorite flag. Discovered-only nodes are not exported unless
        # they have an explicit contact-book entry.
        for key, extra in metadata.items():
            if bool(extra.get("manual")) and key not in contact_rows:
                contact_rows[key] = {
                    "network": key[0],
                    "node_id": key[1],
                    "alias": "",
                    "favorite": False,
                }
        contacts: list[dict[str, Any]] = []
        for key in sorted(contact_rows):
            row = contact_rows[key]
            extra = metadata.get(key, {})
            contacts.append(
                {
                    **row,
                    "long_name": str(extra.get("long_name", "")),
                    "short_name": str(extra.get("short_name", "")),
                }
            )
        return {
            "format": CONTACT_FORMAT,
            "version": CONTACT_FORMAT_VERSION,
            "exported_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "contacts": contacts,
        }

    def export_file(
        self, path: Path, node_metadata: Iterable[dict[str, Any]] | None = None
    ) -> int:
        payload = self.export_payload(node_metadata)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
        return len(payload["contacts"])

    def import_payload(
        self, payload: dict[str, Any], *, replace: bool = False
    ) -> list[dict[str, Any]]:
        if payload.get("format") != CONTACT_FORMAT:
            raise ValueError("Filen er ikke en GuToChat / LoRa Chat-kontaktfil")
        if int(payload.get("version", 0)) != CONTACT_FORMAT_VERSION:
            raise ValueError("Kontaktfilen har en ukjent formatversjon")
        contacts = payload.get("contacts")
        if not isinstance(contacts, list):
            raise ValueError("Kontaktfilen mangler kontaktlisten")
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(contacts, start=1):
            if not isinstance(raw, dict):
                raise ValueError(f"Kontakt {index} er ikke et JSON-objekt")
            network = str(raw.get("network", "")).strip()
            node_id = str(raw.get("node_id", "")).strip().lower()
            if not network or not node_id:
                raise ValueError(f"Kontakt {index} mangler nettverk eller node-ID")
            if network == "waveshare":
                if not node_id.isdecimal() or not 1 <= int(node_id) <= 65535:
                    raise ValueError(
                        f"Kontakt {index} har ugyldig Waveshare-adresse: {node_id}"
                    )
                node_id = str(int(node_id))
            else:
                if not node_id.startswith("!"):
                    node_id = "!" + node_id
                if not re.fullmatch(r"![0-9a-f]{8}", node_id):
                    raise ValueError(
                        f"Kontakt {index} har ugyldig Meshtastic-node-ID: {node_id}"
                    )
            favorite = raw.get("favorite", False)
            if not isinstance(favorite, bool):
                raise ValueError(f"Kontakt {index} har ugyldig favorittverdi")
            normalized.append(
                {
                    "network": network,
                    "node_id": node_id,
                    "alias": str(raw.get("alias", "")).strip(),
                    "favorite": favorite,
                    "long_name": str(raw.get("long_name", "")),
                    "short_name": str(raw.get("short_name", "")),
                }
            )

        # Apply only after every contact has passed validation, so a malformed
        # file cannot partially replace or merge the in-memory contact book.
        if replace:
            self.data = {}
        for item in normalized:
            entry = self.entry(str(item["network"]), str(item["node_id"]))
            entry["alias"] = str(item["alias"])
            entry["favorite"] = bool(item["favorite"])
        self.save()
        return normalized

    def import_file(self, path: Path, *, replace: bool = False) -> list[dict[str, Any]]:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Kontaktfilen må inneholde et JSON-objekt")
        return self.import_payload(raw, replace=replace)
