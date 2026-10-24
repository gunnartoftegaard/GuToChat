#!/usr/bin/env python3
from __future__ import annotations

from mesh_receive_health import receive_health_presentation

import argparse
import base64
import json
import math
import queue
import socket
import sqlite3
import threading
import time
import tkinter as tk
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from branding import PRODUCT_NAME, FORMER_PRODUCT_NAME
from module_selection import private_radio_enabled
from capabilities import (
    CAPABILITY_ORDER,
    capability_enabled,
    network_capability_allowed,
    runtime_capability_view,
)
from contacts import ContactBook
from diagnostics import write_bundle
from emergency_templates import (
    EmergencyTemplateStore,
    TEMPLATE_CATEGORIES,
    TEMPLATE_SEVERITIES,
    TemplateConflictError,
)
from offline_map import (
    ImageTk,
    load_best_raster_tile,
    load_default_raster_tile,
    load_raster_tile_for_center,
    load_raster_tile,
    offline_map_sources_signature,
    read_latest_positions_read_only,
    read_map_package,
    read_mbtiles_metadata,
    read_position_history_read_only,
    resolve_active_map,
    resolve_database_path,
    resolve_offline_map_directory,
    resolve_offline_map_path,
)
from i18n import normalize_language, translate
from export_utils import (
    in_inclusive_range,
    iso_timestamp,
    parse_datetime_input,
    write_delimited,
)
from message_store import MessageStore
from sqlite_resilience import sqlite_locked_retry
from aprs_replica_store import AprsReplicaStore
from map_pub_field_status_v1 import host_proxy_managed, map_action_policy, remote_detail_key
from map_position_provider import (
    map_position_data_signature,
    read_map_latest_positions_read_only,
    read_map_position_history_read_only,
)
from field_aprs_is_gui_adapter import (
    merge_map_rows_for_presentation,
    read_direct_aprs_is_rows_read_only,
)
from aprs_is_client import build_range_filter
from field_aprs_is_presentation import FieldAprsIsPresentationConfig
from field_aprs_is_live_control import FieldAprsIsLiveController
from field_aprs_is_live_gui_control import FieldAprsIsGuiLiveControl
from map_package_operator import (
    AUTO_MAP_KEY,
    OperatorMapEntry,
    build_operator_map_inventory,
    operator_map_metadata_text,
    resolve_operator_map,
)
from secure_mbtiles_installer import (
    SecureMbtilesInstallError,
    secure_install_mbtiles,
)
from map_mode_control import (
    MapOperatorMode,
    initial_map_operator_mode,
    mode_after_online_failure,
    network_fetch_allowed,
    presentation_for_mode,
)
from map_viewport_presentation import (
    filter_rows_to_xyz_tile, group_history_tracks,
)
from map_temporal_presentation import (
    DEFAULT_TRACK_TAIL_PRESET, DEFAULT_VISIBILITY_PRESET, TEMPORAL_PRESETS_SECONDS,
    filter_history_for_track_tail, filter_latest_for_visibility, preset_seconds,
)
from online_map import (
    DEFAULT_ATTRIBUTION as ONLINE_MAP_ATTRIBUTION,
    DEFAULT_TILE_URL_TEMPLATE as ONLINE_MAP_TILE_URL_TEMPLATE,
    OnlineViewport,
    filter_rows_to_viewport,
    project_latlon_to_viewport,
    render_osm_viewport,
)
from lc3_replay_store import LC3ReplayStore
from position_export import MAX_EXPORT_ROWS, write_position_export
from template_placeholders import (
    ALLOWED_PLACEHOLDERS,
    extract_placeholders,
    format_position,
    render_template,
)
from node_catalog import NodeCatalog
from position_store import PositionStore
from roles import infer_role_from_config
from protocol import (
    ControlAuthenticator,
    StatusAuthenticator,
    FragmentAssembler,
    canonical_meshtastic_id,
    destination_to_num,
    encode_info_request,
    encode_aprs_history_request,
    encode_base_status_request,
    encode_base_control_request,
    encode_message_request,
    encode_node_request,
    encode_position_history_request,
    encode_position_request,
    encode_send,
    fragment_frame,
    frame_bytes,
    is_control,
    parse_control,
    control_transport_policy,
)

APP_VERSION = "2.5.0-beta5"
APP_DISPLAY_VERSION = "2.5 beta5"
OFFLINE_MAP_RESIZE_DEBOUNCE_MS = 120
MESH_TEXT_LIMIT = 220
BROADCAST_MESH = 0xFFFFFFFF
SEVERITY_LABELS = {
    None: "Ikke angitt",
    "information": "Informasjon",
    "status": "Status",
    "urgent": "Haster",
    "emergency": "Nød",
}
SEVERITY_BY_LABEL = {label: value for value, label in SEVERITY_LABELS.items()}
EMERGENCY_CATEGORY_KEYS = {
    "Nød": "emergency.category.emergency",
    "Status": "emergency.category.status",
    "Møtepunkt": "emergency.category.meeting",
    "Forsyning": "emergency.category.supply",
    "Teknisk": "emergency.category.technical",
    "Egendefinert": "emergency.category.custom",
}
EMERGENCY_SEVERITY_KEYS = {
    None: "emergency.severity.none",
    "information": "emergency.severity.information",
    "status": "emergency.severity.status",
    "urgent": "emergency.severity.urgent",
    "emergency": "emergency.severity.emergency",
}


def _control_auth_for(instance: Any) -> ControlAuthenticator:
    """Return optional LC3 auth for real and lightweight test app objects."""
    values = getattr(instance, "__dict__", {})
    value = values.get("control_auth") if isinstance(values, dict) else None
    if isinstance(value, ControlAuthenticator):
        return value
    return ControlAuthenticator(None)


def _status_auth_for(instance: Any) -> StatusAuthenticator:
    """Return dedicated read-only status auth for real and lightweight test objects."""
    values = getattr(instance, "__dict__", {})
    value = values.get("status_auth") if isinstance(values, dict) else None
    if isinstance(value, StatusAuthenticator):
        return value
    return StatusAuthenticator(None)


def _text_for(instance: Any, key: str, **values: object) -> str:
    """Translate presentation text for real and lightweight test app objects."""
    data = getattr(instance, "__dict__", {})
    language = data.get("ui_language", "nb") if isinstance(data, dict) else "nb"
    return translate(key, str(language), **values)


class ApiClient:
    def __init__(self, host: str, port: int, timeout: float = 2.5) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def call(
        self, request: dict[str, Any], *, timeout: float | None = None
    ) -> dict[str, Any]:
        data = (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
        effective_timeout = self.timeout if timeout is None else max(0.1, float(timeout))
        with socket.create_connection(
            (self.host, self.port), timeout=effective_timeout
        ) as sock:
            sock.settimeout(effective_timeout)
            sock.sendall(data)
            response = json.loads(sock.makefile("rb").readline().decode("utf-8"))
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "Ukjent feil"))
        return response


class LoRaChatApp(tk.Tk):
    def __init__(self, config: dict[str, Any], *, setup_coordinator=None) -> None:
        super().__init__()
        self.config = config
        self.setup_coordinator = setup_coordinator
        self.private_radio_enabled = private_radio_enabled(config)
        self.node_name = str(config["node_name"])
        self.station_name = str(config.get("station_name") or self.node_name)
        self.station_callsign = str(config.get("station_callsign", "")).strip()
        self.local_address = int(config["address"])
        self.max_text_bytes = int(config.get("max_text_bytes", 190))
        self.ws_client = ApiClient(
            str(config.get("api_host", "127.0.0.1")),
            int(config.get("api_port", 8765)),
        )
        contacts_path = Path(
            config.get(
                "contacts_file",
                str(Path.home() / ".config/lorachat-v2/contacts.json"),
            )
        )
        self.contacts = ContactBook(contacts_path)
        self.ui_state_path = Path(
            config.get(
                "ui_state_file",
                str(contacts_path.with_name("ui-state.json")),
            )
        )
        self.ui_state = self._load_ui_state()
        self.ui_language = normalize_language(
            config.get("ui_language", self.ui_state.get("ui_language", "nb"))
        )
        saved_recipients = self.ui_state.get("last_recipient_by_network", {})
        self.last_recipient_by_network: dict[str, str] = (
            {
                str(key): str(value)
                for key, value in saved_recipients.items()
                if str(key) and str(value)
            }
            if isinstance(saved_recipients, dict)
            else {}
        )
        database_path = Path(config["database"])
        self.catalog = sqlite_locked_retry(
            lambda: NodeCatalog(database_path),
            label="GUI NodeCatalog-oppstart",
        )
        self.message_store = sqlite_locked_retry(
            lambda: MessageStore(database_path),
            label="GUI MessageStore-oppstart",
        )
        self.position_store = sqlite_locked_retry(
            lambda: PositionStore(database_path),
            label="GUI PositionStore-oppstart",
        )
        self.emergency_templates = sqlite_locked_retry(
            lambda: EmergencyTemplateStore(database_path),
            label="GUI beredskapsmaler-oppstart",
        )
        self.offline_map_database_path = resolve_database_path(config)
        self.offline_map_status = resolve_offline_map_path(config)
        self.offline_map_photo: Any | None = None
        self.offline_map_rows: list[dict[str, Any]] = []
        self.offline_map_history_rows: list[dict[str, Any]] = []
        self.offline_map_tree_rows: dict[str, dict[str, Any]] = {}
        self.offline_map_redraw_after_id: str | None = None
        self.offline_map_last_canvas_size: tuple[int, int] | None = None
        self.offline_map_last_tile: Any | None = None
        self.offline_map_manual_viewport = False
        # PRE-A3-A2.4-B: session-only read-only MBTiles operator selection.
        self.operator_map_selected_key = AUTO_MAP_KEY
        self.operator_map_inventory: list[OperatorMapEntry] = []
        self.operator_map_label_to_key: dict[str, str] = {}
        # R2-E.A1-GUI: Field online-map state is isolated from APRS replica semantics.
        # Startup is always fail-safe OFFLINE; no persisted ONLINE auto-resume.
        self.map_operator_mode = initial_map_operator_mode()
        self.online_map_rows: list[dict[str, Any]] = []
        self.online_map_history_rows: list[dict[str, Any]] = []
        self.online_map_photo: Any | None = None
        self.online_map_last_render: Any | None = None
        self.online_map_cache_directory = Path(
            str(config.get("online_map_cache_directory", "~/.cache/gutochat/osm"))
        ).expanduser()
        self.online_map_tile_url_template = str(
            config.get("online_map_tile_url_template", ONLINE_MAP_TILE_URL_TEMPLATE)
        ).strip()
        self.online_map_user_agent = str(
            config.get("online_map_user_agent", f"GuToChat/{APP_VERSION}")
        ).strip()
        self.emergency_template_rows: dict[str, dict[str, Any]] = {}
        self.position_history_item_rows: dict[str, dict[str, Any]] = {}
        self.max_fragments = max(2, min(int(config.get("lc3_max_fragments", 4)), 4))
        self.control_auth = ControlAuthenticator.from_environment(
            sqlite_locked_retry(
                lambda: LC3ReplayStore(database_path),
                label="GUI LC3 control replay-store-oppstart",
            )
        )
        self.status_auth = StatusAuthenticator.from_environment(
            sqlite_locked_retry(
                lambda: LC3ReplayStore(database_path),
                label="GUI LC3 status replay-store-oppstart",
            )
        )
        self.message_sync_interval = max(
            60.0, float(config.get("message_sync_interval_seconds", 300.0))
        )
        self.message_sync_batch_size = max(
            1, min(int(config.get("message_sync_batch_size", 10)), 50)
        )
        self.position_history_sync_batch_size = max(
            1,
            min(
                int(
                    config.get(
                        "position_history_sync_batch_size",
                        self.message_sync_batch_size,
                    )
                ),
                50,
            ),
        )
        self.node_stale_hours = float(config.get("node_stale_hours", 24.0))
        self.gateway_status_stale_seconds = float(
            config.get("gateway_status_stale_seconds", 600.0)
        )
        self.sync_lock_seconds = max(60.0, float(config.get("sync_lock_seconds", 180.0)))
        self.queue_refresh_interval = max(2.0, float(config.get("queue_refresh_interval_seconds", 5.0)))
        self.role = infer_role_from_config(config)
        self.field_base_parity_enabled = bool(config.get("field_base_parity_enabled", False))
        self.aprs_field_sync_enabled = bool(
            self.role == "field" and config.get("aprs_field_sync_enabled", self.field_base_parity_enabled)
        )
        self.remote_base_control_enabled = bool(
            self.role == "field" and config.get("remote_base_control_enabled", False)
        )
        self.remote_base_status_enabled = bool(
            self.role == "field" and config.get("remote_base_status_enabled", False)
        )
        self.aprs_replica_database_path = Path(
            str(config.get(
                "field_aprs_replica_database",
                Path.home() / ".local/share/lorachat-v2/aprs-replica.sqlite3",
            ))
        ).expanduser()
        self.aprs_replica_store = (
            AprsReplicaStore(self.aprs_replica_database_path)
            if self.aprs_field_sync_enabled else None
        )
        # R2-E.A2-A2: optional direct APRS-IS is a separate presentation cache.
        # It is OFF at startup and this GUI integration performs no socket/network I/O.
        self.field_aprs_is_cache_path = Path(
            str(config.get(
                "field_aprs_is_presentation_cache",
                Path.home() / ".local/share/lorachat-v2/aprs-is-presentation.sqlite3",
            ))
        ).expanduser()
        self.field_aprs_is_presentation_enabled = False
        # R2-E.A3-A1: live APRS-IS control is startup-OFF and inert until ARM/START.
        self.field_aprs_is_live_gui = None
        self.field_aprs_is_live_thread_result = None
        self.aprs_sync_batch_size = max(1, min(int(config.get("aprs_sync_batch_size", 10)), 50))
        self.remote_base_control_route = str(config.get("remote_base_control_route", "mesh868"))
        self.remote_base_status_route = str(
            config.get("remote_base_status_route", self.remote_base_control_route)
        )
        self.remote_base_status_ttl_seconds = max(5.0, float(config.get("remote_base_status_ttl_seconds", 30.0)))
        self.remote_base_status: dict[str, dict[str, Any]] = {
            "MAP_PUB": {"state": "UNKNOWN_DEGRADED", "verified": False, "updated_mono": 0.0},
            "APRS_IS_UPLINK": {"state": "UNKNOWN_DEGRADED", "verified": False, "updated_mono": 0.0},
        }
        # Presentation-only memory of the most recent authenticated, verified
        # ON/OFF state.  This never arms remote writes: all control gating still
        # uses _remote_base_status_fresh(), which fails closed after the TTL.
        self.remote_base_last_verified_status: dict[str, dict[str, Any]] = {
            "MAP_PUB": {"state": "UNKNOWN_DEGRADED", "verified": False, "updated_mono": 0.0},
            "APRS_IS_UPLINK": {"state": "UNKNOWN_DEGRADED", "verified": False, "updated_mono": 0.0},
        }
        self.remote_base_pending: dict[str, dict[str, Any]] = {}
        self.last_remote_base_status_request = 0.0
        # Privileged Base status exchange is serialized because the private
        # Waveshare link is half-duplex.  Never have the second status request
        # in flight while Base may still be returning the first response.
        self.remote_base_status_sequence: dict[str, Any] | None = None
        self.remote_base_status_sequence_timeout_seconds = 15.0
        self.remote_base_status_guard_ms = 1000
        self.capability_view = runtime_capability_view(config)
        self.capability_blocked_networks: list[dict[str, str]] = []
        if self.capability_view["enforced"]:
            missing_core = [
                capability
                for capability in ("gui",)
                if not capability_enabled(config, capability)
            ]
            if missing_core:
                raise ValueError(
                    "Hardware profile does not enable required GUI capability/capabilities: "
                    + ", ".join(missing_core)
                )

        self.networks: dict[str, dict[str, Any]] = {}
        self.network_order: list[str] = []
        self.mesh_clients: dict[str, ApiClient] = {}
        self.node_cache: dict[str, list[dict[str, Any]]] = {}
        self.local_mesh_status: dict[str, dict[str, Any]] = {}
        self.gateway_status: dict[str, dict[str, Any]] = {}
        self.gateway_acks: dict[str, dict[str, Any]] = {}
        self.gateway_deliveries: dict[str, dict[str, Any]] = {}
        self.gateway_naks: dict[str, str] = {}
        self.gateway_errors: dict[str, str] = {}
        self.gateway_queue_status: dict[str, dict[str, Any]] = {}
        self.synced_gateway_status: dict[str, str] = {}
        self.message_sync_active: dict[str, tuple[str, float]] = {}
        self.message_sync_pages: dict[str, dict[str, Any]] = {}
        self.position_sync_active: dict[str, tuple[str, float]] = {}
        self.position_history_sync_active: dict[str, dict[str, Any]] = {}
        self.aprs_sync_active: dict[str, dict[str, Any]] = {}
        self.aprs_bootstrap_state: dict[str, dict[str, Any]] = {}
        self.node_sync_active: dict[str, dict[str, Any]] = {}
        self.message_sync_more: set[str] = set()
        self.position_history_sync_more: set[str] = set()
        self.aprs_sync_more: set[str] = set()
        # Mobile synchronisation is deliberately serialized.  A complete
        # INFO/GWIDENT, node-list or message-history exchange must finish
        # before the next request is sent.  The private Waveshare radio is
        # half-duplex; the former six-request burst could make response frames
        # collide with the next request even though ordinary chat still
        # appeared healthy.
        self.sync_request_queue: list[tuple[str, str]] = []
        self.sync_request_current: dict[str, Any] | None = None
        self.processed_control_keys: set[tuple[Any, ...]] = set()
        self.last_messages: list[dict[str, Any]] = []
        self.last_signature: tuple[Any, ...] | None = None
        self.last_local_node_refresh = 0.0

        self.last_gateway_request = 0.0
        self.last_message_sync_request = 0.0
        self.ws_status: dict[str, Any] = {}
        self.current_recipient_items: list[dict[str, Any]] = []
        self.current_recipient_network_key = ""
        self.node_tree_items: dict[str, tuple[str, str]] = {}

        # Keep exactly one periodic GUI refresh scheduled at a time.  beta3
        # accidentally added a new permanent timer after every send and every
        # press on "Oppdater nå", which caused steadily increasing CPU use.
        self.refresh_interval_ms = max(750, int(config.get("ui_refresh_interval_ms", 2000)))
        self.message_list_limit = max(50, min(int(config.get("ui_message_limit", 250)), 1000))
        self.position_export_max_rows = max(1, min(int(config.get("export_position_max_rows", MAX_EXPORT_ROWS)), MAX_EXPORT_ROWS))
        self.refresh_after_id: str | None = None
        self.refresh_running = False
        # R2 responsiveness: message-history reads are the dominant periodic
        # latency source (about 1.3 s for list_display(250) on Base). Keep the
        # socket/database read off Tk's main event loop and coalesce overlapping
        # requests. The same shared mechanism benefits Base and Field while
        # preserving their role-specific source trees.
        self.message_refresh_queue = queue.SimpleQueue()
        self.message_refresh_running = False
        self.message_refresh_pending = False
        self.message_refresh_generation = 0
        self.last_message_history_refresh_started = 0.0
        self.message_refresh_active_seconds = max(
            0.5, float(config.get("ui_message_refresh_active_seconds", 2.0))
        )
        self.message_refresh_inactive_seconds = max(
            self.message_refresh_active_seconds,
            float(config.get("ui_message_refresh_inactive_seconds", 10.0)),
        )
        self.message_history_timeout_seconds = max(
            2.5, float(config.get("ui_message_history_timeout_seconds", 15.0))
        )
        self.message_refresh_poll_after_id: str | None = None
        # R2.1: local map database/package reads are the remaining dominant
        # tab-specific blocking path. Keep those reads in a single-flight
        # worker and apply only reduced results on Tk's main thread.
        self.map_refresh_queue = queue.SimpleQueue()
        self.map_refresh_running = False
        self.map_refresh_pending = False
        self.map_refresh_generation = 0
        self.map_refresh_poll_after_id: str | None = None
        self.online_map_render_queue = queue.SimpleQueue()
        self.online_map_render_running = False
        self.online_map_render_generation = 0
        self.online_map_render_poll_after_id: str | None = None
        self._gui_closing = False
        self.last_node_signature: tuple[Any, ...] | None = None
        self.last_system_signature: tuple[Any, ...] | None = None
        self.last_status_text = ""
        self.last_footer_text = ""
        self.last_queue_refresh = 0.0
        self.last_queue_signature: tuple[Any, ...] | None = None
        self.queue_rows: list[dict[str, Any]] = []
        self.queue_item_refs: dict[str, dict[str, Any]] = {}
        self.message_tree_rows: dict[str, dict[str, Any]] = {}
        self.conversation_tree_rows: dict[str, tuple[str, str, str]] = {}
        self.conversation_messages: dict[
            tuple[str, str, str], list[dict[str, Any]]
        ] = {}
        self.selected_conversation_key: tuple[str, str, str] | None = None
        self.pending_conversation_key: tuple[str, str, str] | None = None
        self.rendered_conversation_key: tuple[str, str, str] | None = None
        self.selected_message_identity: tuple[Any, ...] | None = None
        self.conversation_tag_rows: dict[str, dict[str, Any]] = {}
        self.node_tree_rows: dict[str, dict[str, Any]] = {}
        self.system_tree_rows: dict[str, dict[str, Any]] = {}
        self.visible_message_rows: list[dict[str, Any]] = []
        self.recent_message_rows: list[dict[str, Any]] = []
        self.visible_node_rows: list[dict[str, Any]] = []
        self.visible_system_rows: list[dict[str, Any]] = []
        self.visible_queue_rows: list[dict[str, Any]] = []
        self.visible_position_history_rows: list[dict[str, Any]] = []
        self.all_message_rows_cache: list[dict[str, Any]] | None = None
        self.all_message_rows_cache_signature: tuple[Any, ...] | None = None
        self.last_position_history_signature: tuple[Any, ...] | None = None
        self.last_offline_map_signature: tuple[Any, ...] | None = None

        self._load_networks()
        self._load_persistent_cache()
        self.app_title = f"{PRODUCT_NAME} {APP_DISPLAY_VERSION} - {self._title_role_label()}"
        self.title(self.app_title)
        self.geometry("1380x820")
        self.minsize(1080, 680)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._edit_context_widget: tk.Misc | None = None
        self._edit_context_menu_visible = False
        self._edit_context_focus_after_id: str | None = None
        self._message_action_menu_visible = False
        self._message_action_focus_after_id: str | None = None
        self._build_edit_context_menu()
        self._build_ui()
        self.notebook.bind(
            "<<NotebookTabChanged>>", self._on_notebook_tab_changed, add="+"
        )
        self.message_refresh_poll_after_id = self.after(
            25, self._poll_message_refresh_results
        )
        self.map_refresh_poll_after_id = self.after(
            25, self._poll_map_refresh_results
        )
        self.online_map_render_poll_after_id = self.after(
            50, self._poll_online_map_render_results
        )
        self._schedule_refresh(300)

    def _add_network(self, network: dict[str, Any]) -> None:
        key = str(network["key"])
        self.networks[key] = network
        self.network_order.append(key)
        self.node_cache.setdefault(key, [])

    def _title_role_label(self) -> str:
        """Return the short role label used in the window title."""
        return "Base" if self.role == "base" else "Field"

    def _t(self, key: str, **values: object) -> str:
        """Translate presentation text without changing internal state codes.

        Some isolated unit tests construct the class without initializing Tk;
        reading ``__dict__`` avoids Tk's attribute fallback in that case.
        """
        return _text_for(self, key, **values)

    def _choice_code(
        self, value: str, choices: tuple[tuple[str, str], ...], *, default: str
    ) -> str:
        """Map a localized combobox label to one stable internal filter code."""
        for code, key in choices:
            labels = {
                self._t(key),
                translate(key, "nb"),
                translate(key, "en"),
            }
            if value in labels:
                return code
        return default

    def _network_filter_code(self, value: str, all_key: str) -> str:
        """Map a presentation network label to a stable configured network key."""
        if value == self._t(all_key):
            return "all"
        for key in self.network_order:
            if value == str(self.networks[key].get("label", "")):
                return key
        return "all"

    def _message_direction_filter_code(self) -> str:
        return self._choice_code(
            self.message_direction_filter_var.get(),
            (
                ("all", "messages.filter.direction_all"),
                ("received", "messages.filter.direction_received"),
                ("sent", "messages.filter.direction_sent"),
            ),
            default="all",
        )

    def _message_status_filter_code(self) -> str:
        return self._choice_code(
            self.message_status_filter_var.get(),
            (
                ("all", "messages.filter.status_all"),
                ("confirmed", "messages.filter.status_confirmed"),
                ("recipient_confirmed", "messages.filter.status_recipient_confirmed"),
                ("waiting", "messages.filter.status_waiting"),
                ("error", "messages.filter.status_error"),
                ("expired", "messages.filter.status_expired"),
                ("received", "messages.filter.status_received"),
            ),
            default="all",
        )

    def _node_type_filter_code(self) -> str:
        return self._choice_code(
            self.node_type_filter_var.get(),
            (
                ("all", "nodes.filter.type_all"),
                ("contacts", "nodes.filter.type_contacts"),
                ("without_alias", "nodes.filter.type_without_alias"),
            ),
            default="all",
        )

    def _node_favorite_filter_code(self) -> str:
        return self._choice_code(
            self.node_favorite_filter_var.get(),
            (
                ("all", "nodes.filter.all"),
                ("favorite", "nodes.filter.favorite_only"),
                ("not_favorite", "nodes.filter.not_favorite"),
            ),
            default="all",
        )

    def _node_source_filter_code(self) -> str:
        return self._choice_code(
            self.node_manual_filter_var.get(),
            (
                ("all", "nodes.filter.all"),
                ("manual", "nodes.filter.manual"),
                ("discovered", "nodes.filter.discovered"),
            ),
            default="all",
        )

    def _system_status_filter_code(self) -> str:
        return self._choice_code(
            self.system_status_filter_var.get(),
            (
                ("all", "system.filter.all"),
                ("ok", "system.filter.ok"),
                ("problems", "system.filter.problems"),
            ),
            default="all",
        )

    def _queue_type_filter_code(self) -> str:
        return self._choice_code(
            self.queue_type_filter_var.get(),
            (
                ("all", "operations.filter.type_all"),
                ("user", "operations.filter.type_message"),
                ("sync", "operations.filter.type_control"),
                ("gateway", "operations.filter.type_gateway"),
            ),
            default="all",
        )

    def _queue_state_filter_code(self) -> str:
        return self._choice_code(
            self.queue_state_filter_var.get(),
            (
                ("all", "operations.filter.state_all"),
                ("waiting", "operations.filter.state_waiting"),
                ("retry", "operations.filter.state_retry"),
                ("paused", "operations.filter.state_paused"),
                ("error", "operations.filter.state_error"),
                ("other", "operations.filter.state_other"),
            ),
            default="all",
        )

    def _message_type_values(self, network: dict[str, Any]) -> list[str]:
        """Return localized compose labels; semantics are carried by combobox index."""
        if network["kind"] == "waveshare":
            return [self._t("messages.type.direct"), self._t("messages.type.broadcast")]
        return [
            self._t("messages.type.direct"),
            self._t("messages.type.channel_broadcast"),
        ]

    def _message_type_code(self) -> str:
        return "broadcast" if self.type_combo.current() == 1 else "direct"

    def _station_display_name(self) -> str:
        """Return the user-facing station name without using it as role logic."""
        return self.station_name or self.node_name

    def _station_file_stem(self) -> str:
        """Return a portable, user-facing station stem for exported filenames."""
        name = self._station_display_name().strip() or self._title_role_label().lower()
        cleaned = "".join(
            char if char.isalnum() or char in {"-", "_", "."} else "_"
            for char in name
        ).strip("._-")
        return cleaned or self._title_role_label().lower()

    def _load_ui_state(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.ui_state_path.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception:
            return {}

    def _save_ui_state(self) -> None:
        self.ui_state["last_recipient_by_network"] = dict(
            self.last_recipient_by_network
        )
        try:
            self.ui_state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.ui_state_path.with_name(self.ui_state_path.name + ".tmp")
            temporary.write_text(
                json.dumps(self.ui_state, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            temporary.replace(self.ui_state_path)
        except Exception:
            # Recipient memory is a convenience feature and must never prevent
            # the radio GUI from starting or sending messages.
            pass

    def _record_blocked_network(
        self, item: dict[str, Any], kind: str, required: str | None
    ) -> None:
        self.capability_blocked_networks.append(
            {
                "label": str(item.get("label") or item.get("route_key") or item.get("key") or kind),
                "kind": kind,
                "required_capability": required or "unmapped",
            }
        )

    def _load_networks(self) -> None:
        waveshare = {
            "key": "waveshare",
            "label": "Privat Waveshare 868",
            "kind": "waveshare",
            "frequency": "868,125 MHz",
        }
        allowed, required = network_capability_allowed(self.config, "waveshare", waveshare)
        if self.private_radio_enabled and allowed:
            self._add_network(waveshare)
        elif self.private_radio_enabled:
            self._record_blocked_network(waveshare, "waveshare", required)

        for item in self.config.get("meshtastic_radios", []):
            if not isinstance(item, dict) or not item.get("enabled", True):
                continue
            allowed, required = network_capability_allowed(self.config, "mesh_local", item)
            if not allowed:
                self._record_blocked_network(item, "mesh_local", required)
                continue
            radio = dict(item)
            key = str(radio.get("route_key") or radio.get("key"))
            radio.update(
                {
                    "key": key,
                    "kind": "mesh_local",
                    "label": str(radio.get("label", key)),
                }
            )
            self._add_network(radio)
            self.mesh_clients[key] = ApiClient(
                str(radio.get("api_host", "127.0.0.1")),
                int(radio["api_port"]),
            )

        for item in self.config.get("meshtastic_gateways", []):
            if not isinstance(item, dict) or not item.get("enabled", True):
                continue
            allowed, required = network_capability_allowed(self.config, "mesh_gateway", item)
            if not self.private_radio_enabled:
                allowed, required = False, "private_lora"
            if not allowed:
                self._record_blocked_network(item, "mesh_gateway", required)
                continue
            gateway = dict(item)
            key = str(gateway.get("route_key") or gateway.get("key"))
            gateway.update(
                {
                    "key": key,
                    "kind": "mesh_gateway",
                    "label": str(gateway.get("label", key)),
                    "gateway_address": int(gateway.get("gateway_address", 1)),
                    "channel_index": int(gateway.get("channel_index", 0)),
                }
            )
            self._add_network(gateway)

        peers = []
        for peer in self.config.get("peers", []):
            peers.append(
                {
                    "num": int(peer["address"]),
                    "id": str(peer["address"]),
                    "long_name": str(peer["name"]),
                    "short_name": "",
                }
            )
        if self.private_radio_enabled:
            self.node_cache["waveshare"] = peers

    @staticmethod
    def _catalog_node(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "num": int(row.get("num", 0)),
            "id": str(row.get("node_id") or row.get("id") or ""),
            "long_name": str(row.get("long_name", "")),
            "short_name": str(row.get("short_name", "")),
            "last_heard": row.get("last_heard"),
            "last_updated": str(row.get("last_updated", "")),
            "snr": row.get("snr"),
            "manual": bool(row.get("manual", False)),
            "source": str(row.get("source", "")),
            "revision": int(row.get("revision", 0)),
        }

    def _reload_catalog_network(self, network_key: str) -> None:
        self.node_cache[network_key] = [
            self._catalog_node(row)
            for row in self.catalog.list_nodes(network_key)
        ]

    def _load_persistent_cache(self) -> None:
        for key in self.network_order:
            if key == "waveshare":
                continue
            self._reload_catalog_network(key)
            network = self.networks[key]
            if network.get("kind") == "mesh_gateway":
                cached = self.catalog.load_gateway_status(key)
                if cached:
                    self.gateway_status[key] = cached

    def _build_edit_context_menu(self) -> None:
        """Create one reusable context menu for Text and Entry widgets."""
        self.edit_context_menu = tk.Menu(self, tearoff=False)
        self.edit_context_menu.add_command(
            label=self._t("edit.undo"), command=lambda: self._run_edit_action("undo")
        )
        self.edit_context_menu.add_separator()
        self.edit_context_menu.add_command(
            label=self._t("edit.cut"), command=lambda: self._run_edit_action("cut")
        )
        self.edit_context_menu.add_command(
            label=self._t("edit.copy"), command=lambda: self._run_edit_action("copy")
        )
        self.edit_context_menu.add_command(
            label=self._t("edit.paste"), command=lambda: self._run_edit_action("paste")
        )
        self.edit_context_menu.add_command(
            label=self._t("edit.delete"), command=lambda: self._run_edit_action("delete")
        )
        self.edit_context_menu.add_separator()
        self.edit_context_menu.add_command(
            label=self._t("edit.select_all"), command=lambda: self._run_edit_action("select_all")
        )
        self._edit_menu_indexes = {
            "undo": 0,
            "cut": 2,
            "copy": 3,
            "paste": 4,
            "delete": 5,
            "select_all": 7,
        }

        # Class bindings also cover editable fields created later in dialogs.
        for widget_class in ("Text", "Entry", "TEntry"):
            self.bind_class(
                widget_class,
                "<Button-3>",
                self._show_edit_context_menu,
                add="+",
            )

        # tk_popup is deliberately followed by grab_release so normal GUI
        # controls remain usable.  Without explicit dismissal bindings, Tk 8.6
        # can then leave the menu posted indefinitely.
        self.bind_all(
            "<Escape>",
            self._dismiss_edit_context_menu_event,
            add="+",
        )
        self.bind_all(
            "<Button-1>",
            self._dismiss_edit_context_menu_on_left_click,
            add="+",
        )
        self.bind_all(
            "<FocusOut>",
            self._schedule_edit_context_focus_check,
            add="+",
        )
        self.edit_context_menu.bind(
            "<Unmap>",
            self._edit_context_menu_unmapped,
            add="+",
        )

    def _edit_context_menu_unmapped(self, _event: Any = None) -> None:
        self._edit_context_menu_visible = False

    def _dismiss_edit_context_menu(self) -> None:
        """Unpost the reusable edit menu without affecting normal clicks."""
        try:
            self.edit_context_menu.unpost()
        except (AttributeError, tk.TclError):
            pass
        try:
            self.edit_context_menu.grab_release()
        except (AttributeError, tk.TclError):
            pass
        self._edit_context_menu_visible = False

    def _dismiss_edit_context_menu_event(self, _event: Any = None) -> None:
        self._dismiss_edit_context_menu()

    def _dismiss_edit_context_menu_on_left_click(self, event: Any) -> None:
        if not self._edit_context_menu_visible:
            return
        # A click on the menu itself must still be allowed to choose a command.
        if event.widget is self.edit_context_menu:
            return
        self._dismiss_edit_context_menu()

    def _schedule_edit_context_focus_check(self, _event: Any = None) -> None:
        if not self._edit_context_menu_visible:
            return
        if self._edit_context_focus_after_id is not None:
            try:
                self.after_cancel(self._edit_context_focus_after_id)
            except tk.TclError:
                pass
        self._edit_context_focus_after_id = self.after_idle(
            self._dismiss_edit_context_menu_if_focus_lost
        )

    def _dismiss_edit_context_menu_if_focus_lost(self) -> None:
        self._edit_context_focus_after_id = None
        if not self._edit_context_menu_visible:
            return
        try:
            focused = self.focus_displayof()
        except tk.TclError:
            focused = None
        if focused is None:
            self._dismiss_edit_context_menu()

    @staticmethod
    def _edit_widget_is_editable(widget: Any) -> bool:
        try:
            return str(widget.cget("state")) not in {"disabled", "readonly"}
        except (AttributeError, tk.TclError):
            return True

    @staticmethod
    def _edit_widget_has_selection(widget: Any) -> bool:
        try:
            if str(widget.winfo_class()) == "Text":
                return bool(widget.tag_ranges("sel"))
            return bool(widget.selection_present())
        except (AttributeError, tk.TclError):
            return False

    def _show_edit_context_menu(self, event: Any) -> str:
        # A second right-click replaces the previously posted menu cleanly.
        self._dismiss_edit_context_menu()
        widget = event.widget
        self._edit_context_widget = widget
        widget_class = str(widget.winfo_class())
        editable = self._edit_widget_is_editable(widget)
        has_selection = self._edit_widget_has_selection(widget)

        try:
            self.clipboard_get()
            clipboard_has_text = True
        except tk.TclError:
            clipboard_has_text = False

        states = {
            "undo": editable and widget_class == "Text",
            "cut": editable and has_selection,
            "copy": has_selection,
            "paste": editable and clipboard_has_text,
            "delete": editable and has_selection,
            "select_all": True,
        }
        for action, enabled in states.items():
            self.edit_context_menu.entryconfigure(
                self._edit_menu_indexes[action],
                state="normal" if enabled else "disabled",
            )

        try:
            widget.focus_set()
            if not has_selection:
                if widget_class == "Text":
                    widget.mark_set("insert", f"@{event.x},{event.y}")
                else:
                    widget.icursor(widget.index(f"@{event.x}"))
        except (AttributeError, tk.TclError):
            pass

        try:
            self._edit_context_menu_visible = True
            self.edit_context_menu.tk_popup(event.x_root, event.y_root)
        except tk.TclError:
            self._edit_context_menu_visible = False
        finally:
            try:
                self.edit_context_menu.grab_release()
            except tk.TclError:
                pass
        return "break"

    def _run_edit_action(self, action: str) -> None:
        widget = self._edit_context_widget
        if widget is None:
            return
        widget_class = str(widget.winfo_class())
        try:
            if action == "undo":
                if widget_class == "Text":
                    widget.edit_undo()
                else:
                    widget.event_generate("<<Undo>>")
            elif action == "cut":
                widget.event_generate("<<Cut>>")
            elif action == "copy":
                widget.event_generate("<<Copy>>")
            elif action == "paste":
                widget.event_generate("<<Paste>>")
            elif action == "delete":
                if self._edit_widget_has_selection(widget):
                    widget.delete("sel.first", "sel.last")
            elif action == "select_all":
                if widget_class == "Text":
                    widget.tag_add("sel", "1.0", "end-1c")
                    widget.mark_set("insert", "end-1c")
                    widget.see("insert")
                else:
                    widget.selection_range(0, "end")
                    widget.icursor("end")
        except (AttributeError, tk.TclError):
            # Empty undo stacks and disappearing selections are harmless.
            pass

        if hasattr(self, "message_text") and widget is self.message_text:
            self.after_idle(self._update_counter)
        self._dismiss_edit_context_menu()

    def _build_ui(self) -> None:
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=self.app_title,
            font=("TkDefaultFont", 17, "bold"),
        ).pack(side="left")
        self.status_label = ttk.Label(header, text=self._t("shell.connecting"))
        self.status_label.pack(side="right")

        ttk.Label(
            self,
            text=(self._t("modular.subtitle", version=APP_VERSION) if not self.private_radio_enabled else self._t(
                "shell.subtitle", address=self.local_address, version=APP_VERSION
            )),
            padding=(12, 0, 12, 8),
        ).pack(fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.messages_tab = ttk.Frame(self.notebook)
        self.nodes_tab = ttk.Frame(self.notebook)
        self.position_history_tab = ttk.Frame(self.notebook)
        self.map_tab = ttk.Frame(self.notebook)
        self.online_map_tab = ttk.Frame(self.notebook)
        self.system_tab = ttk.Frame(self.notebook)
        self.operations_tab = ttk.Frame(self.notebook)
        self.emergency_tab = ttk.Frame(self.notebook)
        self.help_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.messages_tab, text=self._t("tab.messages"))
        self.notebook.add(self.nodes_tab, text=self._t("tab.nodes"))
        self.notebook.add(self.position_history_tab, text=self._t("tab.position_history"))
        self.notebook.add(self.map_tab, text=self._t("tab.map_offline"))
        self.notebook.add(self.online_map_tab, text=self._t("tab.map_online"))
        self.notebook.add(self.system_tab, text=self._t("tab.system"))
        self.notebook.add(self.operations_tab, text=self._t("tab.operations"))
        self.notebook.add(self.emergency_tab, text=self._t("tab.emergency"))
        self.notebook.add(self.help_tab, text=self._t("tab.help"))

        self._build_messages_tab()
        self._build_nodes_tab()
        self._build_position_history_tab()
        self._build_map_tab()
        self._build_online_map_tab()
        self._build_system_tab()
        self._build_operations_tab()
        self._build_emergency_tab()
        self._build_help_tab()
        from setup_ui import add_setup_tab
        add_setup_tab(self)

        footer = ttk.Frame(self, padding=(12, 0, 12, 10))
        footer.pack(fill="x")
        self.footer_label = ttk.Label(footer, text=self._t("shell.footer_waiting"))
        self.footer_label.pack(side="left")
        self.refresh_button = ttk.Button(footer, text=self._t("action.refresh_now"), command=self.request_refresh)
        self.refresh_button.pack(side="right")

    def _build_messages_tab(self) -> None:
        filters = ttk.LabelFrame(self.messages_tab, text=self._t("messages.filters"), padding=8)
        filters.pack(fill="x", padx=6, pady=(6, 0))
        self.message_search_var = tk.StringVar()
        self.message_network_filter_var = tk.StringVar(value=self._t("messages.filter.network_all"))
        self.message_direction_filter_var = tk.StringVar(value=self._t("messages.filter.direction_all"))
        self.message_contact_filter_var = tk.StringVar()
        self.message_status_filter_var = tk.StringVar(value=self._t("messages.filter.status_all"))
        self.message_from_filter_var = tk.StringVar()
        self.message_to_filter_var = tk.StringVar()

        ttk.Label(filters, text=self._t("common.search")).grid(row=0, column=0, sticky="w")
        search_entry = ttk.Entry(filters, textvariable=self.message_search_var, width=24)
        search_entry.grid(row=0, column=1, sticky="ew", padx=(5, 10))
        search_entry.bind("<Return>", lambda _event: self._apply_message_filters())
        ttk.Label(filters, text=self._t("messages.network")).grid(row=0, column=2, sticky="w")
        self.message_network_filter = ttk.Combobox(
            filters, state="readonly", width=22,
            textvariable=self.message_network_filter_var,
            values=[self._t("messages.filter.network_all")] + [self.networks[key]["label"] for key in self.network_order],
        )
        self.message_network_filter.grid(row=0, column=3, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("messages.direction")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=16,
            textvariable=self.message_direction_filter_var,
            values=[self._t("messages.filter.direction_all"), self._t("messages.filter.direction_received"), self._t("messages.filter.direction_sent")],
        ).grid(row=0, column=5, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("messages.contact_node")).grid(row=0, column=6, sticky="w")
        ttk.Entry(filters, textvariable=self.message_contact_filter_var, width=19).grid(
            row=0, column=7, sticky="ew", padx=(5, 0)
        )

        ttk.Label(filters, text=self._t("common.status")).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Combobox(
            filters, state="readonly", width=22,
            textvariable=self.message_status_filter_var,
            values=[
                self._t("messages.filter.status_all"),
                self._t("messages.filter.status_confirmed"),
                self._t("messages.filter.status_recipient_confirmed"),
                self._t("messages.filter.status_waiting"),
                self._t("messages.filter.status_error"),
                self._t("messages.filter.status_expired"),
                self._t("messages.filter.status_received"),
            ],
        ).grid(row=1, column=1, sticky="w", padx=(5, 10), pady=(6, 0))
        ttk.Label(filters, text=self._t("common.from")).grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.message_from_filter_var, width=20).grid(
            row=1, column=3, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Label(filters, text=self._t("common.to")).grid(row=1, column=4, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.message_to_filter_var, width=20).grid(
            row=1, column=5, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.apply_filter"), command=self._apply_message_filters).grid(
            row=1, column=6, sticky="e", padx=(0, 6), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.reset"), command=self._clear_message_filters).grid(
            row=1, column=7, sticky="w", pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.export"), command=self.export_messages).grid(
            row=0, column=8, rowspan=2, sticky="ns", padx=(10, 0)
        )
        filters.columnconfigure(1, weight=1)
        filters.columnconfigure(7, weight=1)
        self.message_filter_result_label = ttk.Label(filters, text=self._t("messages.result.latest"))
        self.message_filter_result_label.grid(row=2, column=0, columnspan=9, sticky="w", pady=(5, 0))

        view_bar = ttk.Frame(self.messages_tab, padding=(6, 6, 6, 0))
        view_bar.pack(fill="x")
        ttk.Label(view_bar, text=self._t("messages.view")).pack(side="left")
        saved_view = str(self.ui_state.get("message_view", "Tabellvisning"))
        if saved_view not in {"Tabellvisning", "Samtalevisning"}:
            saved_view = "Tabellvisning"
        self.message_view_var = tk.StringVar(value=saved_view)
        ttk.Radiobutton(
            view_bar,
            text=self._t("messages.view.table"),
            value="Tabellvisning",
            variable=self.message_view_var,
            command=self._message_view_changed,
        ).pack(side="left", padx=(8, 4))
        ttk.Radiobutton(
            view_bar,
            text=self._t("messages.view.conversation"),
            value="Samtalevisning",
            variable=self.message_view_var,
            command=self._message_view_changed,
        ).pack(side="left", padx=4)
        self.message_view_help_label = ttk.Label(
            view_bar,
            text=self._t("messages.view.help_table"),
        )
        self.message_view_help_label.pack(side="right")

        action_bar = ttk.Frame(self.messages_tab, padding=(6, 4, 6, 0))
        action_bar.pack(fill="x")
        ttk.Label(action_bar, text=self._t("messages.selection")).pack(side="left")
        ttk.Button(action_bar, text=self._t("messages.reply"), command=self._reply_selected_message).pack(
            side="left", padx=(8, 4)
        )
        ttk.Button(action_bar, text=self._t("messages.quote_reply"), command=self._quote_selected_message).pack(
            side="left", padx=4
        )
        ttk.Separator(action_bar, orient="vertical").pack(
            side="left", fill="y", padx=8
        )
        ttk.Button(
            action_bar, text=self._t("messages.select_visible"), command=self.select_all_visible_messages
        ).pack(side="left", padx=3)
        ttk.Button(
            action_bar, text=self._t("messages.clear_selection"), command=self.clear_message_selection
        ).pack(side="left", padx=3)
        ttk.Button(
            action_bar, text=self._t("messages.invert_selection"), command=self.invert_message_selection
        ).pack(side="left", padx=3)
        ttk.Button(
            action_bar, text=self._t("messages.select_conversation"), command=self.select_current_conversation_messages
        ).pack(side="left", padx=3)
        ttk.Button(
            action_bar, text=self._t("messages.copy_selected"), command=self.copy_marked_messages
        ).pack(side="left", padx=3)

        self.message_view_container = ttk.Frame(self.messages_tab, padding=(4, 6))
        self.message_view_container.pack(fill="both", expand=True)
        self.message_table_frame = ttk.Frame(self.message_view_container)
        columns = (
            "time", "network", "direction", "source", "destination",
            "status", "signal", "message",
        )
        self.message_tree = ttk.Treeview(
            self.message_table_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        headings = {
            "time": self._t("messages.column.time"),
            "network": self._t("messages.column.network"),
            "direction": self._t("messages.column.direction"),
            "source": self._t("messages.column.source"),
            "destination": self._t("messages.column.destination"),
            "status": self._t("messages.column.status"),
            "signal": self._t("messages.column.signal"),
            "message": self._t("messages.column.message"),
        }
        widths = {
            "time": 145, "network": 145, "direction": 75, "source": 145,
            "destination": 150, "status": 180, "signal": 100, "message": 430,
        }
        for column in columns:
            self.message_tree.heading(column, text=headings[column])
            self.message_tree.column(
                column, width=widths[column], anchor="w", stretch=column == "message"
            )
        scroll = ttk.Scrollbar(
            self.message_table_frame,
            orient="vertical",
            command=self.message_tree.yview,
        )
        self.message_tree.configure(yscrollcommand=scroll.set)
        self.message_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.message_tree.bind("<<TreeviewSelect>>", self._message_table_selection_changed)
        self.message_tree.bind("<Double-1>", self._reply_selected_message)
        self.message_tree.bind("<Button-3>", self._show_message_action_menu)

        self.message_conversation_frame = ttk.Frame(self.message_view_container)
        conversation_panes = ttk.Panedwindow(
            self.message_conversation_frame,
            orient="horizontal",
        )
        conversation_panes.pack(fill="both", expand=True)

        conversation_list_frame = ttk.Frame(conversation_panes, padding=(0, 0, 5, 0))
        conversation_columns = ("conversation", "count", "latest")
        self.conversation_tree = ttk.Treeview(
            conversation_list_frame,
            columns=conversation_columns,
            show="headings",
            selectmode="browse",
        )
        self.conversation_tree.heading("conversation", text=self._t("messages.conversation"))
        self.conversation_tree.heading("count", text=self._t("messages.count"))
        self.conversation_tree.heading("latest", text=self._t("messages.latest"))
        self.conversation_tree.column("conversation", width=245, anchor="w", stretch=True)
        self.conversation_tree.column("count", width=60, anchor="center", stretch=False)
        self.conversation_tree.column("latest", width=125, anchor="w", stretch=False)
        conversation_scroll = ttk.Scrollbar(
            conversation_list_frame,
            orient="vertical",
            command=self.conversation_tree.yview,
        )
        self.conversation_tree.configure(yscrollcommand=conversation_scroll.set)
        self.conversation_tree.pack(side="left", fill="both", expand=True)
        conversation_scroll.pack(side="right", fill="y")
        self.conversation_tree.bind(
            "<<TreeviewSelect>>",
            self._conversation_selected,
        )

        transcript_frame = ttk.Frame(conversation_panes, padding=(5, 0, 0, 0))
        self.conversation_header_label = ttk.Label(
            transcript_frame,
            text=self._t("messages.choose_conversation"),
            font=("TkDefaultFont", 12, "bold"),
            padding=(4, 2, 4, 7),
        )
        self.conversation_header_label.pack(fill="x")
        transcript_body = ttk.Frame(transcript_frame)
        transcript_body.pack(fill="both", expand=True)
        self.conversation_text = tk.Text(
            transcript_body,
            wrap="word",
            state="disabled",
            padx=10,
            pady=8,
            cursor="arrow",
            takefocus=True,
        )
        transcript_scroll = ttk.Scrollbar(
            transcript_body,
            orient="vertical",
            command=self.conversation_text.yview,
        )
        self.conversation_text.configure(yscrollcommand=transcript_scroll.set)
        self.conversation_text.pack(side="left", fill="both", expand=True)
        transcript_scroll.pack(side="right", fill="y")
        self.conversation_text.tag_configure(
            "received_meta",
            justify="left",
            font=("TkDefaultFont", 9, "bold"),
            spacing1=8,
        )
        self.conversation_text.tag_configure(
            "received_body",
            justify="left",
            lmargin1=12,
            lmargin2=12,
            rmargin=90,
            spacing3=3,
        )
        self.conversation_text.tag_configure(
            "sent_meta",
            justify="right",
            font=("TkDefaultFont", 9, "bold"),
            spacing1=8,
        )
        self.conversation_text.tag_configure(
            "sent_body",
            justify="right",
            lmargin1=90,
            lmargin2=90,
            rmargin=12,
            spacing3=3,
        )
        self.conversation_text.tag_configure(
            "received_status",
            justify="left",
            lmargin1=12,
            font=("TkDefaultFont", 8, "italic"),
        )
        self.conversation_text.tag_configure(
            "sent_status",
            justify="right",
            rmargin=12,
            font=("TkDefaultFont", 8, "italic"),
        )
        self.conversation_text.tag_configure(
            "empty",
            justify="center",
            spacing1=20,
        )
        self.conversation_text.tag_configure(
            "selected_message",
            relief="groove",
            borderwidth=1,
        )

        self.message_action_menu = tk.Menu(self, tearoff=False)
        self.message_action_menu.add_command(
            label=self._t("messages.reply"), command=self._reply_selected_message
        )
        self.message_action_menu.add_command(
            label=self._t("messages.quote_reply"), command=self._quote_selected_message
        )
        self.message_action_menu.add_separator()
        self.message_action_menu.add_command(
            label=self._t("messages.copy_selected"), command=self.copy_marked_messages
        )
        self.message_action_menu.add_command(
            label=self._t("messages.details"), command=self._show_message_details
        )
        # The message action popup uses tk_popup followed by grab_release, just
        # like the edit menu.  Add explicit dismissal handlers so Esc, a normal
        # left-click outside the menu, and focus loss close the menu without
        # requiring the user to choose a command.
        self.bind_all(
            "<Escape>",
            self._dismiss_message_action_menu_event,
            add="+",
        )
        self.bind_all(
            "<Button-1>",
            self._dismiss_message_action_menu_on_left_click,
            add="+",
        )
        self.bind_all(
            "<FocusOut>",
            self._schedule_message_action_focus_check,
            add="+",
        )
        self.message_action_menu.bind(
            "<Unmap>",
            self._message_action_menu_unmapped,
            add="+",
        )

        conversation_panes.add(conversation_list_frame, weight=1)
        conversation_panes.add(transcript_frame, weight=3)

        compose = ttk.LabelFrame(self.messages_tab, text=self._t("messages.compose"), padding=10)
        compose.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Label(compose, text=self._t("messages.network")).grid(row=0, column=0, sticky="w")
        self.network_combo = ttk.Combobox(compose, state="readonly", width=29)
        self.network_combo["values"] = [self.networks[key]["label"] for key in self.network_order]
        if self.network_order:
            self.network_combo.current(0)
        else:
            self.network_combo.set(self._t("modular.not_configured"))
            self.network_combo.configure(state="disabled")
        self.network_combo.grid(row=0, column=1, sticky="w", padx=(6, 18))
        self.network_combo.bind("<<ComboboxSelected>>", self._selection_changed)
        ttk.Label(compose, text=self._t("messages.type")).grid(row=0, column=2, sticky="w")
        self.type_combo = ttk.Combobox(compose, state="readonly", width=18)
        self.type_combo.grid(row=0, column=3, sticky="w", padx=(6, 18))
        self.type_combo.bind("<<ComboboxSelected>>", self._selection_changed)
        ttk.Label(compose, text=self._t("messages.recipient")).grid(row=0, column=4, sticky="w")
        self.recipient_combo = ttk.Combobox(compose, state="readonly", width=34)
        self.recipient_combo.grid(row=0, column=5, sticky="ew", padx=(6, 8))
        self.recipient_combo.bind("<<ComboboxSelected>>", self._recipient_changed)
        self.favorite_only_var = tk.BooleanVar(
            value=bool(self.ui_state.get("favorite_recipients_only", False))
        )
        ttk.Checkbutton(
            compose,
            text=self._t("messages.favorite_only"),
            variable=self.favorite_only_var,
            command=self._favorite_only_changed,
        ).grid(row=0, column=6, sticky="w")
        self.route_label = ttk.Label(
            compose, text=self._t("messages.route_placeholder"), foreground="#374151", wraplength=1240,
        )
        self.route_label.grid(row=1, column=0, columnspan=7, sticky="w", pady=(8, 4))
        ttk.Label(compose, text=self._t("messages.message")).grid(row=2, column=0, sticky="nw", pady=(6, 0))
        self.message_text = tk.Text(compose, height=4, wrap="word", undo=True)
        self.message_text.grid(row=2, column=1, columnspan=6, sticky="ew", padx=(6, 0), pady=(6, 0))
        self.message_text.bind("<Control-Return>", lambda event: self.send_selected())
        self.message_text.bind("<KeyRelease>", self._update_counter)
        self.counter_label = ttk.Label(compose, text=self._t("messages.bytes_written", count=0))
        self.counter_label.grid(row=3, column=1, columnspan=5, sticky="w", pady=(5, 0))
        self.send_button = ttk.Button(compose, text=self._t("messages.send"), command=self.send_selected)
        self.send_button.grid(row=3, column=6, sticky="e", pady=(5, 0))
        compose.columnconfigure(5, weight=1)
        self._show_message_view()
        self._selection_changed()

    def _build_nodes_tab(self) -> None:
        outer = ttk.Frame(self.nodes_tab, padding=8)
        outer.pack(fill="both", expand=True)
        ttk.Label(
            outer,
            text=self._t("nodes.description"),
            wraplength=1200,
        ).pack(fill="x", pady=(0, 6))

        filters = ttk.LabelFrame(outer, text=self._t("nodes.filters"), padding=8)
        filters.pack(fill="x", pady=(0, 8))
        self.node_search_var = tk.StringVar()
        self.node_network_filter_var = tk.StringVar(value=self._t("nodes.filter.network_all"))
        self.node_type_filter_var = tk.StringVar(value=self._t("nodes.filter.type_all"))
        self.node_favorite_filter_var = tk.StringVar(value=self._t("nodes.filter.all"))
        self.node_manual_filter_var = tk.StringVar(value=self._t("nodes.filter.all"))
        self.node_from_filter_var = tk.StringVar()
        self.node_to_filter_var = tk.StringVar()
        ttk.Label(filters, text=self._t("common.search")).grid(row=0, column=0, sticky="w")
        node_search = ttk.Entry(filters, textvariable=self.node_search_var, width=24)
        node_search.grid(row=0, column=1, sticky="ew", padx=(5, 10))
        node_search.bind("<Return>", lambda _event: self._apply_node_filters())
        ttk.Label(filters, text=self._t("nodes.network")).grid(row=0, column=2, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=22,
            textvariable=self.node_network_filter_var,
            values=[self._t("nodes.filter.network_all")] + [self.networks[key]["label"] for key in self.network_order],
        ).grid(row=0, column=3, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("common.type")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=16,
            textvariable=self.node_type_filter_var,
            values=[self._t("nodes.filter.type_all"), self._t("nodes.filter.type_contacts"), self._t("nodes.filter.type_without_alias")],
        ).grid(row=0, column=5, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("nodes.favorite")).grid(row=0, column=6, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=14,
            textvariable=self.node_favorite_filter_var,
            values=[self._t("nodes.filter.all"), self._t("nodes.filter.favorite_only"), self._t("nodes.filter.not_favorite")],
        ).grid(row=0, column=7, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("nodes.source")).grid(row=0, column=8, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=14,
            textvariable=self.node_manual_filter_var,
            values=[self._t("nodes.filter.all"), self._t("nodes.filter.manual"), self._t("nodes.filter.discovered")],
        ).grid(row=0, column=9, sticky="w", padx=(5, 0))
        ttk.Label(filters, text=self._t("common.from")).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.node_from_filter_var, width=20).grid(
            row=1, column=1, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Label(filters, text=self._t("common.to")).grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.node_to_filter_var, width=20).grid(
            row=1, column=3, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.apply_filter"), command=self._apply_node_filters).grid(
            row=1, column=7, sticky="e", padx=(0, 6), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.reset"), command=self._clear_node_filters).grid(
            row=1, column=8, sticky="ew", pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.export"), command=self.export_nodes).grid(
            row=1, column=9, sticky="ew", padx=(6, 0), pady=(6, 0)
        )
        filters.columnconfigure(1, weight=1)
        self.node_filter_result_label = ttk.Label(filters, text=self._t("nodes.result.all"))
        self.node_filter_result_label.grid(row=2, column=0, columnspan=10, sticky="w", pady=(5, 0))

        frame = ttk.Frame(outer)
        frame.pack(fill="both", expand=True)
        table_frame = ttk.Frame(frame)
        table_frame.pack(side="left", fill="both", expand=True)
        columns = (
            "network", "favorite", "alias", "name", "id", "short",
            "role", "last", "state", "position", "position_age",
        )
        self.node_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="extended"
        )
        heads = {
            "network": self._t("nodes.column.network"),
            "favorite": self._t("nodes.column.favorite"),
            "alias": self._t("nodes.column.alias"),
            "name": self._t("nodes.column.name"),
            "id": self._t("nodes.column.id"),
            "short": self._t("nodes.column.short"),
            "role": self._t("nodes.column.role"),
            "last": self._t("nodes.column.last"),
            "state": self._t("nodes.column.state"),
            "position": self._t("nodes.column.position"),
            "position_age": self._t("nodes.column.position_age"),
        }
        widths = {
            "network": 150, "favorite": 65, "alias": 140, "name": 205,
            "id": 155, "short": 75, "role": 125, "last": 145, "state": 125,
            "position": 185, "position_age": 125,
        }
        for col in columns:
            self.node_tree.heading(col, text=heads[col])
            self.node_tree.column(col, width=widths[col], anchor="w")
        scroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.node_tree.yview
        )
        horizontal = ttk.Scrollbar(
            table_frame, orient="horizontal", command=self.node_tree.xview
        )
        self.node_tree.configure(
            yscrollcommand=scroll.set, xscrollcommand=horizontal.set
        )
        self.node_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        buttons = ttk.Frame(frame, padding=(10, 0))
        buttons.pack(side="right", fill="y")
        self.node_refresh_button = ttk.Button(
            buttons, text=self._t("nodes.refresh"), command=lambda: self.request_all_nodes(force=True)
        )
        self.node_refresh_button.pack(fill="x", pady=3)
        ttk.Button(buttons, text=self._t("nodes.add_id"), command=self.add_manual_node).pack(fill="x", pady=3)
        ttk.Button(buttons, text=self._t("nodes.set_alias"), command=self.set_selected_alias).pack(fill="x", pady=3)
        ttk.Button(buttons, text=self._t("nodes.toggle_favorite"), command=self.toggle_selected_favorite).pack(fill="x", pady=3)
        ttk.Button(buttons, text=self._t("nodes.use_recipient"), command=self.use_selected_node).pack(fill="x", pady=3)
        ttk.Button(
            buttons,
            text=self._t("nodes.open_conversation"),
            command=self.open_selected_node_conversation,
        ).pack(fill="x", pady=3)
        ttk.Separator(buttons, orient="horizontal").pack(fill="x", pady=8)
        ttk.Button(buttons, text=self._t("nodes.export_contacts"), command=self.export_contacts).pack(fill="x", pady=3)
        ttk.Button(buttons, text=self._t("nodes.import_contacts"), command=self.import_contacts).pack(fill="x", pady=3)
        details = ttk.LabelFrame(
            outer, text=self._t("nodes.position_details"), padding=8
        )
        details.pack(fill="x", pady=(8, 0))
        self.node_position_detail_var = tk.StringVar(
            value=self._t("nodes.position_choose")
        )
        ttk.Label(
            details,
            textvariable=self.node_position_detail_var,
            justify="left",
            wraplength=1280,
        ).pack(fill="x")

        privacy = ttk.LabelFrame(
            outer, text=self._t("nodes.privacy"), padding=8
        )
        privacy.pack(fill="x", pady=(8, 0))
        self.position_storage_enabled_var = tk.BooleanVar(
            value=self.position_store.storage_enabled()
        )
        self.position_stale_minutes_var = tk.StringVar(
            value=str(self.position_store.stale_minutes())
        )
        self.position_privacy_status_var = tk.StringVar()
        ttk.Checkbutton(
            privacy,
            text=self._t("nodes.position_store"),
            variable=self.position_storage_enabled_var,
            command=self._set_position_storage_enabled,
        ).grid(row=0, column=0, sticky="w", padx=(0, 14))
        ttk.Label(privacy, text=self._t("nodes.stale_after")).grid(
            row=0, column=1, sticky="e"
        )
        stale_entry = ttk.Combobox(
            privacy,
            width=9,
            textvariable=self.position_stale_minutes_var,
            values=("5", "15", "30", "60", "180", "360", "720", "1440", "10080"),
        )
        stale_entry.grid(row=0, column=2, sticky="w", padx=(6, 6))
        stale_entry.bind(
            "<Return>", lambda _event: self._save_position_stale_minutes()
        )
        ttk.Button(
            privacy,
            text=self._t("nodes.save_stale"),
            command=self._save_position_stale_minutes,
        ).grid(row=0, column=3, sticky="w", padx=(0, 14))
        ttk.Button(
            privacy,
            text=self._t("nodes.delete_positions"),
            command=self._delete_all_positions,
        ).grid(row=0, column=4, sticky="e")
        ttk.Label(
            privacy,
            textvariable=self.position_privacy_status_var,
            wraplength=1250,
            justify="left",
        ).grid(row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))
        privacy.columnconfigure(0, weight=1)
        self._refresh_position_privacy_controls()

        self.node_tree.bind(
            "<<TreeviewSelect>>", self._node_selection_changed
        )
        self.node_tree.bind("<Double-1>", lambda _event: self.open_selected_node_conversation())

    def _build_position_history_tab(self) -> None:
        """Build the local, non-map position-history view."""
        outer = ttk.Frame(self.position_history_tab, padding=10)
        outer.pack(fill="both", expand=True)
        ttk.Label(
            outer,
            text=self._t("position_history.description"),
            wraplength=1240,
        ).pack(fill="x", pady=(0, 8))

        filters = ttk.LabelFrame(outer, text=self._t("position_history.filters"), padding=8)
        filters.pack(fill="x", pady=(0, 8))
        self.position_history_network_var = tk.StringVar(value=self._t("position_history.filter.network_all"))
        self.position_history_node_var = tk.StringVar()
        self.position_history_limit_var = tk.StringVar(value="250")
        ttk.Label(filters, text=self._t("position_history.network")).grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            filters,
            state="readonly",
            width=24,
            textvariable=self.position_history_network_var,
            values=[self._t("position_history.filter.network_all")]
            + [
                self.networks[key]["label"]
                for key in self.network_order
                if self.networks[key].get("kind") != "waveshare"
            ],
        ).grid(row=0, column=1, sticky="w", padx=(6, 12))
        ttk.Label(filters, text=self._t("position_history.node")).grid(
            row=0, column=2, sticky="w"
        )
        node_entry = ttk.Entry(
            filters,
            width=28,
            textvariable=self.position_history_node_var,
        )
        node_entry.grid(row=0, column=3, sticky="ew", padx=(6, 12))
        node_entry.bind(
            "<Return>", lambda _event: self._refresh_position_history_view(force=True)
        )
        ttk.Label(filters, text=self._t("position_history.max_rows")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters,
            state="readonly",
            width=8,
            textvariable=self.position_history_limit_var,
            values=("50", "100", "250", "500", "1000"),
        ).grid(row=0, column=5, sticky="w", padx=(6, 12))
        ttk.Button(
            filters,
            text=self._t("action.apply_filter"),
            command=lambda: self._refresh_position_history_view(force=True),
        ).grid(row=0, column=6, sticky="e", padx=(0, 6))
        ttk.Button(
            filters,
            text=self._t("action.reset"),
            command=self._clear_position_history_filters,
        ).grid(row=0, column=7, sticky="e", padx=(0, 6))
        self.position_history_sync_button = ttk.Button(
            filters,
            text=self._t("position_history.sync"),
            command=self.request_all_position_history,
        )
        self.position_history_sync_button.grid(row=0, column=8, sticky="e")
        self.position_history_export_button = ttk.Button(
            filters,
            text=self._t("action.export"),
            command=self.export_position_history,
        )
        self.position_history_export_button.grid(row=0, column=9, sticky="e", padx=(6, 0))
        filters.columnconfigure(3, weight=1)
        self.position_history_status_var = tk.StringVar(
            value=self._t("position_history.status.initial")
        )
        ttk.Label(
            filters,
            textvariable=self.position_history_status_var,
            wraplength=1240,
        ).grid(row=1, column=0, columnspan=10, sticky="w", pady=(6, 0))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill="both", expand=True)
        columns = (
            "time",
            "network",
            "node",
            "coordinates",
            "altitude",
            "precision",
            "gnss",
            "signal",
            "source",
        )
        self.position_history_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="extended",
        )
        headings = {
            "time": self._t("position_history.column.time"),
            "network": self._t("position_history.column.network"),
            "node": self._t("position_history.column.node"),
            "coordinates": self._t("position_history.column.coordinates"),
            "altitude": self._t("position_history.column.altitude"),
            "precision": self._t("position_history.column.precision"),
            "gnss": self._t("position_history.column.gnss"),
            "signal": self._t("position_history.column.signal"),
            "source": self._t("position_history.column.source"),
        }
        widths = {
            "time": 165,
            "network": 145,
            "node": 180,
            "coordinates": 190,
            "altitude": 80,
            "precision": 85,
            "gnss": 165,
            "signal": 150,
            "source": 210,
        }
        for column in columns:
            self.position_history_tree.heading(column, text=headings[column])
            self.position_history_tree.column(
                column,
                width=widths[column],
                anchor="w",
            )
        vertical = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.position_history_tree.yview,
        )
        horizontal = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.position_history_tree.xview,
        )
        self.position_history_tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        self.position_history_tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self._refresh_position_history_view(force=True)


    def _build_map_tab(self) -> None:
        """Build the local offline-map preview tab."""
        outer = ttk.Frame(self.map_tab, padding=10)
        outer.pack(fill="both", expand=True)
        self.map_visibility_preset_var = tk.StringVar(value=DEFAULT_VISIBILITY_PRESET)
        self.map_track_tail_preset_var = tk.StringVar(value=DEFAULT_TRACK_TAIL_PRESET)
        self.map_visibility_display_var = tk.StringVar()
        self.map_track_tail_display_var = tk.StringVar()
        mode_bar = ttk.Frame(outer)
        mode_bar.pack(fill="x", pady=(0, 8))
        self.map_mode_status_var = tk.StringVar(value=self._t("map_mode.status.offline"))
        ttk.Label(mode_bar, textvariable=self.map_mode_status_var).pack(side="left")
        self.offline_map_mode_button = ttk.Button(mode_bar)
        self.offline_map_mode_button.pack(side="right")
        self.offline_map_viewport_mode_var = tk.StringVar(value="all")
        self.offline_map_viewport_display_var = tk.StringVar()
        self.offline_map_track_tail_combo = ttk.Combobox(mode_bar,state="readonly",width=10,textvariable=self.map_track_tail_display_var,values=[])
        self.offline_map_track_tail_combo.pack(side="right",padx=(4,10))
        self.offline_map_track_tail_combo.bind("<<ComboboxSelected>>",lambda _e:self._temporal_map_controls_changed())
        ttk.Label(mode_bar,text=self._t("map.track_tail")).pack(side="right")
        self.offline_map_visibility_combo = ttk.Combobox(mode_bar,state="readonly",width=10,textvariable=self.map_visibility_display_var,values=[])
        self.offline_map_visibility_combo.pack(side="right",padx=(4,10))
        self.offline_map_visibility_combo.bind("<<ComboboxSelected>>",lambda _e:self._temporal_map_controls_changed())
        ttk.Label(mode_bar,text=self._t("map.visibility_window")).pack(side="right")
        self._refresh_temporal_control_presentation()
        ttk.Label(
            outer,
            text=self._t("map.description"),
            wraplength=1240,
        ).pack(fill="x", pady=(0, 8))

        viewport_controls = ttk.LabelFrame(
            outer, text=self._t("offline_map.viewport"), padding=8
        )
        viewport_controls.pack(fill="x", pady=(0, 8))
        self.offline_map_lat_var = tk.StringVar(
            value=str(
                self.config.get(
                    "offline_map_center_latitude",
                    self.config.get("online_map_center_latitude", "61.0"),
                )
            )
        )
        self.offline_map_lon_var = tk.StringVar(
            value=str(
                self.config.get(
                    "offline_map_center_longitude",
                    self.config.get("online_map_center_longitude", "10.0"),
                )
            )
        )
        self.offline_map_zoom_var = tk.StringVar(
            value=str(
                self.config.get(
                    "offline_map_zoom",
                    self.config.get("online_map_zoom", "8"),
                )
            )
        )
        ttk.Label(viewport_controls, text=self._t("map.viewport_filter")).grid(
            row=0, column=0, sticky="w"
        )
        self.offline_map_viewport_combo = ttk.Combobox(
            viewport_controls,
            state="readonly",
            width=10,
            textvariable=self.offline_map_viewport_display_var,
            values=[],
        )
        self.offline_map_viewport_combo.grid(
            row=0, column=1, sticky="w", padx=(6, 12)
        )
        self.offline_map_viewport_combo.bind(
            "<<ComboboxSelected>>",
            lambda _e: self._offline_viewport_control_changed(),
        )
        self._refresh_offline_viewport_control_presentation()
        ttk.Label(viewport_controls, text=self._t("offline_map.latitude")).grid(
            row=0, column=2, sticky="w"
        )
        ttk.Entry(
            viewport_controls, width=12, textvariable=self.offline_map_lat_var
        ).grid(row=0, column=3, sticky="w", padx=(6, 12))
        ttk.Label(viewport_controls, text=self._t("offline_map.longitude")).grid(
            row=0, column=4, sticky="w"
        )
        ttk.Entry(
            viewport_controls, width=12, textvariable=self.offline_map_lon_var
        ).grid(row=0, column=5, sticky="w", padx=(6, 12))
        ttk.Label(viewport_controls, text=self._t("offline_map.zoom")).grid(
            row=0, column=6, sticky="w"
        )
        ttk.Spinbox(
            viewport_controls,
            from_=0,
            to=18,
            width=5,
            textvariable=self.offline_map_zoom_var,
        ).grid(row=0, column=7, sticky="w", padx=(6, 12))
        ttk.Button(
            viewport_controls,
            text=self._t("offline_map.center_data"),
            command=self._center_offline_map_on_local_data,
        ).grid(row=0, column=8, sticky="e", padx=(0, 6))
        ttk.Button(
            viewport_controls,
            text=self._t("offline_map.refresh_data"),
            command=self._refresh_offline_map_from_viewport,
        ).grid(row=0, column=9, sticky="e")
        viewport_controls.columnconfigure(9, weight=1)

        filters = ttk.LabelFrame(outer, text=self._t("map.filters"), padding=8)
        filters.pack(fill="x", pady=(0, 8))
        self.offline_map_network_var = tk.StringVar(value=self._t("map.filter.network_all"))
        self.offline_map_node_var = tk.StringVar()
        self.offline_map_limit_var = tk.StringVar(value="250")
        ttk.Label(filters, text=self._t("map.network")).grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            filters,
            state="readonly",
            width=24,
            textvariable=self.offline_map_network_var,
            values=[self._t("map.filter.network_all")]
            + [
                self.networks[key]["label"]
                for key in self.network_order
                if self.networks[key].get("kind") != "waveshare"
            ],
        ).grid(row=0, column=1, sticky="w", padx=(6, 12))
        ttk.Label(filters, text=self._t("map.node")).grid(row=0, column=2, sticky="w")
        map_node_entry = ttk.Entry(filters, width=28, textvariable=self.offline_map_node_var)
        map_node_entry.grid(row=0, column=3, sticky="ew", padx=(6, 12))
        map_node_entry.bind("<Return>", lambda _event: self._start_map_refresh(force=True))
        ttk.Label(filters, text=self._t("map.history_points")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters,
            state="readonly",
            width=8,
            textvariable=self.offline_map_limit_var,
            values=["50", "100", "250", "500", "1000"],
        ).grid(row=0, column=5, sticky="w", padx=(6, 12))
        self.offline_map_aprs_var = tk.BooleanVar(
            value=bool(self.config.get("map_aprs_layer_enabled", True))
        )
        aprs_check = ttk.Checkbutton(
            filters, text=self._t("map.layer.aprs"), variable=self.offline_map_aprs_var,
            command=lambda: self._refresh_map_view(force=True),
        )
        aprs_check.grid(row=0, column=8, sticky="w", padx=(12, 0))
        if not self.aprs_field_sync_enabled:
            aprs_check.configure(state="disabled")
        ttk.Label(filters, text=self._t("map.package.label")).grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.operator_map_display_var = tk.StringVar(value=self._t("map.package.auto"))
        self.operator_map_combo = ttk.Combobox(
            filters, state="readonly", width=52, textvariable=self.operator_map_display_var, values=[]
        )
        self.operator_map_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=(6, 12), pady=(8, 0))
        self.operator_map_combo.bind("<<ComboboxSelected>>", lambda _e: self._operator_map_selection_changed())
        self.operator_map_install_button = ttk.Button(
            filters,
            text=self._t("map.package.install"),
            command=self._install_offline_mbtiles,
        )
        self.operator_map_install_button.grid(
            row=1, column=4, sticky="w", padx=(0, 12), pady=(8, 0)
        )
        self.operator_map_metadata_var = tk.StringVar(value=self._t("map.package.metadata_auto"))
        ttk.Label(filters, textvariable=self.operator_map_metadata_var, wraplength=650).grid(
            row=1, column=5, columnspan=4, sticky="w", pady=(8, 0)
        )
        self._refresh_operator_map_inventory()
        ttk.Button(filters, text=self._t("map.refresh"), command=lambda: self._start_map_refresh(force=True)).grid(
            row=0, column=6, sticky="e", padx=(0, 6)
        )
        ttk.Button(filters, text=self._t("action.reset"), command=self._clear_map_filters).grid(
            row=0, column=7, sticky="w"
        )
        filters.columnconfigure(3, weight=1)

        self.offline_map_status_var = tk.StringVar(value=self._t("map.status.initial"))
        ttk.Label(outer, textvariable=self.offline_map_status_var, wraplength=1240).pack(
            fill="x", pady=(0, 8)
        )

        panes = ttk.Panedwindow(outer, orient="horizontal")
        panes.pack(fill="both", expand=True)

        map_frame = ttk.LabelFrame(panes, text=self._t("map.local_view"), padding=8)
        panes.add(map_frame, weight=2)
        map_frame.columnconfigure(0, weight=1)
        map_frame.rowconfigure(0, weight=1)
        self.offline_map_canvas = tk.Canvas(
            map_frame,
            width=620,
            height=420,
            background="white",
            highlightthickness=1,
            highlightbackground="#b0b0b0",
        )
        self.offline_map_canvas.grid(row=0, column=0, sticky="nsew")
        self.offline_map_canvas.bind(
            "<Configure>",
            self._on_offline_map_canvas_configure,
            add="+",
        )

        # Map identity and attribution belong outside the raster canvas. This
        # prevents long licence text from covering the map or position layer.
        self.offline_map_info_var = tk.StringVar(value=self._t("map.info.initial"))
        self.offline_map_info_label = ttk.Label(
            map_frame,
            textvariable=self.offline_map_info_var,
            anchor="w",
            justify="left",
            wraplength=600,
        )
        self.offline_map_info_label.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        map_frame.bind(
            "<Configure>",
            lambda event: self.offline_map_info_label.configure(
                wraplength=max(180, int(event.width) - 24)
            ),
        )

        data_frame = ttk.Frame(panes)
        panes.add(data_frame, weight=3)

        latest_frame = ttk.LabelFrame(data_frame, text=self._t("map.latest_per_node"), padding=6)
        latest_frame.pack(fill="both", expand=True, pady=(0, 6))
        latest_columns = ("network", "node", "position", "time", "precision", "source")
        self.offline_map_latest_tree = ttk.Treeview(
            latest_frame,
            columns=latest_columns,
            show="headings",
            selectmode="browse",
            height=6,
        )
        latest_headings = {
            "network": self._t("map.column.network"),
            "node": self._t("map.column.node"),
            "position": self._t("map.column.position"),
            "time": self._t("map.column.time"),
            "precision": self._t("map.column.precision"),
            "source": self._t("map.column.source"),
        }
        latest_widths = {
            "network": 135,
            "node": 180,
            "position": 190,
            "time": 155,
            "precision": 85,
            "source": 95,
        }
        for column in latest_columns:
            self.offline_map_latest_tree.heading(column, text=latest_headings[column])
            self.offline_map_latest_tree.column(
                column,
                width=latest_widths[column],
                anchor="w",
                stretch=column in {"node", "position"},
            )
        latest_scroll = ttk.Scrollbar(
            latest_frame, orient="vertical", command=self.offline_map_latest_tree.yview
        )
        self.offline_map_latest_tree.configure(yscrollcommand=latest_scroll.set)
        self.offline_map_latest_tree.pack(side="left", fill="both", expand=True)
        latest_scroll.pack(side="right", fill="y")
        self.offline_map_latest_tree.bind(
            "<<TreeviewSelect>>", self._on_map_latest_selected, add="+"
        )

        details_frame = ttk.LabelFrame(
            data_frame, text=self._t("map.details_title"), padding=6
        )
        details_frame.pack(fill="x", pady=(0, 6))
        self.offline_map_detail_var = tk.StringVar(value=self._t("map.details.initial"))
        ttk.Label(
            details_frame,
            textvariable=self.offline_map_detail_var,
            anchor="w",
            justify="left",
            wraplength=720,
        ).pack(fill="x")

        history_frame = ttk.LabelFrame(data_frame, text=self._t("map.history_title"), padding=6)
        history_frame.pack(fill="both", expand=True)
        history_columns = ("time", "network", "node", "position", "source")
        self.offline_map_history_tree = ttk.Treeview(
            history_frame,
            columns=history_columns,
            show="headings",
            selectmode="browse",
            height=8,
        )
        history_headings = {
            "time": self._t("map.column.time"),
            "network": self._t("map.column.network"),
            "node": self._t("map.column.node"),
            "position": self._t("map.column.position"),
            "source": self._t("map.column.source"),
        }
        history_widths = {
            "time": 155,
            "network": 135,
            "node": 180,
            "position": 190,
            "source": 95,
        }
        for column in history_columns:
            self.offline_map_history_tree.heading(column, text=history_headings[column])
            self.offline_map_history_tree.column(
                column,
                width=history_widths[column],
                anchor="w",
                stretch=column in {"node", "position"},
            )
        history_scroll = ttk.Scrollbar(
            history_frame, orient="vertical", command=self.offline_map_history_tree.yview
        )
        self.offline_map_history_tree.configure(yscrollcommand=history_scroll.set)
        self.offline_map_history_tree.pack(side="left", fill="both", expand=True)
        history_scroll.pack(side="right", fill="y")
        self._refresh_map_view(force=True)

    def _build_online_map_tab(self) -> None:
        """Build the R2-D.1 online OSM candidate without implicit network I/O."""
        outer = ttk.Frame(self.online_map_tab, padding=10)
        outer.pack(fill="both", expand=True)
        mode_bar = ttk.Frame(outer)
        mode_bar.pack(fill="x", pady=(0, 8))
        self.online_map_mode_status_var = tk.StringVar(value=self._t("map_mode.status.offline"))
        ttk.Label(mode_bar, textvariable=self.online_map_mode_status_var).pack(side="left")
        self.online_map_mode_button = ttk.Button(mode_bar)
        self.online_map_mode_button.pack(side="right")
        self.online_map_track_tail_combo = ttk.Combobox(mode_bar,state="readonly",width=10,textvariable=self.map_track_tail_display_var,values=[])
        self.online_map_track_tail_combo.pack(side="right",padx=(4,10))
        self.online_map_track_tail_combo.bind("<<ComboboxSelected>>",lambda _e:self._temporal_map_controls_changed())
        ttk.Label(mode_bar,text=self._t("map.track_tail")).pack(side="right")
        self.online_map_visibility_combo = ttk.Combobox(mode_bar,state="readonly",width=10,textvariable=self.map_visibility_display_var,values=[])
        self.online_map_visibility_combo.pack(side="right",padx=(4,10))
        self.online_map_visibility_combo.bind("<<ComboboxSelected>>",lambda _e:self._temporal_map_controls_changed())
        ttk.Label(mode_bar,text=self._t("map.visibility_window")).pack(side="right")
        self._refresh_temporal_control_presentation()

        ttk.Label(
            outer,
            text=self._t("online_map.description"),
            wraplength=1240,
        ).pack(fill="x", pady=(0, 8))

        controls = ttk.LabelFrame(outer, text=self._t("online_map.viewport"), padding=8)
        controls.pack(fill="x", pady=(0, 8))
        self.online_map_lat_var = tk.StringVar(
            value=str(self.config.get("online_map_center_latitude", "61.0"))
        )
        self.online_map_lon_var = tk.StringVar(
            value=str(self.config.get("online_map_center_longitude", "10.0"))
        )
        self.online_map_zoom_var = tk.StringVar(
            value=str(self.config.get("online_map_zoom", "8"))
        )
        ttk.Label(controls, text=self._t("online_map.latitude")).grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, width=12, textvariable=self.online_map_lat_var).grid(
            row=0, column=1, sticky="w", padx=(5, 10)
        )
        ttk.Label(controls, text=self._t("online_map.longitude")).grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, width=12, textvariable=self.online_map_lon_var).grid(
            row=0, column=3, sticky="w", padx=(5, 10)
        )
        ttk.Label(controls, text=self._t("online_map.zoom")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            controls,
            state="readonly",
            width=5,
            textvariable=self.online_map_zoom_var,
            values=[str(value) for value in range(2, 19)],
        ).grid(row=0, column=5, sticky="w", padx=(5, 10))
        ttk.Button(
            controls,
            text=self._t("online_map.center_data"),
            command=self._center_online_map_on_local_data,
        ).grid(row=0, column=6, sticky="w", padx=(0, 6))
        ttk.Button(
            controls,
            text=self._t("online_map.refresh_data"),
            command=self._refresh_online_map_rows,
        ).grid(row=0, column=7, sticky="w", padx=(0, 6))
        self.online_map_load_button = ttk.Button(
            controls,
            text=self._t("online_map.load_osm"),
            command=self._start_online_map_render,
        )
        self.online_map_load_button.grid(row=0, column=8, sticky="e")
        controls.columnconfigure(8, weight=1)

        aprs_is_bar = ttk.Frame(outer)
        aprs_is_bar.pack(fill="x", pady=(0, 8))
        self.field_aprs_is_presentation_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            aprs_is_bar,
            text=self._t("field_aprs_is.presentation_toggle"),
            variable=self.field_aprs_is_presentation_var,
            command=self._toggle_field_aprs_is_presentation,
        ).pack(side="left")
        self.field_aprs_is_arm_button = ttk.Button(
            aprs_is_bar, text=self._t("field_aprs_is.live.arm"), command=self._arm_field_aprs_is_live
        )
        self.field_aprs_is_arm_button.pack(side="left", padx=(10, 4))
        self.field_aprs_is_start_button = ttk.Button(
            aprs_is_bar, text=self._t("field_aprs_is.live.start"), command=self._start_field_aprs_is_live
        )
        self.field_aprs_is_start_button.pack(side="left", padx=4)
        self.field_aprs_is_stop_button = ttk.Button(
            aprs_is_bar, text=self._t("field_aprs_is.live.stop"), command=self._stop_field_aprs_is_live
        )
        self.field_aprs_is_stop_button.pack(side="left", padx=4)
        self.field_aprs_is_status_var = tk.StringVar(
            value=self._t("field_aprs_is.status.off")
        )
        ttk.Label(aprs_is_bar, textvariable=self.field_aprs_is_status_var).pack(side="right")

        self.online_map_status_var = tk.StringVar(value=self._t("online_map.status.initial"))
        ttk.Label(outer, textvariable=self.online_map_status_var, wraplength=1240).pack(
            fill="x", pady=(0, 8)
        )

        panes = ttk.Panedwindow(outer, orient="horizontal")
        panes.pack(fill="both", expand=True)
        map_frame = ttk.LabelFrame(panes, text=self._t("online_map.map_title"), padding=8)
        panes.add(map_frame, weight=2)
        map_frame.columnconfigure(0, weight=1)
        map_frame.rowconfigure(0, weight=1)
        self.online_map_canvas = tk.Canvas(
            map_frame,
            width=620,
            height=420,
            background="white",
            highlightthickness=1,
            highlightbackground="#b0b0b0",
        )
        self.online_map_canvas.grid(row=0, column=0, sticky="nsew")
        self.online_map_canvas.create_text(
            16,
            16,
            anchor="nw",
            text=self._t("online_map.not_loaded"),
            width=560,
        )

        data_frame = ttk.LabelFrame(panes, text=self._t("online_map.visible_entities"), padding=6)
        panes.add(data_frame, weight=3)
        columns = ("network", "node", "position", "time", "source")
        self.online_map_tree = ttk.Treeview(
            data_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "network": self._t("map.column.network"),
            "node": self._t("map.column.node"),
            "position": self._t("map.column.position"),
            "time": self._t("map.column.time"),
            "source": self._t("map.column.source"),
        }
        widths = {"network": 110, "node": 180, "position": 190, "time": 155, "source": 130}
        for column in columns:
            self.online_map_tree.heading(column, text=headings[column])
            self.online_map_tree.column(column, width=widths[column], anchor="w")
        scroll = ttk.Scrollbar(data_frame, orient="vertical", command=self.online_map_tree.yview)
        self.online_map_tree.configure(yscrollcommand=scroll.set)
        self.online_map_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._refresh_online_map_rows()
        self._refresh_map_mode_controls()

    def _refresh_map_mode_controls(self) -> None:
        """Render one authoritative OFFLINE/ONLINE state on both map tabs."""
        presentation = presentation_for_mode(self.map_operator_mode)
        status_text = self._t(presentation.status_key)
        action_text = self._t(presentation.action_key)
        if hasattr(self, "map_mode_status_var"):
            self.map_mode_status_var.set(status_text)
        if hasattr(self, "online_map_mode_status_var"):
            self.online_map_mode_status_var.set(status_text)
        command = (
            self._operator_select_online_map
            if presentation.target_mode is MapOperatorMode.ONLINE
            else self._operator_select_offline_map
        )
        for button_name in ("offline_map_mode_button", "online_map_mode_button"):
            button = getattr(self, button_name, None)
            if button is not None:
                button.configure(text=action_text, command=command)

    def _operator_select_online_map(self) -> None:
        """Enter ONLINE operator mode without performing network I/O."""
        self.map_operator_mode = MapOperatorMode.ONLINE
        self._refresh_map_mode_controls()
        try:
            self.notebook.select(self.online_map_tab)
        except (AttributeError, tk.TclError):
            pass
        if hasattr(self, "online_map_status_var"):
            self.online_map_status_var.set(self._t("online_map.status.online_selected"))

    def _operator_select_offline_map(self, *, fallback_error: str = "") -> None:
        """Return fail-safe OFFLINE and invalidate any in-flight online render."""
        self.map_operator_mode = mode_after_online_failure() if fallback_error else MapOperatorMode.OFFLINE
        self.online_map_render_generation += 1
        self._refresh_map_mode_controls()
        try:
            self.notebook.select(self.map_tab)
        except (AttributeError, tk.TclError):
            pass
        if fallback_error and hasattr(self, "offline_map_status_var"):
            self.offline_map_status_var.set(
                self._t("map_mode.status.fallback", error=fallback_error)
            )

    def _online_viewport(self) -> OnlineViewport:
        width = 620
        height = 420
        try:
            width = max(64, int(self.online_map_canvas.winfo_width()))
            height = max(64, int(self.online_map_canvas.winfo_height()))
        except (AttributeError, tk.TclError):
            pass
        return OnlineViewport(
            center_latitude=float(self.online_map_lat_var.get().strip()),
            center_longitude=float(self.online_map_lon_var.get().strip()),
            zoom=int(self.online_map_zoom_var.get().strip()),
            width=width,
            height=height,
        )

    def _field_aprs_is_live_control(self) -> FieldAprsIsGuiLiveControl:
        """Create inert live control only on explicit ARM; construction itself is network-free."""
        if self.field_aprs_is_live_gui is None:
            login = str(self.config.get("field_aprs_is_login") or self.station_callsign or "").strip()
            if not login:
                raise RuntimeError("APRS-IS login/callsign is not configured")
            explicit_filter = str(self.config.get("field_aprs_is_range_filter") or "").strip()
            if explicit_filter:
                range_filter = explicit_filter
            else:
                viewport = self._online_viewport()
                radius_km = float(self.config.get("field_aprs_is_radius_km", 50.0))
                range_filter = build_range_filter(
                    float(viewport.center_latitude), float(viewport.center_longitude), radius_km
                )
            config = FieldAprsIsPresentationConfig(
                login=login,
                range_filter=range_filter,
                cache_db=self.field_aprs_is_cache_path,
                enabled=False,
            )
            self.field_aprs_is_live_gui = FieldAprsIsGuiLiveControl(
                FieldAprsIsLiveController(config)
            )
        return self.field_aprs_is_live_gui

    def _arm_field_aprs_is_live(self) -> None:
        """Explicit operator ARM; performs no network I/O and creates no cache DB."""
        try:
            control = self._field_aprs_is_live_control()
            control.arm()
            # A2.1: a new explicit ARM begins a fresh operator attempt and clears
            # any completed-run failure from the previous bounded session.
            self.field_aprs_is_live_thread_result = None
            self.field_aprs_is_status_var.set(self._t("field_aprs_is.live.status.armed"))
        except Exception as exc:
            self.field_aprs_is_status_var.set(
                self._t("field_aprs_is.live.status.error", error=exc)
            )

    def _start_field_aprs_is_live(self) -> None:
        """Start one bounded receive-only session only after explicit ARM."""
        try:
            control = self._field_aprs_is_live_control()
            self.field_aprs_is_status_var.set(self._t("field_aprs_is.live.status.running"))
            self.field_aprs_is_live_thread_result = None
            control.start_bounded_async(
                max_packets=max(1, min(int(self.config.get("field_aprs_is_max_packets", 25)), 500)),
                max_seconds=max(1.0, min(float(self.config.get("field_aprs_is_max_seconds", 30.0)), 300.0)),
            )
            self.after(100, self._poll_field_aprs_is_live_completion)
        except Exception as exc:
            self.field_aprs_is_status_var.set(
                self._t("field_aprs_is.live.status.error", error=exc)
            )

    def _stop_field_aprs_is_live(self) -> None:
        """Request STOP/OFF.  Never starts a connection."""
        try:
            if self.field_aprs_is_live_gui is not None:
                self.field_aprs_is_live_gui.stop_off()
            self.field_aprs_is_status_var.set(self._t("field_aprs_is.status.off"))
        except Exception as exc:
            self.field_aprs_is_status_var.set(
                self._t("field_aprs_is.live.status.error", error=exc)
            )

    def _poll_field_aprs_is_live_completion(self) -> None:
        """Poll worker completion from Tk main thread; worker never calls Tk."""
        control = self.field_aprs_is_live_gui
        if control is None:
            return
        result = control.take_completed_result()
        if result is None:
            self.after(100, self._poll_field_aprs_is_live_completion)
            return
        self._field_aprs_is_live_done(result)

    def _field_aprs_is_live_done(self, result) -> None:
        self.field_aprs_is_live_thread_result = result
        if result.success:
            self.field_aprs_is_status_var.set(
                self._t(
                    "field_aprs_is.live.status.done",
                    packets=result.packets_received,
                    positions=result.positions_parsed,
                )
            )
        else:
            self.field_aprs_is_status_var.set(
                self._t("field_aprs_is.live.status.failed", error=result.error)
            )
        self._refresh_online_map_rows()

    def _toggle_field_aprs_is_presentation(self) -> None:
        """Toggle only display of the separate local APRS-IS cache; never network."""
        enabled = bool(self.field_aprs_is_presentation_var.get())
        self.field_aprs_is_presentation_enabled = enabled
        if enabled:
            self.field_aprs_is_status_var.set(self._t("field_aprs_is.status.cache_only"))
        else:
            self.field_aprs_is_status_var.set(self._t("field_aprs_is.status.off"))
        self._refresh_online_map_rows()

    def _read_online_map_source_rows(self) -> list[dict[str, Any]]:
        """Read local presentation sources only; direct APRS-IS cache is optional."""
        rows = read_map_latest_positions_read_only(
            self.offline_map_database_path,
            include_aprs=True,
            aprs_database_path=self.aprs_replica_database_path if self.aprs_field_sync_enabled else None,
        )
        if self.field_aprs_is_presentation_enabled:
            direct = read_direct_aprs_is_rows_read_only(self.field_aprs_is_cache_path)
            if hasattr(self, "field_aprs_is_status_var"):
                self.field_aprs_is_status_var.set(self._t("field_aprs_is.status.cache_rows", count=len(direct)))
            rows = merge_map_rows_for_presentation(rows, direct)
        return filter_latest_for_visibility(rows,now_epoch=int(time.time()),visibility_seconds=preset_seconds(self.map_visibility_preset_var.get()))

    def _read_online_map_history_rows(self) -> list[dict[str, Any]]:
        """Read local/replicated history only; direct APRS-IS cache remains latest-only."""
        rows=read_map_position_history_read_only(
            self.offline_map_database_path,include_aprs=True,limit=1000,
            aprs_database_path=self.aprs_replica_database_path if self.aprs_field_sync_enabled else None,
        )
        return filter_history_for_track_tail(rows,now_epoch=int(time.time()),track_tail_seconds=preset_seconds(self.map_track_tail_preset_var.get()))

    def _center_online_map_on_local_data(self) -> None:
        try:
            rows = self._read_online_map_source_rows()
            if not rows:
                self.online_map_status_var.set(self._t("online_map.status.no_data"))
                return
            latitude = sum(float(row["latitude"]) for row in rows) / len(rows)
            longitude = sum(float(row["longitude"]) for row in rows) / len(rows)
            self.online_map_lat_var.set(f"{latitude:.3f}")
            self.online_map_lon_var.set(f"{longitude:.3f}")
            self._refresh_online_map_rows()
        except Exception as exc:
            self.online_map_status_var.set(self._t("online_map.status.data_error", error=exc))

    def _refresh_online_map_rows(self) -> None:
        """Refresh only local privacy-reduced rows; never fetch OSM tiles."""
        try:
            viewport = self._online_viewport()
            if self.online_map_last_render is not None:
                rendered = self.online_map_last_render.viewport
                if (
                    float(rendered.center_latitude) != float(viewport.center_latitude)
                    or float(rendered.center_longitude) != float(viewport.center_longitude)
                    or int(rendered.zoom) != int(viewport.zoom)
                    or int(rendered.width) != int(viewport.width)
                    or int(rendered.height) != int(viewport.height)
                ):
                    # Never paint positions over a stale tile viewport after the
                    # operator changes center/zoom or the visible canvas size.
                    self.online_map_last_render = None
                    self.online_map_photo = None
            rows = filter_rows_to_viewport(
                self._read_online_map_source_rows(), viewport, limit=500
            )
            history = filter_rows_to_viewport(
                self._read_online_map_history_rows(), viewport, limit=1000
            )
            self.online_map_rows = rows
            self.online_map_history_rows = history
            for item in self.online_map_tree.get_children():
                self.online_map_tree.delete(item)
            for index, row in enumerate(rows):
                timestamp = str(row.get("received_at") or row.get("updated_at") or "")
                self.online_map_tree.insert(
                    "",
                    "end",
                    iid=f"online-{index}",
                    values=(
                        "APRS" if row.get("map_layer") == "aprs" else row.get("network", ""),
                        row.get("node_label") or row.get("node_id") or "",
                        f"{float(row.get('latitude', 0.0)):.3f}, {float(row.get('longitude', 0.0)):.3f}",
                        timestamp,
                        row.get("source", ""),
                    ),
                )
            self._draw_online_map_overlay()
            # Preserve the last OSM load/result status while a matching rendered
            # OSM viewport is still displayed. Local row refreshes are read-only
            # and must not claim that network fetching has never started.
            if self.online_map_last_render is None:
                self.online_map_status_var.set(
                    self._t("online_map.status.local_rows", count=len(rows))
                )
        except Exception as exc:
            self.online_map_rows = []
            self.online_map_history_rows = []
            self.online_map_status_var.set(self._t("online_map.status.data_error", error=exc))

    def _draw_online_map_overlay(self) -> None:
        if not hasattr(self, "online_map_canvas"):
            return
        canvas = self.online_map_canvas
        if self.online_map_last_render is None:
            canvas.delete("all")
            canvas.create_text(
                16,
                16,
                anchor="nw",
                text=self._t("online_map.not_loaded"),
                width=max(160, int(canvas.winfo_width()) - 32),
            )
            return
        render = self.online_map_last_render
        canvas.delete("all")
        try:
            if ImageTk is not None:
                self.online_map_photo = ImageTk.PhotoImage(render.image)
            else:
                # Pillow's ImageTk may be packaged separately on Linux. Keep the
                # Online Map usable by falling back to Tk's native PNG loader,
                # matching the existing offline MBTiles rendering strategy.
                import io
                buffer = io.BytesIO()
                render.image.save(buffer, format="PNG")
                encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
                self.online_map_photo = tk.PhotoImage(data=encoded, format="png")
            canvas.create_image(0, 0, anchor="nw", image=self.online_map_photo)
        except Exception as exc:
            canvas.create_text(16, 16, anchor="nw", text=str(exc))
            return
        for track in group_history_tracks(self.online_map_history_rows):
            coords=[]
            for point in track:
                x,y=project_latlon_to_viewport(float(point["latitude"]),float(point["longitude"]),render.viewport)
                if 0 <= x <= render.viewport.width and 0 <= y <= render.viewport.height:
                    coords.extend((x,y))
            if len(coords)>=4:
                canvas.create_line(*coords,width=2)
        for row in self.online_map_rows:
            x, y = project_latlon_to_viewport(
                float(row["latitude"]), float(row["longitude"]), render.viewport
            )
            if not (0 <= x <= render.viewport.width and 0 <= y <= render.viewport.height):
                continue
            if row.get("map_layer") == "aprs":
                canvas.create_polygon(
                    x, y - 6, x + 6, y, x, y + 6, x - 6, y,
                    outline="#303030", fill="", width=2,
                )
            else:
                canvas.create_oval(x - 5, y - 5, x + 5, y + 5, width=2)
        canvas.create_text(
            max(8, render.viewport.width - 8),
            max(8, render.viewport.height - 8),
            anchor="se",
            text=ONLINE_MAP_ATTRIBUTION,
            fill="#202020",
        )

    def _start_online_map_render(self) -> None:
        """Fetch only the explicitly requested current viewport in ONLINE mode."""
        if not network_fetch_allowed(self.map_operator_mode, explicit_load_request=True):
            self.online_map_status_var.set(self._t("online_map.status.mode_required"))
            return
        if self.online_map_render_running:
            return
        try:
            viewport = self._online_viewport()
        except Exception as exc:
            self.online_map_status_var.set(self._t("online_map.status.viewport_error", error=exc))
            return
        self.online_map_render_running = True
        self.online_map_render_generation += 1
        generation = self.online_map_render_generation
        self.online_map_load_button.configure(state="disabled")
        self.online_map_status_var.set(self._t("online_map.status.loading"))
        threading.Thread(
            target=self._online_map_render_worker,
            args=(generation, viewport),
            name="online-osm-render",
            daemon=True,
        ).start()

    def _online_map_render_worker(self, generation: int, viewport: OnlineViewport) -> None:
        try:
            render = render_osm_viewport(
                viewport,
                cache_directory=self.online_map_cache_directory,
                user_agent=self.online_map_user_agent,
                url_template=self.online_map_tile_url_template,
            )
            result = {"generation": generation, "ok": True, "render": render}
        except Exception as exc:
            result = {
                "generation": generation,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        self.online_map_render_queue.put(result)

    def _poll_online_map_render_results(self) -> None:
        if self._gui_closing:
            return
        while True:
            try:
                result = self.online_map_render_queue.get_nowait()
            except queue.Empty:
                break
            self.online_map_render_running = False
            try:
                self.online_map_load_button.configure(state="normal")
            except (AttributeError, tk.TclError):
                pass
            if int(result.get("generation", -1)) != self.online_map_render_generation:
                continue
            if result.get("ok"):
                render = result["render"]
                self.online_map_last_render = render
                self._refresh_online_map_rows()
                self.online_map_status_var.set(
                    self._t(
                        "online_map.status.loaded",
                        tiles=render.tile_count,
                        cache=render.cache_hits,
                        fetched=render.network_fetches,
                    )
                )
            else:
                error_text = str(result.get("error", ""))
                self.online_map_status_var.set(
                    self._t("online_map.status.load_error", error=error_text)
                )
                self._operator_select_offline_map(fallback_error=error_text)
        self.online_map_render_poll_after_id = self.after(
            50, self._poll_online_map_render_results
        )

    def _on_offline_map_canvas_configure(self, event: Any) -> None:
        """Debounce a redraw after Tk assigns the canvas its real size.

        The map tab is built while it may still be hidden. Tk then reports a
        tiny provisional canvas, so the first raster can be much smaller than
        the visible area. A configure event arrives when the tab becomes
        visible or the window changes size; redraw from already reduced cached
        rows instead of reading the database again.
        """
        width = max(1, int(getattr(event, "width", 0) or 0))
        height = max(1, int(getattr(event, "height", 0) or 0))
        if width <= 1 or height <= 1:
            return

        size = (width, height)
        if (
            size == self.offline_map_last_canvas_size
            and self.offline_map_redraw_after_id is None
        ):
            return

        if self.offline_map_redraw_after_id is not None:
            try:
                self.after_cancel(self.offline_map_redraw_after_id)
            except tk.TclError:
                pass
            self.offline_map_redraw_after_id = None

        self.offline_map_redraw_after_id = self.after(
            OFFLINE_MAP_RESIZE_DEBOUNCE_MS,
            self._redraw_offline_map_after_resize,
        )

    def _redraw_offline_map_after_resize(self) -> None:
        """Redraw the map from cached privacy-reduced rows after resize."""
        self.offline_map_redraw_after_id = None
        try:
            if not self.offline_map_canvas.winfo_exists():
                return
            self._draw_offline_map_canvas(
                list(self.offline_map_rows),
                list(self.offline_map_history_rows),
            )
        except tk.TclError:
            # The window may be closing while a debounced callback is pending.
            return

    def _refresh_operator_map_inventory(self) -> None:
        """Refresh validated MBTiles choices read-only; preserve stale explicit choices."""
        if not hasattr(self, "operator_map_combo"):
            return
        inventory = build_operator_map_inventory(self.config)
        self.operator_map_inventory = inventory
        auto_label = self._t("map.package.auto")
        label_to_key = {auto_label: AUTO_MAP_KEY}
        for entry in inventory:
            label_to_key[entry.label] = entry.key
        self.operator_map_label_to_key = label_to_key
        self.operator_map_combo.configure(values=list(label_to_key))
        matching = next((entry for entry in inventory if entry.key == self.operator_map_selected_key), None)
        if self.operator_map_selected_key == AUTO_MAP_KEY:
            self.operator_map_display_var.set(auto_label)
            self.operator_map_metadata_var.set(self._t("map.package.metadata_auto"))
        elif matching is None:
            self.operator_map_display_var.set(self._t("map.package.unavailable", key=self.operator_map_selected_key))
            self.operator_map_metadata_var.set(self._t("map.package.metadata_unavailable", key=self.operator_map_selected_key))
        else:
            self.operator_map_display_var.set(matching.label)
            self.operator_map_metadata_var.set(operator_map_metadata_text(matching))

    def _install_offline_mbtiles(self) -> None:
        """Install one operator-selected local MBTiles package fail-closed."""
        source_text = filedialog.askopenfilename(
            title=self._t("map.package.install_title"),
            filetypes=[
                (self._t("map.package.mbtiles_files"), "*.mbtiles"),
                (self._t("map.package.all_files"), "*"),
            ],
        )
        if not source_text:
            return
        source = Path(source_text).expanduser()
        try:
            package = read_map_package(source)
            map_directory = resolve_offline_map_directory(self.config)
            if not map_directory.exists() or not map_directory.is_dir():
                raise SecureMbtilesInstallError(
                    self._t("map.package.map_directory_missing", path=map_directory)
                )
            staging_directory = map_directory.parent / ".gutochat-map-install-staging"
            staging_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            west, south, east, north = package.bounds
            confirmation = self._t(
                "map.package.install_confirm",
                name=package.name,
                filename=source.name,
                bounds=f"{west:g},{south:g},{east:g},{north:g}",
                zoom=f"{package.min_zoom}–{package.max_zoom}",
                destination=map_directory / source.name,
            )
            if not messagebox.askyesno(
                self._t("map.package.install_confirm_title"),
                confirmation,
            ):
                return
            result = secure_install_mbtiles(
                source,
                map_directory,
                staging_directory,
                config=self.config,
            )
            self._refresh_operator_map_inventory()
            self._start_map_refresh(force=True)
            messagebox.showinfo(
                self._t("map.package.install_success_title"),
                self._t(
                    "map.package.install_success",
                    name=result.package_name,
                    filename=result.destination_path.name,
                ),
            )
        except (SecureMbtilesInstallError, OSError, sqlite3.Error, ValueError) as exc:
            messagebox.showerror(
                self._t("map.package.install_error_title"),
                self._t("map.package.install_error", error=exc),
            )

    def _operator_map_selection_changed(self) -> None:
        """Apply only session presentation state; no config, DB, APRS or transport write."""
        key = self.operator_map_label_to_key.get(self.operator_map_display_var.get())
        if key is None:
            return
        self.operator_map_selected_key = key
        self._refresh_operator_map_inventory()
        self._start_map_refresh(force=True)

    def _temporal_preset_label(self,preset:str)->str:return self._t(f"map.temporal.{preset}")
    def _temporal_key_from_display(self,value:str)->str:
        for key in TEMPORAL_PRESETS_SECONDS:
            if value==self._temporal_preset_label(key):return key
        if value in TEMPORAL_PRESETS_SECONDS:return value
        raise ValueError(f"unknown temporal presentation selection: {value}")
    def _refresh_temporal_control_presentation(self)->None:
        vk=self.map_visibility_preset_var.get();tk=self.map_track_tail_preset_var.get()
        if vk not in TEMPORAL_PRESETS_SECONDS:vk=DEFAULT_VISIBILITY_PRESET;self.map_visibility_preset_var.set(vk)
        if tk not in TEMPORAL_PRESETS_SECONDS:tk=DEFAULT_TRACK_TAIL_PRESET;self.map_track_tail_preset_var.set(tk)
        labels=[self._temporal_preset_label(k) for k in TEMPORAL_PRESETS_SECONDS]
        for n in ("offline_map_visibility_combo","online_map_visibility_combo","offline_map_track_tail_combo","online_map_track_tail_combo"):
            c=getattr(self,n,None)
            if c is not None:c.configure(values=labels)
        self.map_visibility_display_var.set(self._temporal_preset_label(vk));self.map_track_tail_display_var.set(self._temporal_preset_label(tk))
    def _temporal_map_controls_changed(self)->None:
        self.map_visibility_preset_var.set(self._temporal_key_from_display(self.map_visibility_display_var.get()));self.map_track_tail_preset_var.set(self._temporal_key_from_display(self.map_track_tail_display_var.get()));self._refresh_temporal_control_presentation()
        self._start_map_refresh(force=True)
        if hasattr(self,"online_map_tree"):self._refresh_online_map_rows()
    def _offline_viewport_values(self) -> tuple[float, float, int]:
        """Return validated operator-entered local viewport values."""
        latitude = float(self.offline_map_lat_var.get().strip())
        longitude = float(self.offline_map_lon_var.get().strip())
        zoom_text = self.offline_map_zoom_var.get().strip()
        if not zoom_text or any(char in zoom_text for char in ".eE"):
            raise ValueError("Zoom må være et heltall mellom 0 og 18")
        zoom = int(zoom_text)
        if not math.isfinite(latitude) or not -85.05112878 <= latitude <= 85.05112878:
            raise ValueError("Breddegrad må være mellom -85.05112878 og 85.05112878")
        if not math.isfinite(longitude) or not -180.0 <= longitude <= 180.0:
            raise ValueError("Lengdegrad må være mellom -180 og 180")
        if not 0 <= zoom <= 18:
            raise ValueError("Zoom må være mellom 0 og 18")
        return latitude, longitude, zoom

    def _center_offline_map_on_local_data(self) -> None:
        """Center the local viewport on privacy-reduced local data only."""
        try:
            rows = read_map_latest_positions_read_only(
                self.offline_map_database_path,
                include_aprs=True,
                aprs_database_path=self.offline_map_aprs_database_path,
            )
            rows = filter_latest_for_visibility(
                rows,
                now_epoch=int(time.time()),
                visibility_seconds=preset_seconds(self.map_visibility_preset_var.get()),
            )
            if not rows:
                self.offline_map_status_var.set(self._t("offline_map.status.no_data"))
                return
            latitude = sum(float(row["latitude"]) for row in rows) / len(rows)
            longitude = sum(float(row["longitude"]) for row in rows) / len(rows)
            self.offline_map_lat_var.set(f"{latitude:.3f}")
            self.offline_map_lon_var.set(f"{longitude:.3f}")
            self.offline_map_manual_viewport = True
            self._start_map_refresh(force=True)
        except Exception as exc:
            self.offline_map_status_var.set(self._t("map.status.error", error=exc))

    def _refresh_offline_map_from_viewport(self) -> None:
        """Refresh local presentation for the explicit MBTiles center/zoom only."""
        try:
            self._offline_viewport_values()
        except Exception as exc:
            self.offline_map_status_var.set(self._t("map.status.error", error=exc))
            return
        self.offline_map_manual_viewport = True
        self._start_map_refresh(force=True)

    def _refresh_offline_viewport_control_presentation(self)->None:
        values=[self._t("map.viewport.all"),self._t("map.viewport.current")]
        if hasattr(self,"offline_map_viewport_combo"):self.offline_map_viewport_combo.configure(values=values)
        self.offline_map_viewport_display_var.set(self._t("map.viewport.current") if self.offline_map_viewport_mode_var.get()=="viewport" else self._t("map.viewport.all"))
    def _offline_viewport_control_changed(self)->None:
        self.offline_map_viewport_mode_var.set("viewport" if self.offline_map_viewport_display_var.get()==self._t("map.viewport.current") else "all")
        self._refresh_offline_viewport_control_presentation();self._start_map_refresh(force=True)
    def _apply_offline_viewport_filter(self,latest:list[dict[str,Any]],history:list[dict[str,Any]])->tuple[list[dict[str,Any]],list[dict[str,Any]]]:
        rows=list(latest) or list(history);self.offline_map_last_tile=None
        if self.offline_map_status.state=="ready" and self.offline_map_status.path:
            try:
                if self.offline_map_manual_viewport:
                    latitude,longitude,zoom=self._offline_viewport_values()
                    self.offline_map_last_tile=load_raster_tile_for_center(
                        self.offline_map_status.path,latitude,longitude,zoom
                    )
                elif rows:
                    metadata=read_mbtiles_metadata(self.offline_map_status.path)
                    self.offline_map_last_tile=load_best_raster_tile(
                        self.offline_map_status.path,rows,metadata
                    )
                    if (
                        self.offline_map_last_tile is None
                        and self.operator_map_selected_key == AUTO_MAP_KEY
                    ):
                        self.offline_map_last_tile=load_default_raster_tile(
                            self.offline_map_status.path,metadata
                        )
                    if self.offline_map_last_tile is not None:
                        center_latitude=sum(float(row["latitude"]) for row in rows)/len(rows)
                        center_longitude=sum(float(row["longitude"]) for row in rows)/len(rows)
                        self.offline_map_lat_var.set(f"{center_latitude:.3f}")
                        self.offline_map_lon_var.set(f"{center_longitude:.3f}")
                        self.offline_map_zoom_var.set(str(self.offline_map_last_tile.zoom))
            except Exception:self.offline_map_last_tile=None
        if self.offline_map_viewport_mode_var.get()!="viewport":return latest,history
        tile=self.offline_map_last_tile
        if tile is None:return [],[]
        return (filter_rows_to_xyz_tile(latest,zoom=tile.zoom,x=tile.x,y=tile.y),filter_rows_to_xyz_tile(history,zoom=tile.zoom,x=tile.x,y=tile.y))

    def _map_network_key(self) -> str | None:
        """Return the selected map network key, or None for all networks."""
        code = self._network_filter_code(
            self.offline_map_network_var.get(), "map.filter.network_all"
        )
        return None if code == "all" else code

    def _map_status_message(self) -> str:
        """Translate known offline-map status states at the GUI boundary."""
        status = self.offline_map_status
        path = str(status.path or "")
        if status.state == "ready":
            prefix = "Automatisk valgt kart: "
            if status.message.startswith(prefix):
                return self._t(
                    "map.status.auto_selected",
                    name=status.message[len(prefix):],
                )
            selected_prefix = "Operatørvalgt kart: "
            if status.message.startswith(selected_prefix):
                return self._t("map.status.operator_selected", name=status.message[len(selected_prefix):])
            return self._t("map.status.compatibility", path=path)
        if status.state == "selection_unavailable":
            return self._t("map.status.selection_unavailable", key=self.operator_map_selected_key)
        if status.state == "no_coverage":
            return self._t("map.status.no_coverage")
        if status.state == "not_configured":
            # For the discovered-map path, the directory is carried in the
            # original status message even when status.path is None.
            marker = ": "
            detail = status.message.rsplit(marker, 1)[-1] if marker in status.message else path
            return self._t("map.status.not_configured", path=detail)
        if status.state == "missing":
            return self._t("map.status.missing", path=path)
        if status.state == "invalid":
            return self._t("map.status.invalid", path=path)
        return status.message

    def _clear_map_filters(self) -> None:
        """Reset the map tab filters without touching radio or database state."""
        self.offline_map_network_var.set(self._t("map.filter.network_all"))
        self.offline_map_node_var.set("")
        self.map_visibility_preset_var.set(DEFAULT_VISIBILITY_PRESET)
        self.map_track_tail_preset_var.set(DEFAULT_TRACK_TAIL_PRESET)
        self._refresh_temporal_control_presentation()
        self.offline_map_viewport_mode_var.set("all")
        self._refresh_offline_viewport_control_presentation()
        self.offline_map_limit_var.set("250")
        self._start_map_refresh(force=True)

    def _map_data_signature(self) -> tuple[Any, ...]:
        """Return a read-only signature across Meshtastic and Field APRS replica."""
        try:
            aprs_path = self.aprs_replica_database_path if self.aprs_field_sync_enabled else None
            return (
                str(self.offline_map_database_path),
                str(aprs_path or ""),
                offline_map_sources_signature(self.config),
                self.offline_map_network_var.get(),
                self.offline_map_node_var.get(),
                self.offline_map_limit_var.get(),
                bool(self.offline_map_aprs_var.get()) if hasattr(self, "offline_map_aprs_var") else False,
                map_position_data_signature(
                    self.offline_map_database_path, aprs_database_path=aprs_path
                ),
            )
        except Exception:
            return (str(self.offline_map_database_path), "error", time.monotonic_ns())

    def _filter_map_rows(self, rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
        """Apply the map node/name filter to privacy-reduced position rows."""
        rendered: list[dict[str, Any]] = []
        for row in rows:
            route = str(row.get("network", ""))
            node_id = str(row.get("node_id", ""))
            if row.get("map_layer") == "aprs" or route == "aprs":
                label = node_id
            else:
                label = self.contacts.alias(route, node_id) or self._resolve_node_name(route, node_id)
            haystack = " ".join((route, node_id, str(label), str(row.get("num", "")))).casefold()
            if query and query not in haystack:
                continue
            item = dict(row)
            item["node_label"] = str(label or node_id)
            rendered.append(item)
        return rendered

    def _refresh_map_view(self, *, force: bool = False) -> None:
        """Refresh the map tab from local read-only files only."""
        if not hasattr(self, "offline_map_canvas"):
            return
        signature = self._map_data_signature()
        if not force and signature == self.last_offline_map_signature:
            return
        try:
            network = self._map_network_key()
            limit = max(1, min(int(self.offline_map_limit_var.get()), 1000))
            query = self.offline_map_node_var.get().strip().casefold()
            include_aprs = bool(
                self.aprs_field_sync_enabled and self.offline_map_aprs_var.get()
            )
            aprs_path = self.aprs_replica_database_path if self.aprs_field_sync_enabled else None
            latest = self._filter_map_rows(
                read_map_latest_positions_read_only(
                    self.offline_map_database_path,
                    meshtastic_network=network,
                    include_aprs=include_aprs,
                    aprs_database_path=aprs_path,
                ),
                query,
            )
            history = self._filter_map_rows(
                read_map_position_history_read_only(
                    self.offline_map_database_path,
                    meshtastic_network=network,
                    include_aprs=include_aprs,
                    limit=limit,
                    aprs_database_path=aprs_path,
                ),
                query,
            )[:limit]
            now_epoch=int(time.time())
            latest=filter_latest_for_visibility(latest,now_epoch=now_epoch,visibility_seconds=preset_seconds(self.map_visibility_preset_var.get()))
            history=filter_history_for_track_tail(history,now_epoch=now_epoch,track_tail_seconds=preset_seconds(self.map_track_tail_preset_var.get()))
            self.offline_map_status = (resolve_active_map(self.config, latest or history) if self.operator_map_selected_key == AUTO_MAP_KEY else resolve_operator_map(self.config, latest or history, self.operator_map_selected_key))
            latest,history=self._apply_offline_viewport_filter(latest,history)
            self.offline_map_rows = latest
            self.offline_map_history_rows = history
            # Select from privacy-reduced rows only. Map packages and the
            # legacy fallback remain local and are always opened read-only.
            self._render_map_tables(latest, history)
            self._draw_offline_map_canvas(latest, history)
            parts = [
                self._t("map.status.database", database=self.offline_map_database_path),
                self._t("map.status.aprs_database", database=self.aprs_replica_database_path)
                if self.aprs_field_sync_enabled else "APRS replica: off",
                self._map_status_message(),
                self._t("map.status.count", latest=len(latest), history=len(history)),
                self._t("map.status.privacy"),
            ]
            self.offline_map_status_var.set("  •  ".join(parts))
            self.last_offline_map_signature = signature
        except Exception as exc:
            message = self._t("map.status.error", error=exc)
            self.offline_map_status_var.set(message)
            if hasattr(self, "offline_map_info_var"):
                self.offline_map_info_var.set(message)
            self.offline_map_canvas.delete("all")
            self.offline_map_canvas.create_text(
                20,
                20,
                anchor="nw",
                text=self._t("map.disabled"),
                width=560,
            )

    def _map_detail_text(self, row: dict[str, Any]) -> str:
        """Render local Field details for a selected map row without network access."""
        node = row.get("node_label") or row.get("node_id") or self._t("common.unknown")
        source = row.get("source") or self._t("common.unknown")
        if row.get("map_layer") == "aprs" or str(row.get("network", "")).lower() == "aprs":
            return self._t("map.details.aprs_field", node=node, source=source)
        return self._t("map.details.meshtastic", node=node, source=source)

    def _on_map_latest_selected(self, _event: Any = None) -> None:
        """Show details for the selected latest Field map entity."""
        if not hasattr(self, "offline_map_detail_var"):
            return
        selection = self.offline_map_latest_tree.selection()
        if not selection:
            self.offline_map_detail_var.set(self._t("map.details.initial"))
            return
        row = self.offline_map_tree_rows.get(str(selection[0]))
        self.offline_map_detail_var.set(
            self._map_detail_text(row) if row is not None else self._t("map.details.initial")
        )

    def _capture_map_refresh_request(self) -> dict[str, Any]:
        """Capture Tk-owned Field map filter state before the R2.1 worker."""
        self._refresh_operator_map_inventory()
        include_aprs = bool(
            self.aprs_field_sync_enabled and self.offline_map_aprs_var.get()
        )
        aprs_path = self.aprs_replica_database_path if self.aprs_field_sync_enabled else None
        return {
            "database": self.offline_map_database_path,
            "aprs_database": aprs_path,
            "network": self._map_network_key(),
            "network_filter": self.offline_map_network_var.get(),
            "node_filter": self.offline_map_node_var.get(),
            "query": self.offline_map_node_var.get().strip().casefold(),
            "limit_text": self.offline_map_limit_var.get(),
            "limit": max(1, min(int(self.offline_map_limit_var.get()), 1000)),
            "include_aprs": include_aprs,
            "visibility_preset": self.map_visibility_preset_var.get(),
            "track_tail_preset": self.map_track_tail_preset_var.get(),
            "viewport_mode": self.offline_map_viewport_mode_var.get(),
            "operator_map_selected_key": self.operator_map_selected_key,
            "previous_signature": self.last_offline_map_signature,
        }

    def _start_map_refresh(self, *, force: bool = False) -> None:
        """Start at most one Field local-map read worker without blocking Tk."""
        if self._gui_closing or not hasattr(self, "offline_map_canvas"):
            return
        if not force and not self._active_tab_is(self.map_tab):
            return
        if self.map_refresh_running:
            self.map_refresh_pending = self.map_refresh_pending or force
            return
        try:
            request = self._capture_map_refresh_request()
        except Exception as exc:
            self.offline_map_status_var.set(self._t("map.status.error", error=exc))
            return
        self.map_refresh_running = True
        self.map_refresh_pending = False
        self.map_refresh_generation += 1
        generation = self.map_refresh_generation
        if self._active_tab_is(self.map_tab):
            self.offline_map_status_var.set(self._t("common.refreshing"))
        threading.Thread(
            target=self._map_refresh_worker,
            args=(generation, request, force),
            name="map-data-refresh",
            daemon=True,
        ).start()

    def _map_refresh_worker(
        self, generation: int, request: dict[str, Any], force: bool
    ) -> None:
        """Read Field map source/database state in the background; never touch Tk."""
        try:
            counts = map_position_data_signature(
                request["database"], aprs_database_path=request["aprs_database"]
            )
            signature = (
                str(request["database"]),
                str(request["aprs_database"] or ""),
                offline_map_sources_signature(self.config),
                request["network_filter"],
                request["node_filter"],
                request["limit_text"],
                bool(request["include_aprs"]),
                request["visibility_preset"],request["track_tail_preset"],request["viewport_mode"],
                request["operator_map_selected_key"],
                counts,
            )
            if not force and signature == request.get("previous_signature"):
                result: dict[str, Any] = {
                    "generation": generation,
                    "ok": True,
                    "unchanged": True,
                    "signature": signature,
                }
            else:
                latest = read_map_latest_positions_read_only(
                    request["database"],
                    meshtastic_network=request["network"],
                    include_aprs=bool(request["include_aprs"]),
                    aprs_database_path=request["aprs_database"],
                )
                history = read_map_position_history_read_only(
                    request["database"],
                    meshtastic_network=request["network"],
                    include_aprs=bool(request["include_aprs"]),
                    limit=int(request["limit"]),
                    aprs_database_path=request["aprs_database"],
                )
                now_epoch=int(time.time())
                latest=filter_latest_for_visibility(latest,now_epoch=now_epoch,visibility_seconds=preset_seconds(request["visibility_preset"]))
                history=filter_history_for_track_tail(history,now_epoch=now_epoch,track_tail_seconds=preset_seconds(request["track_tail_preset"]))
                result = {
                    "generation": generation,
                    "ok": True,
                    "unchanged": False,
                    "signature": signature,
                    "query": request["query"],
                    "limit": int(request["limit"]),
                    "latest": latest,
                    "history": history,
                    "map_status": (
                        resolve_active_map(self.config, latest or history)
                        if request["operator_map_selected_key"] == AUTO_MAP_KEY
                        else resolve_operator_map(
                            self.config, latest or history, request["operator_map_selected_key"]
                        )
                    ),
                }
        except Exception as exc:
            result = {
                "generation": generation,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        self.map_refresh_queue.put(result)

    def _apply_map_refresh_result(self, result: dict[str, Any]) -> None:
        """Apply one completed Field R2.1 map read on Tk's main thread."""
        if result.get("unchanged"):
            return
        query = str(result.get("query", ""))
        limit = int(result.get("limit", 250))
        latest = self._filter_map_rows(list(result.get("latest", [])), query)
        history = self._filter_map_rows(list(result.get("history", [])), query)[:limit]
        self.offline_map_status = result["map_status"]
        latest,history=self._apply_offline_viewport_filter(latest,history)
        self.offline_map_rows = latest
        self.offline_map_history_rows = history
        self._render_map_tables(latest, history)
        self._draw_offline_map_canvas(latest, history)
        parts = [
            self._t("map.status.database", database=self.offline_map_database_path),
            self._t("map.status.aprs_database", database=self.aprs_replica_database_path)
            if self.aprs_field_sync_enabled else "APRS replica: off",
            self._map_status_message(),
            self._t("map.status.count", latest=len(latest), history=len(history)),
            self._t("map.status.privacy"),
        ]
        self.offline_map_status_var.set("  •  ".join(parts))
        self.last_offline_map_signature = result.get("signature")

    def _poll_map_refresh_results(self) -> None:
        """Drain R2.1 Field map worker results without blocking tab selection."""
        if self._gui_closing:
            return
        while True:
            try:
                result = self.map_refresh_queue.get_nowait()
            except queue.Empty:
                break
            self.map_refresh_running = False
            if result.get("ok"):
                if self._active_tab_is(self.map_tab):
                    self._apply_map_refresh_result(result)
            elif self._active_tab_is(self.map_tab):
                message = self._t("map.status.error", error=result.get("error", "map refresh failed"))
                self.offline_map_status_var.set(message)
                if hasattr(self, "offline_map_info_var"):
                    self.offline_map_info_var.set(message)
            if self.map_refresh_pending:
                self.map_refresh_pending = False
                self._start_map_refresh(force=True)
        self.map_refresh_poll_after_id = self.after(25, self._poll_map_refresh_results)

    def _render_map_tables(
        self,
        latest: list[dict[str, Any]],
        history: list[dict[str, Any]],
    ) -> None:
        """Render privacy-reduced latest and history rows in the map tab."""
        for tree in (self.offline_map_latest_tree, self.offline_map_history_tree):
            children = tree.get_children()
            if children:
                tree.delete(*children)
        self.offline_map_tree_rows = {}
        if hasattr(self, "offline_map_detail_var"):
            aprs_latest = sum(
                1 for row in latest
                if row.get("map_layer") == "aprs" or str(row.get("network", "")).lower() == "aprs"
            )
            self.offline_map_detail_var.set(
                self._t("map.details.summary", aprs=aprs_latest, total=len(latest))
            )
        for index, row in enumerate(latest):
            precision = (
                f"{row['precision_bits']} bit"
                if row.get("precision_bits") not in (None, "")
                else self._t("common.unknown")
            )
            iid = f"map-latest:{index}"
            self.offline_map_tree_rows[iid] = dict(row)
            self.offline_map_latest_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    self._network_label(str(row.get("network", ""))),
                    row.get("node_label", row.get("node_id", "")),
                    f"{float(row.get('latitude', 0.0)):.3f}, {float(row.get('longitude', 0.0)):.3f}",
                    self._position_timestamp(row.get("position_epoch")),
                    precision,
                    str(row.get("source") or self._t("common.unknown")),
                ),
            )
        for index, row in enumerate(history):
            self.offline_map_history_tree.insert(
                "",
                "end",
                iid=f"map-history:{index}",
                values=(
                    self._position_timestamp(row.get("position_epoch")),
                    self._network_label(str(row.get("network", ""))),
                    row.get("node_label", row.get("node_id", "")),
                    f"{float(row.get('latitude', 0.0)):.3f}, {float(row.get('longitude', 0.0)):.3f}",
                    str(row.get("source") or self._t("common.unknown")),
                ),
            )

    def _draw_offline_map_canvas(
        self,
        latest: list[dict[str, Any]],
        history: list[dict[str, Any]],
    ) -> None:
        """Draw a stable local map preview using reduced/read-only data."""
        canvas = self.offline_map_canvas
        canvas.delete("all")
        canvas.update_idletasks()
        width = max(200, int(canvas.winfo_width() or 620))
        height = max(160, int(canvas.winfo_height() or 420))
        self.offline_map_last_canvas_size = (width, height)

        rows = list(latest) or list(history)

        # Use the largest centered square that fits the canvas. The previous
        # 256-pixel cap left most of a large field display unused.
        margin = 18
        map_size = max(96, min(width - (2 * margin), height - (2 * margin)))
        map_x0 = max(margin, (width - map_size) // 2)
        map_y0 = max(margin, (height - map_size) // 2)
        map_rect = (map_x0, map_y0, map_x0 + map_size, map_y0 + map_size)

        if self.offline_map_status.state == "ready" and self.offline_map_status.path:
            title, has_background = self._draw_mbtiles_background(
                canvas,
                rows,
                map_rect,
            )
            if has_background:
                # Beta1f map-layer-v2 rule:
                # Keep the raster tile clean, but draw small position markers as
                # a separate marker layer. Node names, coordinates and other
                # details stay in the tables, not as text on top of the tile.
                self._draw_privacy_reduced_points(
                    canvas,
                    width,
                    height,
                    latest,
                    history,
                    plot_rect=map_rect,
                    show_labels=False,
                )
                # Map identity and attribution are displayed by a dedicated
                # label below the canvas, never on top of the raster or markers.
                self.offline_map_info_var.set(title)
                return

            self._draw_privacy_reduced_points(
                canvas,
                width,
                height,
                latest,
                history,
                plot_rect=map_rect,
                show_labels=False,
            )
            self.offline_map_info_var.set(title)
            return

        title = self._map_status_message()
        canvas.create_rectangle(*map_rect, outline="#d0d0d0")
        canvas.create_text(
            map_rect[0] + 10,
            map_rect[1] + 10,
            anchor="nw",
            text=self._t("map.no_map"),
            width=max(120, map_size - 20),
        )
        self._draw_privacy_reduced_points(
            canvas,
            width,
            height,
            latest,
            history,
            plot_rect=map_rect,
            show_labels=False,
        )

        self.offline_map_info_var.set(title)

    def _draw_mbtiles_background(
        self,
        canvas: tk.Canvas,
        rows: list[dict[str, Any]],
        map_rect: tuple[int, int, int, int],
    ) -> tuple[str, bool]:
        """Draw one local MBTiles raster tile in a fixed rectangle."""
        assert self.offline_map_status.path is not None
        x0, y0, x1, y1 = map_rect
        draw_size = max(1, min(x1 - x0, y1 - y0))

        try:
            metadata = read_mbtiles_metadata(self.offline_map_status.path)
            map_name = str(metadata.get("name") or self.offline_map_status.path.name)
            attribution = str(metadata.get("attribution") or "").strip()
            title_parts = [self._t("map.mbtiles_read_only"), map_name]
            if attribution:
                title_parts.append(attribution)
            title = " • ".join(title_parts)
            tile = self.offline_map_last_tile
            if tile is None and rows and not self.offline_map_manual_viewport:
                # Automatic Offline mode may select a suitable local tile from
                # privacy-reduced local rows. An explicit center/zoom request
                # must fail closed instead: never substitute another tile when
                # the requested local MBTiles coordinate has no raster tile.
                tile = load_best_raster_tile(self.offline_map_status.path, rows, metadata)
                if tile is None and self.operator_map_selected_key == AUTO_MAP_KEY:
                    tile = load_default_raster_tile(self.offline_map_status.path, metadata)
                self.offline_map_last_tile = tile
            elif tile is not None:
                # Reload the same read-only tile selected before viewport filtering.
                tile = load_raster_tile(self.offline_map_status.path, tile.zoom, tile.x, tile.y)
            if tile is not None:
                if ImageTk is not None and tile.image is not None:
                    image = tile.image.resize((draw_size, draw_size))
                    self.offline_map_photo = ImageTk.PhotoImage(image)
                    canvas.create_image(x0, y0, anchor="nw", image=self.offline_map_photo)
                    canvas.create_rectangle(x0, y0, x0 + draw_size, y0 + draw_size, outline="#606060")
                    return title, True

                if tile.data:
                    try:
                        data = tile.data
                        if tile.image is not None:
                            import io
                            buffer = io.BytesIO()
                            tile.image.resize((draw_size, draw_size)).save(buffer, format="PNG")
                            data = buffer.getvalue()
                        encoded = base64.b64encode(data).decode("ascii")
                        self.offline_map_photo = tk.PhotoImage(data=encoded, format="png")
                        canvas.create_image(x0, y0, anchor="nw", image=self.offline_map_photo)
                        canvas.create_rectangle(x0, y0, x0 + draw_size, y0 + draw_size, outline="#606060")
                        return title, True
                    except Exception:
                        pass

            canvas.create_rectangle(*map_rect, outline="#d0d0d0")
            canvas.create_text(
                x0 + 10,
                y0 + 10,
                anchor="nw",
                text=self._t("map.no_tile"),
                width=max(120, draw_size - 20),
            )
            return f"{title} • {self._t("map.no_tile_suffix")}", False
        except Exception as exc:
            canvas.create_rectangle(*map_rect, outline="#d0d0d0")
            canvas.create_text(
                x0 + 10,
                y0 + 10,
                anchor="nw",
                text=self._t("map.file_error", error=exc),
                width=max(120, draw_size - 20),
            )
            return self._t("map.file_unavailable"), False

    def _draw_privacy_reduced_points(
        self,
        canvas: tk.Canvas,
        width: int,
        height: int,
        latest: list[dict[str, Any]],
        history: list[dict[str, Any]],
        *,
        top_margin: int = 32,
        bottom_margin: int = 42,
        show_labels: bool = True,
        plot_rect: tuple[int, int, int, int] | None = None,
    ) -> None:
        """Draw latest/history points without exposing full stored coordinates."""
        rows = list(history) + list(latest)

        if plot_rect is None:
            safe_top = max(20, min(int(top_margin), max(20, height - 80)))
            safe_bottom = max(30, min(int(bottom_margin), max(30, height - safe_top - 20)))
            plot_rect = (32, safe_top, width - 32, height - safe_bottom)

        x0, y0, x1, y1 = plot_rect
        pad = 8
        plot_x0 = min(x1 - 1, x0 + pad)
        plot_y0 = min(y1 - 1, y0 + pad)
        plot_x1 = max(plot_x0 + 1, x1 - pad)
        plot_y1 = max(plot_y0 + 1, y1 - pad)

        if not rows:
            canvas.create_text(
                (x0 + x1) // 2,
                (y0 + y1) // 2,
                text=self._t("map.no_positions"),
                width=max(120, x1 - x0 - 20),
            )
            return

        lats = [float(row.get("latitude", 0.0)) for row in rows]
        lons = [float(row.get("longitude", 0.0)) for row in rows]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        if min_lat == max_lat:
            min_lat -= 0.001
            max_lat += 0.001
        if min_lon == max_lon:
            min_lon -= 0.001
            max_lon += 0.001

        def clamp(value: float, low: float, high: float) -> float:
            return max(low, min(high, value))

        def project(row: dict[str, Any]) -> tuple[float, float]:
            lon = float(row.get("longitude", 0.0))
            lat = float(row.get("latitude", 0.0))
            x = plot_x0 + (lon - min_lon) / (max_lon - min_lon) * (plot_x1 - plot_x0)
            y = plot_y0 + (max_lat - lat) / (max_lat - min_lat) * (plot_y1 - plot_y0)
            return clamp(x, plot_x0, plot_x1), clamp(y, plot_y0, plot_y1)

        for row in history[-300:]:
            x, y = project(row)
            canvas.create_oval(x - 2, y - 2, x + 2, y + 2, outline="#606060")

        for row in latest:
            x, y = project(row)
            canvas.create_oval(x - 5, y - 5, x + 5, y + 5, width=2)
            if show_labels:
                label = str(row.get("node_label") or row.get("node_id") or "node")
                label_x = min(x + 7, plot_x1 - 8)
                canvas.create_text(
                    label_x,
                    y,
                    anchor="w",
                    text=label,
                    width=max(40, plot_x1 - label_x),
                )

    def _build_system_tab(self) -> None:
        frame = ttk.Frame(self.system_tab, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=self._t("system.description"),
            wraplength=1200,
        ).pack(fill="x", pady=(0, 6))
        filters = ttk.Frame(frame)
        filters.pack(fill="x", pady=(0, 8))
        self.system_search_var = tk.StringVar()
        self.system_status_filter_var = tk.StringVar(value=self._t("system.filter.all"))
        ttk.Label(filters, text=self._t("common.search")).pack(side="left")
        system_search = ttk.Entry(filters, textvariable=self.system_search_var, width=28)
        system_search.pack(side="left", padx=(5, 10))
        system_search.bind("<Return>", lambda _event: self._apply_system_filters())
        ttk.Label(filters, text=self._t("common.status")).pack(side="left")
        ttk.Combobox(
            filters, state="readonly", width=20,
            textvariable=self.system_status_filter_var,
            values=[
                self._t("system.filter.all"),
                self._t("system.filter.ok"),
                self._t("system.filter.problems"),
            ],
        ).pack(side="left", padx=(5, 10))
        ttk.Button(filters, text=self._t("action.apply_filter"), command=self._apply_system_filters).pack(side="left")
        ttk.Button(filters, text=self._t("action.reset"), command=self._clear_system_filters).pack(side="left", padx=(6, 0))
        ttk.Button(filters, text=self._t("action.export"), command=self.export_system_status).pack(side="right")
        self.system_filter_result_label = ttk.Label(frame, text=self._t("system.current_snapshot"))
        self.system_filter_result_label.pack(fill="x", pady=(0, 5))
        columns = ("component", "status", "details")
        self.system_tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="extended"
        )
        self.system_tree.heading("component", text=self._t("system.column.component"))
        self.system_tree.heading("status", text=self._t("system.column.status"))
        self.system_tree.heading("details", text=self._t("system.column.details"))
        self.system_tree.column("component", width=230, anchor="w")
        self.system_tree.column("status", width=150, anchor="w")
        self.system_tree.column("details", width=780, anchor="w")
        self.system_tree.pack(fill="both", expand=True)
        controls = ttk.Frame(frame, padding=(0, 8))
        controls.pack(fill="x")
        ttk.Button(controls, text=self._t("system.self_test"), command=self.run_self_test).pack(side="left")
        self.remote_map_publication_button = ttk.Button(
            controls, text=self._t("system.map_publication.action.unavailable"),
            command=lambda: self._remote_base_control_action("MAP_PUB"), state="disabled",
        )
        self.remote_map_publication_button.pack(side="right", padx=(6, 0))
        self.remote_base_status_button = ttk.Button(
            controls, text=self._t("action.refresh_now"),
            command=lambda: self.request_remote_base_statuses(force=True), state="disabled",
        )
        self.remote_base_status_button.pack(side="right", padx=(6, 0))
        self.remote_aprs_igate_button = ttk.Button(
            controls, text=self._t("system.aprs_igate.action.safe_deactivate"),
            command=lambda: self._remote_base_control_action("APRS_IS_UPLINK"), state="disabled",
        )
        self.remote_aprs_igate_button.pack(side="right", padx=(6, 0))
        self.self_test_label = ttk.Label(controls, text="")
        self.self_test_label.pack(side="left", padx=12)

    def _build_operations_tab(self) -> None:
        frame = ttk.Frame(self.operations_tab, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=self._t("operations.description"),
            wraplength=1200,
        ).pack(fill="x", pady=(0, 6))
        self.sync_status_label = ttk.Label(frame, text=self._t("operations.sync_waiting"))
        self.sync_status_label.pack(fill="x", pady=(0, 3))
        self.queue_summary_label = ttk.Label(frame, text=self._t("operations.queue_waiting"))
        self.queue_summary_label.pack(fill="x", pady=(0, 3))
        self.queue_health_label = ttk.Label(frame, text=self._t("operations.long_waiting"))
        self.queue_health_label.pack(fill="x", pady=(0, 6))

        filters = ttk.LabelFrame(frame, text=self._t("operations.filtering"), padding=8)
        filters.pack(fill="x", pady=(0, 8))
        self.queue_search_var = tk.StringVar()
        self.queue_type_filter_var = tk.StringVar(value=self._t("operations.filter.type_all"))
        self.queue_state_filter_var = tk.StringVar(value=self._t("operations.filter.state_all"))
        self.queue_from_filter_var = tk.StringVar()
        self.queue_to_filter_var = tk.StringVar()
        ttk.Label(filters, text=self._t("operations.search_recipient")).grid(row=0, column=0, sticky="w")
        queue_search = ttk.Entry(filters, textvariable=self.queue_search_var, width=25)
        queue_search.grid(row=0, column=1, sticky="ew", padx=(5, 10))
        queue_search.bind("<Return>", lambda _event: self._apply_queue_filters())
        ttk.Label(filters, text=self._t("common.type")).grid(row=0, column=2, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=17,
            textvariable=self.queue_type_filter_var,
            values=[
                self._t("operations.filter.type_all"),
                self._t("operations.filter.type_message"),
                self._t("operations.filter.type_control"),
                self._t("operations.filter.type_gateway"),
            ],
        ).grid(row=0, column=3, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("common.state")).grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters, state="readonly", width=18,
            textvariable=self.queue_state_filter_var,
            values=[
                self._t("operations.filter.state_all"),
                self._t("operations.filter.state_waiting"),
                self._t("operations.filter.state_retry"),
                self._t("operations.filter.state_paused"),
                self._t("operations.filter.state_error"),
                self._t("operations.filter.state_other"),
            ],
        ).grid(row=0, column=5, sticky="w", padx=(5, 10))
        ttk.Label(filters, text=self._t("common.from")).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.queue_from_filter_var, width=20).grid(
            row=1, column=1, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Label(filters, text=self._t("common.to")).grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Entry(filters, textvariable=self.queue_to_filter_var, width=20).grid(
            row=1, column=3, sticky="w", padx=(5, 10), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.apply_filter"), command=self._apply_queue_filters).grid(
            row=1, column=4, sticky="e", padx=(0, 6), pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.reset"), command=self._clear_queue_filters).grid(
            row=1, column=5, sticky="w", pady=(6, 0)
        )
        ttk.Button(filters, text=self._t("action.export"), command=self.export_operations).grid(
            row=0, column=6, rowspan=2, sticky="ns", padx=(10, 0)
        )
        filters.columnconfigure(1, weight=1)
        self.queue_filter_result_label = ttk.Label(filters, text=self._t("operations.active_rows"))
        self.queue_filter_result_label.grid(row=2, column=0, columnspan=7, sticky="w", pady=(5, 0))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        columns = (
            "uid", "class", "priority", "route", "destination", "state",
            "attempts", "age", "last", "next", "expires", "error",
        )
        self.queue_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "uid": self._t("operations.column.uid"), "class": self._t("operations.column.class"), "priority": self._t("operations.column.priority"), "route": self._t("operations.column.route"),
            "destination": self._t("operations.column.destination"), "state": self._t("operations.column.state"), "attempts": self._t("operations.column.attempts"),
            "age": self._t("operations.column.age"), "last": self._t("operations.column.last"), "next": self._t("operations.column.next"), "expires": self._t("operations.column.expires"),
            "error": self._t("operations.column.error"),
        }
        widths = {
            "uid": 115, "class": 90, "priority": 85, "route": 160, "destination": 85,
            "state": 120, "attempts": 80, "age": 85, "last": 100, "next": 100,
            "expires": 100, "error": 300,
        }
        for column in columns:
            self.queue_tree.heading(column, text=headings[column])
            self.queue_tree.column(
                column, width=widths[column], anchor="w", stretch=column == "error"
            )
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.queue_tree.yview)
        self.queue_tree.configure(yscrollcommand=scroll.set)
        self.queue_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.queue_tree.bind("<<TreeviewSelect>>", lambda _event: self._show_selected_queue_details())

        controls = ttk.Frame(frame, padding=(0, 8))
        controls.pack(fill="x")
        ttk.Button(controls, text=self._t("operations.refresh_queue"), command=lambda: self._refresh_queue_view(force=True)).pack(side="left")
        ttk.Button(controls, text=self._t("operations.retry_selected"), command=self.retry_selected_outbox).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.pause_selected"), command=self.pause_selected_outbox).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.resume_selected"), command=self.resume_selected_outbox).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.renew_selected"), command=self.renew_selected_outbox).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.cancel_selected"), command=self.cancel_selected_outbox).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.database_maintenance"), command=self.run_database_maintenance).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text=self._t("operations.export_diagnostics"), command=self.export_diagnostics).pack(side="right")
        self.operations_result_label = ttk.Label(frame, text="")
        self.operations_result_label.pack(fill="x")

        detail_frame = ttk.LabelFrame(frame, text=self._t("operations.detail_title"), padding=8)
        detail_frame.pack(fill="x", pady=(8, 0))
        self.queue_detail_text = tk.Text(detail_frame, height=8, wrap="word", state="disabled")
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.queue_detail_text.yview)
        self.queue_detail_text.configure(yscrollcommand=detail_scroll.set)
        self.queue_detail_text.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")

    def _build_emergency_tab(self) -> None:
        frame = ttk.Frame(self.emergency_tab, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame,
            text=self._t("emergency.heading"),
            font=("TkDefaultFont", 15, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text=self._t("emergency.description"),
            wraplength=1050,
        ).pack(anchor="w", pady=(4, 10))

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(
            toolbar, text=self._t("emergency.action.new"), command=self.new_emergency_template
        ).pack(side="left")
        self.emergency_edit_button = ttk.Button(
            toolbar, text=self._t("emergency.action.edit"), command=self.edit_selected_emergency_template
        )
        self.emergency_edit_button.pack(side="left", padx=(6, 0))
        self.emergency_copy_button = ttk.Button(
            toolbar, text=self._t("emergency.action.copy"), command=self.copy_selected_emergency_template
        )
        self.emergency_copy_button.pack(side="left", padx=(6, 0))
        self.emergency_delete_button = ttk.Button(
            toolbar, text=self._t("emergency.action.delete"), command=self.delete_selected_emergency_template
        )
        self.emergency_delete_button.pack(side="left", padx=(6, 0))
        self.emergency_move_up_button = ttk.Button(
            toolbar,
            text=self._t("emergency.action.move_up"),
            command=lambda: self.move_selected_emergency_template(-1),
        )
        self.emergency_move_up_button.pack(side="left", padx=(14, 0))
        self.emergency_move_down_button = ttk.Button(
            toolbar,
            text=self._t("emergency.action.move_down"),
            command=lambda: self.move_selected_emergency_template(1),
        )
        self.emergency_move_down_button.pack(side="left", padx=(6, 0))
        ttk.Button(
            toolbar, text=self._t("emergency.action.import"), command=self.import_emergency_templates
        ).pack(side="right")
        ttk.Button(
            toolbar, text=self._t("emergency.action.export"), command=self.export_emergency_templates
        ).pack(side="right", padx=(0, 6))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        columns = ("name", "category", "severity", "confirmation", "preview")
        self.emergency_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=12,
        )
        headings = {
            "name": self._t("emergency.column.name"),
            "category": self._t("emergency.column.category"),
            "severity": self._t("emergency.column.severity"),
            "confirmation": self._t("emergency.column.confirmation"),
            "preview": self._t("emergency.column.message"),
        }
        widths = {
            "name": 220,
            "category": 120,
            "severity": 130,
            "confirmation": 110,
            "preview": 620,
        }
        for column in columns:
            self.emergency_tree.heading(column, text=headings[column])
            self.emergency_tree.column(
                column,
                width=widths[column],
                anchor="w",
                stretch=column == "preview",
            )
        emergency_scroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.emergency_tree.yview
        )
        self.emergency_tree.configure(yscrollcommand=emergency_scroll.set)
        self.emergency_tree.pack(side="left", fill="both", expand=True)
        emergency_scroll.pack(side="right", fill="y")
        self.emergency_tree.bind(
            "<<TreeviewSelect>>", self._emergency_template_selection_changed
        )
        self.emergency_tree.bind(
            "<Double-1>", lambda _event: self.use_selected_emergency_template()
        )

        details = ttk.LabelFrame(frame, text=self._t("emergency.selected"), padding=8)
        details.pack(fill="x", pady=(8, 0))
        self.emergency_details_text = tk.Text(
            details,
            height=5,
            wrap="word",
            state="disabled",
            padx=6,
            pady=4,
        )
        self.emergency_details_text.pack(fill="x", expand=True)

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=(8, 0))
        self.emergency_status_label = ttk.Label(bottom, text="")
        self.emergency_status_label.pack(side="left")
        self.emergency_use_button = ttk.Button(
            bottom,
            text=self._t("emergency.action.use_selected"),
            command=self.use_selected_emergency_template,
        )
        self.emergency_use_button.pack(side="right")
        self._refresh_emergency_templates()

    def _build_help_tab(self) -> None:
        text_widget = tk.Text(self.help_tab, wrap="word", padx=16, pady=14)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", self._t("help.body"))
        text_widget.configure(state="disabled")

    @staticmethod
    def _parse_optional_range(
        start_text: str, end_text: str, *, language: str = "nb"
    ) -> tuple[datetime | None, datetime | None]:
        start = parse_datetime_input(start_text, end_of_day=False)
        end = parse_datetime_input(end_text, end_of_day=True)
        if start is not None and end is not None and start > end:
            raise ValueError(translate("export_options.range_order", language))
        return start, end

    def _message_filters_active(self) -> bool:
        return any(
            (
                self.message_search_var.get().strip(),
                self.message_contact_filter_var.get().strip(),
                self.message_from_filter_var.get().strip(),
                self.message_to_filter_var.get().strip(),
                self._network_filter_code(
                    self.message_network_filter_var.get(),
                    "messages.filter.network_all",
                ) != "all",
                self._message_direction_filter_code() != "all",
                self._message_status_filter_code() != "all",
            )
        )

    def _get_all_message_rows(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        if self.all_message_rows_cache is not None and not refresh:
            return list(self.all_message_rows_cache)
        previous_cursor = ""
        try:
            previous_cursor = str(self.cget("cursor"))
            self.configure(cursor="watch")
        except tk.TclError:
            pass
        self.message_filter_result_label.configure(text=self._t("messages.history.loading"))
        self.update_idletasks()
        carrier_rows: list[dict[str, Any]] = []
        before_id: int | None = None
        page_size = 1000
        max_rows = max(1000, int(self.config.get("export_message_max_rows", 100000)))
        truncated = False
        try:
            while len(carrier_rows) < max_rows:
                request: dict[str, Any] = {"command": "list_display", "limit": page_size}
                if before_id is not None:
                    request["before_id"] = before_id
                page = self.ws_client.call(request).get("messages", [])
                if not page:
                    break
                carrier_rows = list(page) + carrier_rows
                ids = [int(row["id"]) for row in page if row.get("id") is not None]
                if len(carrier_rows) % 5000 < page_size:
                    self.message_filter_result_label.configure(
                        text=self._t("messages.history.loading_rows", count=len(carrier_rows))
                    )
                    self.update_idletasks()
                if not ids or len(page) < page_size:
                    break
                before_id = min(ids)
            else:
                truncated = True
            logical = self._logical_control_rows(carrier_rows)
            visible = self._virtual_messages(logical)
            self.all_message_rows_cache = list(visible)
            self.all_message_rows_cache_signature = self._message_signature(visible[-20:])
            if truncated:
                messagebox.showwarning(
                    self._t("messages.history_large_title"),
                    self._t("messages.history_large_body", max_rows=max_rows),
                    parent=self,
                )
            return list(visible)
        finally:
            try:
                self.configure(cursor=previous_cursor)
            except tk.TclError:
                pass

    def _filter_message_rows(
        self,
        rows: list[dict[str, Any]],
        *,
        use_time_fields: bool = True,
    ) -> list[dict[str, Any]]:
        start = end = None
        if use_time_fields:
            start, end = self._parse_optional_range(
                self.message_from_filter_var.get(), self.message_to_filter_var.get()
            )
        search = self.message_search_var.get().strip().casefold()
        contact = self.message_contact_filter_var.get().strip().casefold()
        network = self._network_filter_code(
            self.message_network_filter_var.get(), "messages.filter.network_all"
        )
        direction = self._message_direction_filter_code()
        status_filter = self._message_status_filter_code()
        result: list[dict[str, Any]] = []
        for row in rows:
            row_network_key = self._network_key_from_row(row)
            row_network = self._network_label(row_network_key)
            row_direction_code = "received" if row.get("direction") == "received" else "sent"
            row_direction = self._t(
                "messages.filter.direction_received"
                if row_direction_code == "received"
                else "messages.filter.direction_sent"
            )
            source_label = self._label_from_row(row, "source")
            destination_label = self._label_from_row(row, "destination")
            status = str(row.get("status", ""))
            text = str(row.get("text", ""))
            if network != "all" and row_network_key != network:
                continue
            if direction != "all" and row_direction_code != direction:
                continue
            if contact and contact not in " ".join(
                (source_label, destination_label, str(row.get("source", "")), str(row.get("destination", "")))
            ).casefold():
                continue
            folded_status = status.casefold()
            if status_filter == "confirmed" and "bekreftet" not in folded_status:
                continue
            if status_filter == "recipient_confirmed" and "bekreftet av mottakernode" not in folded_status:
                continue
            if status_filter == "waiting" and not any(
                token in folded_status for token in ("venter", "utboks", "kø", "lagt i")
            ):
                continue
            if status_filter == "error" and not any(
                token in folded_status for token in ("feil", "nak", "avbrutt", "ingen svar")
            ):
                continue
            if status_filter == "expired" and "utløpt" not in folded_status:
                continue
            if status_filter == "received" and row_direction_code != "received" and "mottatt" not in folded_status:
                continue
            if search:
                haystack = " ".join(
                    (
                        row_network, row_direction, source_label, destination_label,
                        status, text, str(row.get("source", "")), str(row.get("destination", "")),
                    )
                ).casefold()
                if search not in haystack:
                    continue
            if not in_inclusive_range(row.get("timestamp"), start, end):
                continue
            result.append(row)
        return result

    def _apply_message_filters(self) -> None:
        try:
            rows = self._get_all_message_rows(refresh=True) if self._message_filters_active() else list(self.recent_message_rows)
            filtered = self._filter_message_rows(rows)
            self._render_messages(filtered)
            self.message_filter_result_label.configure(
                text=self._t("messages.result.count", shown=len(filtered), total=len(rows))
            )
        except Exception as exc:
            messagebox.showerror(self._t("messages.filter_error_title"), str(exc), parent=self)

    def _clear_message_filters(self) -> None:
        self.message_search_var.set("")
        self.message_network_filter_var.set(self._t("messages.filter.network_all"))
        self.message_direction_filter_var.set(self._t("messages.filter.direction_all"))
        self.message_contact_filter_var.set("")
        self.message_status_filter_var.set(self._t("messages.filter.status_all"))
        self.message_from_filter_var.set("")
        self.message_to_filter_var.set("")
        self._render_messages(list(self.recent_message_rows))
        self.message_filter_result_label.configure(
            text=self._t("messages.result.recent", count=len(self.recent_message_rows))
        )

    def _format_position_duration(self, seconds: int) -> str:
        seconds = max(0, int(seconds))
        if seconds < 60:
            return self._t("position.duration.now")
        minutes = seconds // 60
        if minutes < 60:
            return self._t("position.duration.minutes", minutes=minutes)
        hours = minutes // 60
        if hours < 24:
            remaining = minutes % 60
            if remaining == 0:
                return self._t("position.duration.hours", hours=hours)
            return self._t("position.duration.hours_minutes", hours=hours, minutes=remaining)
        days = hours // 24
        remaining_hours = hours % 24
        if remaining_hours == 0:
            return self._t("position.duration.days", days=days)
        return self._t("position.duration.days_hours", days=days, hours=remaining_hours)

    def _position_display_fields(
        self,
        position: dict[str, Any] | None,
        *,
        now_epoch: int | None = None,
        stale_minutes: int | None = None,
    ) -> tuple[str, str, str]:
        if not position:
            return "—", self._t("position.state.unknown"), "unknown"
        try:
            latitude = float(position["latitude"])
            longitude = float(position["longitude"])
            position_epoch = int(position["position_epoch"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return "—", self._t("position.state.unknown"), "unknown"
        current = int(time.time()) if now_epoch is None else int(now_epoch)
        age_seconds = max(0, current - position_epoch)
        if stale_minutes is None:
            stale_minutes = self.position_store.stale_minutes()
        stale_seconds = max(60, int(stale_minutes) * 60)
        state = "fresh" if age_seconds <= stale_seconds else "stale"
        state_label = self._t(
            "position.state.fresh" if state == "fresh" else "position.state.stale"
        )
        return (
            f"{latitude:.5f}, {longitude:.5f}",
            f"{state_label} · {self._format_position_duration(age_seconds)}",
            state,
        )

    def _position_index(self) -> dict[tuple[str, str], dict[str, Any]]:
        try:
            rows = self.position_store.list_latest()
        except Exception:
            return {}
        return {
            (str(row.get("network", "")), str(row.get("node_id", ""))): row
            for row in rows
            if row.get("network") and row.get("node_id")
        }

    def _position_history_network_key(self) -> str | None:
        code = self._network_filter_code(
            self.position_history_network_var.get(),
            "position_history.filter.network_all",
        )
        return None if code == "all" else code

    def _position_history_signature(self) -> tuple[Any, ...]:
        values: list[tuple[str, int, int]] = []
        for key in self.network_order:
            if self.networks[key].get("kind") == "waveshare":
                continue
            values.append(
                (
                    key,
                    self.position_store.history_count(key),
                    self.position_store.current_history_sequence(key),
                )
            )
        return tuple(values)

    def _clear_position_history_filters(self) -> None:
        self.position_history_network_var.set(self._t("position_history.filter.network_all"))
        self.position_history_node_var.set("")
        self.position_history_limit_var.set("250")
        self._refresh_position_history_view(force=True)

    def _refresh_position_history_view(self, *, force: bool = False) -> None:
        """Render a bounded local history list without map or export features."""
        if not hasattr(self, "position_history_tree"):
            return
        try:
            signature = self._position_history_signature()
            if not force and signature == self.last_position_history_signature:
                return
            limit = max(1, min(int(self.position_history_limit_var.get()), 1000))
            network = self._position_history_network_key()
            query = self.position_history_node_var.get().strip().casefold()
            # Fetch a larger bounded window when a name filter is active because
            # aliases and long names are resolved outside the history table.
            fetch_limit = min(5000, max(limit, limit * 5 if query else limit))
            rows = self.position_store.list_history(
                network,
                limit=fetch_limit,
                newest_first=True,
            )
            rendered: list[dict[str, Any]] = []
            for row in rows:
                route = str(row.get("network", ""))
                node_id = str(row.get("node_id", ""))
                label = self.contacts.alias(route, node_id) or self._resolve_node_name(
                    route,
                    node_id,
                )
                if query:
                    haystack = " ".join(
                        (
                            route,
                            node_id,
                            str(label),
                            str(row.get("num", "")),
                        )
                    ).casefold()
                    if query not in haystack:
                        continue
                item = dict(row)
                item["node_label"] = str(label or node_id)
                rendered.append(item)
                if len(rendered) >= limit:
                    break

            children = self.position_history_tree.get_children()
            if children:
                self.position_history_tree.delete(*children)
            self.visible_position_history_rows = rendered
            self.position_history_item_rows = {}
            for row in rendered:
                latitude = float(row.get("latitude", 0.0))
                longitude = float(row.get("longitude", 0.0))
                gnss = []
                if row.get("sats_in_view") not in (None, ""):
                    gnss.append(self._t("position_history.gnss.sat", value=row['sats_in_view']))
                if row.get("fix_quality") not in (None, ""):
                    gnss.append(self._t("position_history.gnss.quality", value=row['fix_quality']))
                if row.get("fix_type") not in (None, ""):
                    gnss.append(self._t("position_history.gnss.type", value=row['fix_type']))
                signal = []
                if row.get("rx_rssi") not in (None, ""):
                    signal.append(f"RSSI {row['rx_rssi']} dBm")
                if row.get("rx_snr") not in (None, ""):
                    signal.append(f"SNR {float(row['rx_snr']):g} dB")
                self.position_history_tree.insert(
                    "",
                    "end",
                    iid=f"position-history:{int(row['sequence'])}",
                    values=(
                        self._position_timestamp(row.get("position_epoch")),
                        self._network_label(str(row.get("network", ""))),
                        row["node_label"],
                        f"{latitude:.7f}, {longitude:.7f}",
                        (
                            f"{row['altitude']} m"
                            if row.get("altitude") not in (None, "")
                            else "—"
                        ),
                        (
                            f"{row['precision_bits']} bit"
                            if row.get("precision_bits") not in (None, "")
                            else self._t("common.unknown")
                        ),
                        ", ".join(gnss) if gnss else "—",
                        ", ".join(signal) if signal else "—",
                        str(row.get("source") or self._t("common.unknown")),
                    ),
                )
                self.position_history_item_rows[
                    f"position-history:{int(row['sequence'])}"
                ] = row
            total = self.position_store.history_count(network)
            self.position_history_status_var.set(
                self._t(
                    "position_history.status.count",
                    shown=len(rendered),
                    total=total,
                )
            )
            self.last_position_history_signature = signature
        except Exception as exc:
            self.position_history_status_var.set(
                self._t("position_history.status.error", error=exc)
            )

    def _position_export_node_options(self) -> list[dict[str, str]]:
        """Return stable network/node choices for the position export dialog."""
        options: list[dict[str, str]] = []
        for row in self.position_store.history_nodes():
            network = str(row.get("network", ""))
            node_id = str(row.get("node_id", ""))
            label = self.contacts.alias(network, node_id) or self._resolve_node_name(
                network,
                node_id,
            )
            options.append(
                {
                    "network": network,
                    "node_id": node_id,
                    "label": (
                        f"{self._network_label(network)} · {label or node_id} "
                        f"({node_id})"
                    ),
                }
            )
        return options

    def _position_export_rows(
        self,
        scope: str,
        *,
        network: str | None = None,
        node_id: str | None = None,
        from_text: str = "",
        to_text: str = "",
    ) -> list[dict[str, Any]]:
        """Resolve one export scope without reading coordinates from Treeview text."""
        if scope == "selected":
            rows = self._selected_mapped_rows(
                self.position_history_tree,
                self.position_history_item_rows,
            )
            sequences = [int(row["sequence"]) for row in rows]
            result = self.position_store.history_by_sequences(
                sequences,
                max_rows=self.position_export_max_rows,
            )
        elif scope == "visible":
            sequences = [
                int(row["sequence"]) for row in self.visible_position_history_rows
            ]
            result = self.position_store.history_by_sequences(
                sequences,
                max_rows=self.position_export_max_rows,
            )
        elif scope in {"node_range", "node_all"}:
            if not network or not node_id:
                raise ValueError(self._t("position_export.error.select_node"))
            start = None
            end = None
            if scope == "node_range":
                start = parse_datetime_input(from_text)
                end = parse_datetime_input(to_text, end_of_day=True)
                if start is None and end is None:
                    raise ValueError(self._t("position_export.error.range_required"))
                if start is not None and end is not None and start > end:
                    raise ValueError(self._t("position_export.error.range_order"))
            result = self.position_store.history_for_export(
                network,
                node_id,
                from_epoch=None if start is None else int(start.timestamp()),
                to_epoch=None if end is None else int(end.timestamp()),
                max_rows=self.position_export_max_rows,
            )
        else:
            raise ValueError(self._t("position_export.error.unknown_scope"))
        if not result:
            raise ValueError(self._t("position_export.error.no_points"))
        enriched: list[dict[str, Any]] = []
        for row in result:
            item = dict(row)
            route = str(item.get("network", ""))
            identity = str(item.get("node_id", ""))
            item["node_label"] = (
                self.contacts.alias(route, identity)
                or self._resolve_node_name(route, identity)
                or identity
            )
            enriched.append(item)
        return enriched

    def export_position_history(self) -> None:
        """Open a controlled position export dialog without map or send actions."""
        node_options = self._position_export_node_options()
        node_by_label = {item["label"]: item for item in node_options}
        dialog = tk.Toplevel(self)
        dialog.title(self._t("position_export.title"))
        dialog.transient(self)
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)

        scope_labels = {
            self._t("position_export.scope.selected"): "selected",
            self._t("position_export.scope.visible"): "visible",
            self._t("position_export.scope.node_range"): "node_range",
            self._t("position_export.scope.node_all"): "node_all",
        }
        format_labels = {
            "CSV": "csv",
            "GPX": "gpx",
            "GeoJSON": "geojson",
        }
        scope_var = tk.StringVar(
            value=(
                self._t("position_export.scope.selected")
                if self.position_history_tree.selection()
                else self._t("position_export.scope.visible")
            )
        )
        format_var = tk.StringVar(value="CSV")
        node_var = tk.StringVar(value=node_options[0]["label"] if node_options else "")
        from_var = tk.StringVar()
        to_var = tk.StringVar()
        precision_var = tk.StringVar(value="reduced")

        ttk.Label(frame, text=self._t("common.format")).grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            frame,
            state="readonly",
            textvariable=format_var,
            values=list(format_labels),
            width=28,
        ).grid(row=0, column=1, sticky="ew", padx=(10, 0))
        ttk.Label(frame, text=self._t("common.scope")).grid(row=1, column=0, sticky="w", pady=(8, 0))
        scope_combo = ttk.Combobox(
            frame,
            state="readonly",
            textvariable=scope_var,
            values=list(scope_labels),
            width=34,
        )
        scope_combo.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(8, 0))
        ttk.Label(frame, text=self._t("common.node")).grid(row=2, column=0, sticky="w", pady=(8, 0))
        node_combo = ttk.Combobox(
            frame,
            state="readonly",
            textvariable=node_var,
            values=[item["label"] for item in node_options],
            width=54,
        )
        node_combo.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=(8, 0))
        ttk.Label(frame, text=self._t("common.from_inclusive")).grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        from_entry = ttk.Entry(frame, textvariable=from_var)
        from_entry.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=(8, 0))
        ttk.Label(frame, text=self._t("common.to_inclusive")).grid(
            row=4, column=0, sticky="w", pady=(8, 0)
        )
        to_entry = ttk.Entry(frame, textvariable=to_var)
        to_entry.grid(row=4, column=1, sticky="ew", padx=(10, 0), pady=(8, 0))

        precision = ttk.LabelFrame(frame, text=self._t("position_export.precision"), padding=8)
        precision.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        ttk.Radiobutton(
            precision,
            text=self._t("position_export.precision.reduced"),
            value="reduced",
            variable=precision_var,
        ).pack(anchor="w")
        ttk.Radiobutton(
            precision,
            text=self._t("position_export.precision.exact"),
            value="exact",
            variable=precision_var,
        ).pack(anchor="w", pady=(4, 0))
        ttk.Label(
            frame,
            text=self._t("position_export.privacy_note"),
            wraplength=560,
            justify="left",
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))

        def update_scope_controls(event: Any = None) -> None:
            selected = scope_labels.get(scope_var.get(), "visible")
            node_state = "readonly" if selected in {"node_range", "node_all"} else "disabled"
            time_state = "normal" if selected == "node_range" else "disabled"
            node_combo.configure(state=node_state)
            from_entry.configure(state=time_state)
            to_entry.configure(state=time_state)

        def perform_export() -> None:
            try:
                scope = scope_labels[scope_var.get()]
                option = node_by_label.get(node_var.get())
                rows = self._position_export_rows(
                    scope,
                    network=None if option is None else option["network"],
                    node_id=None if option is None else option["node_id"],
                    from_text=from_var.get(),
                    to_text=to_var.get(),
                )
                export_format = format_labels[format_var.get()]
                extension = {
                    "csv": ".csv",
                    "gpx": ".gpx",
                    "geojson": ".geojson",
                }[export_format]
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                filename = filedialog.asksaveasfilename(
                    parent=dialog,
                    title=self._t("position_export.save_title"),
                    defaultextension=extension,
                    initialfile=f"gutochat-posisjoner-{self._station_file_stem()}-{stamp}{extension}",
                    filetypes=[
                        ("CSV", "*.csv"),
                        ("GPX", "*.gpx"),
                        ("GeoJSON", "*.geojson"),
                        (self._t("common.all_files"), "*"),
                    ],
                )
                if not filename:
                    return
                selected_precision = precision_var.get()
                if selected_precision == "exact":
                    identities = {
                        (str(row.get("network", "")), str(row.get("node_id", "")))
                        for row in rows
                    }
                    epochs = [int(row["position_epoch"]) for row in rows]
                    if not messagebox.askyesno(
                        self._t("position_export.confirm_title"),
                        self._t(
                            "position_export.confirm_body",
                            points=len(rows),
                            nodes=len(identities),
                            start=self._position_timestamp(min(epochs)),
                            end=self._position_timestamp(max(epochs)),
                            filename=filename,
                        ),
                        parent=dialog,
                    ):
                        return
                count = write_position_export(
                    Path(filename),
                    rows,
                    export_format=export_format,
                    precision=selected_precision,
                    max_rows=self.position_export_max_rows,
                )
                dialog.destroy()
                messagebox.showinfo(
                    self._t("position_export.done_title"),
                    self._t("position_export.done_body", count=count, filename=filename),
                    parent=self,
                )
            except Exception as exc:
                messagebox.showerror(self._t("position_export.error_title"), str(exc), parent=dialog)

        scope_combo.bind("<<ComboboxSelected>>", update_scope_controls)
        buttons = ttk.Frame(frame)
        buttons.grid(row=7, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text=self._t("action.cancel"), command=dialog.destroy).pack(side="right")
        ttk.Button(buttons, text=self._t("action.export"), command=perform_export).pack(
            side="right", padx=(0, 8)
        )
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        update_scope_controls()
        dialog.grab_set()
        self.wait_window(dialog)

    def _node_position_key(
        self, network_key: str, node_id: Any, node_num: Any = None
    ) -> tuple[str, str] | None:
        network = self.networks.get(network_key, {})
        if network.get("kind") == "waveshare":
            return None
        try:
            numeric = None if node_num in (None, "") else int(node_num)
            canonical = canonical_meshtastic_id(node_id, node_num=numeric)
        except (TypeError, ValueError, OverflowError):
            return None
        return network_key, canonical

    def _position_timestamp(self, epoch: Any) -> str:
        try:
            return datetime.fromtimestamp(int(epoch)).astimezone().isoformat(
                timespec="seconds"
            )
        except (TypeError, ValueError, OverflowError, OSError):
            return self._t("position.detail.unknown")

    def _optional_position_value(self, value: Any, suffix: str = "") -> str:
        if value in (None, ""):
            return self._t("position.detail.unknown")
        return f"{value}{suffix}"

    def _position_detail_text(self, row: dict[str, Any]) -> str:
        position = row.get("position")
        node_label = str(
            row.get("alias")
            or row.get("long_name")
            or row.get("short_name")
            or row.get("node_id")
            or self._t("position.detail.selected_node")
        )
        if not position:
            return self._t(
                "position.detail.none",
                label=node_label,
                node_id=row.get("node_id", ""),
            )
        latitude = float(position["latitude"])
        longitude = float(position["longitude"])
        radio_parts = []
        if position.get("channel") not in (None, ""):
            radio_parts.append(
                self._t("position.detail.channel", value=position["channel"])
            )
        if position.get("rx_rssi") not in (None, ""):
            radio_parts.append(f"RSSI {position['rx_rssi']} dBm")
        if position.get("rx_snr") not in (None, ""):
            radio_parts.append(f"SNR {float(position['rx_snr']):g} dB")
        gnss_parts = []
        for field, key in (
            ("precision_bits", "position.detail.precision"),
            ("sats_in_view", "position.detail.satellites"),
            ("fix_quality", "position.detail.fix_quality"),
            ("fix_type", "position.detail.fix_type"),
        ):
            value = position.get(field)
            if value not in (None, ""):
                gnss_parts.append(self._t(key, value=value))
        unknown = self._t("position.detail.unknown")
        source_parts = [str(position.get("source") or unknown)]
        if position.get("location_source") not in (None, ""):
            source_parts.append(
                self._t(
                    "position.detail.location_source",
                    value=position["location_source"],
                )
            )
        if position.get("altitude_source") not in (None, ""):
            source_parts.append(
                self._t(
                    "position.detail.altitude_source",
                    value=position["altitude_source"],
                )
            )
        return "\n".join(
            (
                self._t(
                    "position.detail.line_identity",
                    label=node_label,
                    node_id=row.get("node_id", ""),
                    network=row.get("network", ""),
                ),
                self._t(
                    "position.detail.line_coordinates",
                    latitude=latitude,
                    longitude=longitude,
                    altitude=self._optional_position_value(
                        position.get("altitude"), " m"
                    ),
                ),
                self._t(
                    "position.detail.line_time",
                    time=self._position_timestamp(position.get("position_epoch")),
                    time_source=position.get("position_time_source") or unknown,
                    received=position.get("received_at") or unknown,
                ),
                self._t(
                    "position.detail.line_age",
                    age=row.get("position_age_display", unknown),
                    source=", ".join(source_parts),
                ),
                self._t(
                    "position.detail.line_meta",
                    gnss=(
                        ", ".join(gnss_parts)
                        if gnss_parts
                        else self._t("position.detail.no_gnss")
                    ),
                    radio=(
                        ", ".join(radio_parts)
                        if radio_parts
                        else self._t("position.detail.no_radio")
                    ),
                ),
            )
        )

    def _position_privacy_summary(self) -> str:
        status = self.position_store.aggregate_status()
        enabled = bool(status.get("storage_enabled"))
        count = int(status.get("position_count", 0))
        history_count = int(status.get("history_count", 0))
        stale_minutes = int(status.get("stale_minutes", self.position_store.stale_minutes()))
        storage_text = self._t(
            "position.privacy.storage_on" if enabled else "position.privacy.storage_off"
        )
        return self._t(
            "position.privacy.summary",
            storage=storage_text,
            count=count,
            history=history_count,
            minutes=stale_minutes,
        )

    def _refresh_position_privacy_status(self, notice: str = "") -> None:
        text = self._position_privacy_summary()
        if notice:
            text = f"{notice} {text}"
        self.position_privacy_status_var.set(text)

    def _refresh_position_privacy_controls(self, notice: str = "") -> None:
        self.position_storage_enabled_var.set(
            self.position_store.storage_enabled()
        )
        self.position_stale_minutes_var.set(
            str(self.position_store.stale_minutes())
        )
        self._refresh_position_privacy_status(notice)

    def _set_position_storage_enabled(self) -> None:
        requested = bool(self.position_storage_enabled_var.get())
        try:
            self.position_store.set_storage_enabled(requested)
            notice = self._t(
                "position.storage.enabled" if requested else "position.storage.disabled"
            )
            self._refresh_position_privacy_controls(notice)
            self.last_system_signature = None
        except Exception as exc:
            self.position_storage_enabled_var.set(
                self.position_store.storage_enabled()
            )
            messagebox.showerror(
                self._t("position.storage.error_title"),
                self._t("position.storage.error_body", error=exc),
                parent=self,
            )

    def _save_position_stale_minutes(self) -> None:
        try:
            raw = self.position_stale_minutes_var.get().strip()
            if not raw:
                raise ValueError(self._t("position.age.empty"))
            minutes = int(raw)
            self.position_store.set_stale_minutes(minutes)
            self.last_node_signature = None
            self.last_system_signature = None
            self._refresh_node_tree()
            self._node_selection_changed()
            self._refresh_position_privacy_controls(
                self._t("position.age.saved", minutes=minutes)
            )
        except Exception as exc:
            self.position_stale_minutes_var.set(
                str(self.position_store.stale_minutes())
            )
            messagebox.showerror(
                self._t("position.age.error_title"),
                self._t("position.age.error_body", error=exc),
                parent=self,
            )

    def _delete_all_positions(self) -> None:
        latest_count = self.position_store.count()
        history_count = self.position_store.history_count()
        count = latest_count + history_count
        if count <= 0:
            self._refresh_position_privacy_controls(self._t("position.delete.none"))
            return
        if not messagebox.askyesno(
            self._t("position.delete.title"),
            self._t("position.delete.confirm", latest=latest_count, history=history_count),
            parent=self,
        ):
            return
        try:
            self.position_store.clear_positions()
            self.last_node_signature = None
            self.last_system_signature = None
            self.last_position_history_signature = None
            self._refresh_node_tree()
            self._node_selection_changed()
            self._refresh_position_history_view(force=True)
            self._refresh_position_privacy_controls(
                self._t("position.delete.done", count=count)
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("position.delete.error_title"),
                self._t("position.delete.error_body", error=exc),
                parent=self,
            )

    def _node_selection_changed(self, _event: Any = None) -> None:
        selected = self.node_tree.selection()
        if len(selected) != 1:
            self.node_position_detail_var.set(self._t("nodes.position_choose"))
            return
        row = self.node_tree_rows.get(selected[0])
        if not row:
            self.node_position_detail_var.set(self._t("nodes.position_choose"))
            return
        self.node_position_detail_var.set(self._position_detail_text(row))

    def _all_node_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        positions = self._position_index()
        stale_minutes = self.position_store.stale_minutes()
        for key in self.network_order:
            network = self.networks[key]
            for node in self._sorted_nodes(key):
                node_id = str(node.get("id", node.get("num", "")))
                alias = self.contacts.alias(key, node_id)
                favorite = self.contacts.favorite(key, node_id)
                position_key = self._node_position_key(
                    key, node_id, node.get("num")
                )
                position = positions.get(position_key) if position_key else None
                position_display, position_age_display, position_state = (
                    self._position_display_fields(
                        position, stale_minutes=stale_minutes
                    )
                )
                rows.append(
                    {
                        "network_key": key,
                        "network": str(network["label"]),
                        "node_id": node_id,
                        "num": node.get("num", ""),
                        "alias": alias,
                        "favorite": bool(favorite),
                        "long_name": str(node.get("long_name", "")),
                        "short_name": str(node.get("short_name", "")),
                        "role": self._gateway_role(key, node),
                        "last_display": self._format_node_time(node),
                        "last_value": node.get("last_heard") or node.get("last_updated"),
                        "state": self._node_state(node, key),
                        "manual": bool(node.get("manual", False)),
                        "snr": node.get("snr"),
                        "source": str(node.get("source", "")),
                        "type": self._t(
                            "nodes.type.contact" if alias else "nodes.type.node"
                        ),
                        "node": node,
                        "position": position,
                        "position_display": position_display,
                        "position_age_display": position_age_display,
                        "position_state": position_state,
                    }
                )
        return rows

    def _filter_node_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        start, end = self._parse_optional_range(
            self.node_from_filter_var.get(), self.node_to_filter_var.get()
        )
        search = self.node_search_var.get().strip().casefold()
        network = self._network_filter_code(
            self.node_network_filter_var.get(), "nodes.filter.network_all"
        )
        row_type = self._node_type_filter_code()
        favorite = self._node_favorite_filter_code()
        manual = self._node_source_filter_code()
        result: list[dict[str, Any]] = []
        for row in rows:
            if network != "all" and row["network_key"] != network:
                continue
            if row_type == "contacts" and not row["alias"]:
                continue
            if row_type == "without_alias" and row["alias"]:
                continue
            if favorite == "favorite" and not row["favorite"]:
                continue
            if favorite == "not_favorite" and row["favorite"]:
                continue
            if manual == "manual" and not row["manual"]:
                continue
            if manual == "discovered" and row["manual"]:
                continue
            if search:
                haystack = " ".join(
                    str(row.get(key, ""))
                    for key in (
                        "network", "node_id", "num", "alias", "long_name",
                        "short_name", "role", "state", "source",
                    )
                ).casefold()
                if search not in haystack:
                    continue
            if not in_inclusive_range(row.get("last_value"), start, end):
                continue
            result.append(row)
        return result

    def _render_node_rows(self, rows: list[dict[str, Any]]) -> None:
        selected_identity: tuple[str, str] | None = None
        selected = self.node_tree.selection()
        if len(selected) == 1:
            selected_identity = self.node_tree_items.get(selected[0])
        children = self.node_tree.get_children()
        if children:
            self.node_tree.delete(*children)
        self.node_tree_items.clear()
        self.node_tree_rows.clear()
        self.visible_node_rows = list(rows)
        for index, row in enumerate(rows):
            iid = self.node_tree.insert(
                "", "end", iid=f"node:{index}",
                values=(
                    row["network"], "★" if row["favorite"] else "", row["alias"],
                    row["long_name"], row["node_id"], row["short_name"],
                    row["role"], row["last_display"], row["state"],
                    row.get("position_display", "—"),
                    row.get("position_age_display", "Ukjent"),
                ),
            )
            identity = (str(row["network_key"]), str(row["node_id"]))
            self.node_tree_items[iid] = identity
            self.node_tree_rows[iid] = row
            if selected_identity == identity:
                self.node_tree.selection_set(iid)
                self.node_tree.focus(iid)
        self._node_selection_changed()

    def _apply_node_filters(self) -> None:
        try:
            all_rows = self._all_node_rows()
            rows = self._filter_node_rows(all_rows)
            self._render_node_rows(rows)
            self.node_filter_result_label.configure(text=self._t("nodes.result.count", shown=len(rows), total=len(all_rows)))
        except Exception as exc:
            messagebox.showerror(self._t("nodes.filter_error_title"), str(exc), parent=self)

    def _clear_node_filters(self) -> None:
        self.node_search_var.set("")
        self.node_network_filter_var.set(self._t("nodes.filter.network_all"))
        self.node_type_filter_var.set(self._t("nodes.filter.type_all"))
        self.node_favorite_filter_var.set(self._t("nodes.filter.all"))
        self.node_manual_filter_var.set(self._t("nodes.filter.all"))
        self.node_from_filter_var.set("")
        self.node_to_filter_var.set("")
        rows = self._all_node_rows()
        self._render_node_rows(rows)
        self.node_filter_result_label.configure(text=self._t("nodes.result.all_count", count=len(rows)))

    def _filter_system_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        search = self.system_search_var.get().strip().casefold()
        status_filter = self._system_status_filter_code()
        result: list[dict[str, Any]] = []
        for row in rows:
            status = str(row["status"]).upper()
            if status_filter == "ok" and status != "OK":
                continue
            if status_filter == "problems" and status == "OK":
                continue
            if search and search not in " ".join(
                (str(row["component"]), str(row["status"]), str(row["details"]))
            ).casefold():
                continue
            result.append(row)
        return result

    def _render_system_rows(self, rows: list[dict[str, Any]]) -> None:
        children = self.system_tree.get_children()
        if children:
            self.system_tree.delete(*children)
        self.system_tree_rows.clear()
        self.visible_system_rows = list(rows)
        for index, row in enumerate(rows):
            iid = self.system_tree.insert(
                "", "end", iid=f"system:{index}",
                values=(row["component"], row["status"], row["details"]),
            )
            self.system_tree_rows[iid] = row

    def _apply_system_filters(self) -> None:
        all_rows = [
            {"component": component, "status": status, "details": details}
            for component, status, details in self._system_rows()
        ]
        rows = self._filter_system_rows(all_rows)
        self._render_system_rows(rows)
        self.system_filter_result_label.configure(
            text=self._t("system.result.count", shown=len(rows), total=len(all_rows))
        )

    def _clear_system_filters(self) -> None:
        self.system_search_var.set("")
        self.system_status_filter_var.set(self._t("system.filter.all"))
        self._apply_system_filters()

    @staticmethod
    def _queue_type_code(row: dict[str, Any]) -> str:
        traffic_class = str(row.get("traffic_class", "user"))
        return traffic_class if traffic_class in {"gateway", "sync"} else "user"

    def _queue_type(self, row: dict[str, Any]) -> str:
        key = {
            "gateway": "operations.queue.type.gateway",
            "sync": "operations.queue.type.control",
            "user": "operations.queue.type.message",
        }[self._queue_type_code(row)]
        return self._t(key)

    def _queue_route(self, row: dict[str, Any]) -> str:
        command = str(row.get("control_command", ""))
        route = str(row.get("control_route", ""))
        return "/".join(part for part in (route, command) if part) or self._t("operations.queue.route.user")

    def _queue_priority_text(self, row: dict[str, Any]) -> str:
        try:
            priority = int(row.get("priority", 100))
        except (TypeError, ValueError):
            priority = 100
        if priority >= 200:
            return self._t("operations.queue.priority.high", priority=priority)
        if priority < 100:
            return self._t("operations.queue.priority.low", priority=priority)
        return self._t("operations.queue.priority.normal", priority=priority)

    @staticmethod
    def _queue_disruption_category(
        row: dict[str, Any],
        ws_status: dict[str, Any],
        mesh_status: dict[str, dict[str, Any]],
    ) -> str:
        """Classify the most useful operator-facing reason for a queued row."""
        state = str(row.get("state", "")).casefold()
        error = str(row.get("last_error", "")).casefold()
        if state in {"paused", "expired_hold"}:
            return "user_action"

        if row.get("_queue_source") == "gateway":
            key = str(row.get("_queue_key", ""))
            status = mesh_status.get(key, {})
            if status and not bool(status.get("online")):
                return "local_radio"
        elif ws_status and not bool(ws_status.get("radio_online")):
            return "local_radio"

        reachability_tokens = (
            "no response", "no_response", "ingen svar", "ingen kvittering",
            "timeout", "tidsavbrudd", "no route", "no_route", "ingen rute",
            "max retransmit", "max_retransmit", "ikke bekreftet",
            "mottakernode", "dekning",
        )
        if state in {"retry_wait", "waiting_ack"} or any(
            token in error for token in reachability_tokens
        ):
            return "reachability"
        return "normal"

    @classmethod
    def _queue_health_snapshot(
        cls,
        rows: list[dict[str, Any]],
        ws_status: dict[str, Any],
        mesh_status: dict[str, dict[str, Any]],
        *,
        now_epoch: float | None = None,
        expiring_window_seconds: float = 3600.0,
    ) -> dict[str, Any]:
        now = time.time() if now_epoch is None else float(now_epoch)
        active_rows = [
            row for row in rows
            if str(row.get("state", "")).casefold() not in {"paused", "expired_hold"}
        ]
        oldest_uid = ""
        oldest_age = 0.0
        for row in active_rows:
            try:
                created = datetime.fromisoformat(str(row.get("created_at", ""))).timestamp()
            except Exception:
                continue
            age = max(0.0, now - created)
            if not oldest_uid or age > oldest_age:
                oldest_uid = str(row.get("message_uid", ""))
                oldest_age = age

        expiring_soon = 0
        for row in active_rows:
            try:
                expires = float(row.get("expires_epoch"))
            except (TypeError, ValueError):
                continue
            if now < expires <= now + max(60.0, float(expiring_window_seconds)):
                expiring_soon += 1

        categories = {"local_radio": 0, "reachability": 0, "user_action": 0, "normal": 0}
        for row in rows:
            category = cls._queue_disruption_category(row, ws_status, mesh_status)
            categories[category] = categories.get(category, 0) + 1

        return {
            "active": len(active_rows),
            "oldest_uid": oldest_uid,
            "oldest_age_seconds": oldest_age if oldest_uid else None,
            "expiring_soon": expiring_soon,
            "held": sum(1 for row in rows if str(row.get("state", "")).casefold() == "expired_hold"),
            "paused": sum(1 for row in rows if str(row.get("state", "")).casefold() == "paused"),
            **categories,
        }

    @classmethod
    def _queue_health_text(
        cls,
        rows: list[dict[str, Any]],
        ws_status: dict[str, Any],
        mesh_status: dict[str, dict[str, Any]],
        *,
        now_epoch: float | None = None,
        language: str = "nb",
    ) -> str:
        snapshot = cls._queue_health_snapshot(
            rows, ws_status, mesh_status, now_epoch=now_epoch
        )
        if snapshot["active"]:
            age_text = cls._duration_text(float(snapshot["oldest_age_seconds"] or 0.0), language=language)
            oldest = translate("operations.health.oldest", language, age=age_text)
            if snapshot["oldest_uid"]:
                oldest += f" ({snapshot['oldest_uid']})"
        else:
            oldest = translate("operations.health.none_active", language)
        causes: list[str] = []
        if snapshot["local_radio"]:
            causes.append(translate("operations.health.local_radio", language, count=snapshot["local_radio"]))
        if snapshot["reachability"]:
            causes.append(translate("operations.health.reachability", language, count=snapshot["reachability"]))
        if snapshot["user_action"]:
            causes.append(translate("operations.health.user_action", language, count=snapshot["user_action"]))
        cause_text = ", ".join(causes) if causes else translate("operations.health.no_cause", language)
        return translate(
            "operations.health.summary",
            language,
            oldest=oldest,
            expiring=snapshot["expiring_soon"],
            causes=cause_text,
        )

    @staticmethod
    def _queue_state_explanation(row: dict[str, Any], *, language: str = "nb") -> str:
        state = str(row.get("state", "")).casefold()
        error = str(row.get("last_error", "")).strip()
        if state == "paused":
            return translate("operations.explain.paused", language)
        if state == "expired_hold":
            return translate("operations.explain.expired", language)
        if state == "waiting_ack":
            return translate("operations.explain.waiting_ack", language)
        if state == "sending":
            return translate("operations.explain.sending", language)
        if state == "retry_wait":
            prefix = translate("operations.explain.retry_prefix", language, error=error) if error else ""
            return prefix + translate("operations.explain.retry", language)
        if state in {"queued", "pending"}:
            if str(row.get("traffic_class", "user")) == "sync":
                return translate("operations.explain.sync", language)
            return translate("operations.explain.queued", language)
        if error:
            return translate("operations.explain.error", language, state=row.get("state", ""), error=error)
        return translate("operations.explain.unknown", language, state=row.get("state", "") or translate("operations.detail.cause.unknown", language))

    def _set_queue_detail_text(self, text: str) -> None:
        widget = self.queue_detail_text
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _show_selected_queue_details(self) -> None:
        row = self._selected_queue_row()
        if not row:
            self._set_queue_detail_text(self._t("operations.detail.select"))
            return
        uid = str(row.get("message_uid", ""))
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                history = self.mesh_clients[key].call(
                    {"command": "outbox_history", "request_id": uid, "limit": 50}
                ).get("history", [])
            else:
                history = self.ws_client.call(
                    {"command": "outbox_history", "message_uid": uid, "limit": 50}
                ).get("history", [])
        except Exception as exc:
            history = []
            history_error = str(exc)
        else:
            history_error = ""

        category = self._queue_disruption_category(
            row, self.ws_status, self.local_mesh_status
        )
        category_key = {
            "local_radio": "operations.detail.cause.local_radio",
            "reachability": "operations.detail.cause.reachability",
            "user_action": "operations.detail.cause.user_action",
            "normal": "operations.detail.cause.normal",
        }.get(category, "operations.detail.cause.unknown")
        category_text = self._t(category_key)
        language = str(self.__dict__.get("ui_language", "nb"))
        lines = [
            self._t("operations.detail.packet_id", uid=uid),
            self._t(
                "operations.detail.explanation",
                text=self._queue_state_explanation(row, language=language),
            ),
            self._t("operations.detail.cause", cause=category_text),
        ]
        last_attempt = row.get("last_attempt_epoch")
        if last_attempt not in (None, ""):
            try:
                stamp = datetime.fromtimestamp(float(last_attempt)).astimezone().isoformat(timespec="seconds")
                lines.append(self._t("operations.detail.last_attempt", stamp=stamp))
            except Exception:
                pass
        lines.append("")
        lines.append(self._t("operations.detail.history"))
        if history:
            for event in history:
                when = str(event.get("occurred_at", ""))
                event_type = str(event.get("event_type", ""))
                state = str(event.get("state", ""))
                attempts = int(event.get("attempts", 0) or 0)
                detail = str(event.get("detail", "")).strip()
                suffix = f" — {detail}" if detail else ""
                lines.append(
                    self._t(
                        "operations.detail.event",
                        when=when,
                        event_type=event_type,
                        state=state,
                        attempts=attempts,
                        suffix=suffix,
                    )
                )
        elif history_error:
            lines.append(self._t("operations.detail.history_error", error=history_error))
        else:
            lines.append(self._t("operations.detail.history_none"))
        self._set_queue_detail_text("\n".join(lines))

    def _filter_queue_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        start, end = self._parse_optional_range(
            self.queue_from_filter_var.get(), self.queue_to_filter_var.get()
        )
        search = self.queue_search_var.get().strip().casefold()
        type_filter = self._queue_type_filter_code()
        state_filter = self._queue_state_filter_code()
        result: list[dict[str, Any]] = []
        for row in rows:
            queue_type_code = self._queue_type_code(row)
            queue_type = self._queue_type(row)
            state = str(row.get("state", ""))
            folded_state = state.casefold()
            if type_filter != "all" and queue_type_code != type_filter:
                continue
            if state_filter == "waiting" and not any(token in folded_state for token in ("pending", "venter", "queued", "kø")):
                continue
            if state_filter == "retry" and not any(token in folded_state for token in ("retry", "prøver")):
                continue
            if state_filter == "paused" and "paused" not in folded_state and "paus" not in folded_state:
                continue
            if state_filter == "error" and not any(token in folded_state for token in ("fail", "error", "feil", "nak", "expired", "utløpt")):
                continue
            if state_filter == "other" and any(
                token in folded_state for token in ("pending", "venter", "queued", "kø", "retry", "prøver", "paused", "paus", "fail", "error", "feil", "nak", "expired", "utløpt")
            ):
                continue
            if search:
                haystack = " ".join(
                    (
                        str(row.get("message_uid", "")), queue_type, self._queue_route(row),
                        str(row.get("destination", "")), state, str(row.get("last_error", "")),
                    )
                ).casefold()
                if search not in haystack:
                    continue
            if not in_inclusive_range(row.get("created_at"), start, end):
                continue
            result.append(row)
        return result

    def _render_queue_rows(self, rows: list[dict[str, Any]]) -> None:
        children = self.queue_tree.get_children()
        if children:
            self.queue_tree.delete(*children)
        current = time.time()
        self.queue_item_refs.clear()
        self.visible_queue_rows = list(rows)
        for index, row in enumerate(rows):
            uid = str(row.get("message_uid", ""))
            tree_id = f"queue:{index}:{uid}"
            self.queue_item_refs[tree_id] = row
            attempts = int(row.get("attempts", 0) or 0)
            max_attempts = row.get("max_attempts")
            attempt_text = f"{attempts}/{int(max_attempts)}" if max_attempts not in (None, "") else str(attempts)
            try:
                created = datetime.fromisoformat(str(row.get("created_at", ""))).timestamp()
            except Exception:
                created = current
            next_epoch = float(row.get("next_attempt_epoch", current) or current)
            expires_epoch = float(row.get("expires_epoch", current) or current)
            last_attempt_raw = row.get("last_attempt_epoch")
            if last_attempt_raw in (None, ""):
                last_attempt_text = "–"
            else:
                try:
                    last_attempt_text = self._t(
                        "operations.queue.last_ago",
                        duration=self._duration_text(
                            current - float(last_attempt_raw), language=str(self.__dict__.get("ui_language", "nb"))
                        ),
                    )
                except Exception:
                    last_attempt_text = "–"
            self.queue_tree.insert(
                "", "end", iid=tree_id,
                values=(
                    uid, self._queue_type(row), self._queue_priority_text(row),
                    self._queue_route(row), row.get("destination", ""),
                    row.get("state", ""), attempt_text,
                    self._duration_text(current - created, language=str(self.__dict__.get("ui_language", "nb"))),
                    last_attempt_text,
                    self._duration_text(next_epoch - current, language=str(self.__dict__.get("ui_language", "nb"))),
                    self._duration_text(expires_epoch - current, language=str(self.__dict__.get("ui_language", "nb"))),
                    str(row.get("last_error", ""))[:240],
                ),
            )

    def _apply_queue_filters(self) -> None:
        try:
            rows = self._filter_queue_rows(list(self.queue_rows))
            self._render_queue_rows(rows)
            self.queue_filter_result_label.configure(
                text=self._t("operations.result.count", shown=len(rows), total=len(self.queue_rows))
            )
        except Exception as exc:
            messagebox.showerror(self._t("operations.filter_error_title"), str(exc), parent=self)

    def _clear_queue_filters(self) -> None:
        self.queue_search_var.set("")
        self.queue_type_filter_var.set(self._t("operations.filter.type_all"))
        self.queue_state_filter_var.set(self._t("operations.filter.state_all"))
        self.queue_from_filter_var.set("")
        self.queue_to_filter_var.set("")
        self._render_queue_rows(list(self.queue_rows))
        self.queue_filter_result_label.configure(
            text=self._t("operations.result.all", count=len(self.queue_rows))
        )

    def _choose_export_options(
        self,
        title: str,
        *,
        supports_time: bool,
        privacy_note: str = "",
    ) -> dict[str, Any] | None:
        result: dict[str, Any] = {}
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        scope_var = tk.StringVar(value="visible")
        format_var = tk.StringVar(value="csv")
        from_var = tk.StringVar()
        to_var = tk.StringVar()
        ttk.Label(frame, text=self._t("common.scope"), font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, sticky="w")
        scopes = [
            (self._t("export_options.scope.all"), "all"),
            (self._t("export_options.scope.visible"), "visible"),
            (self._t("export_options.scope.selected"), "selected"),
        ]
        if supports_time:
            scopes.append((self._t("export_options.scope.time"), "time"))
        for index, (label, value) in enumerate(scopes, start=1):
            ttk.Radiobutton(frame, text=label, value=value, variable=scope_var).grid(
                row=index, column=0, columnspan=2, sticky="w", pady=2
            )
        row = len(scopes) + 1
        if supports_time:
            ttk.Label(frame, text=self._t("common.from_inclusive")).grid(row=row, column=0, sticky="w", pady=(8, 2))
            ttk.Entry(frame, textvariable=from_var, width=24).grid(row=row, column=1, sticky="w", pady=(8, 2))
            ttk.Label(frame, text=self._t("common.to_inclusive")).grid(row=row + 1, column=0, sticky="w", pady=2)
            ttk.Entry(frame, textvariable=to_var, width=24).grid(row=row + 1, column=1, sticky="w", pady=2)
            ttk.Label(
                frame,
                text=self._t("export_options.time_hint"),
                wraplength=430,
            ).grid(row=row + 2, column=0, columnspan=2, sticky="w", pady=(2, 8))
            row += 3
        ttk.Label(frame, text=self._t("common.format"), font=("TkDefaultFont", 10, "bold")).grid(row=row, column=0, sticky="w", pady=(5, 2))
        ttk.Radiobutton(frame, text=self._t("export_options.format.csv"), value="csv", variable=format_var).grid(row=row + 1, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(frame, text=self._t("export_options.format.tsv"), value="tsv", variable=format_var).grid(row=row + 2, column=0, columnspan=2, sticky="w")
        row += 3
        if privacy_note:
            ttk.Label(frame, text=privacy_note, wraplength=430, foreground="#8b4513").grid(
                row=row, column=0, columnspan=2, sticky="w", pady=(8, 4)
            )
            row += 1

        def accept() -> None:
            try:
                start = end = None
                if scope_var.get() == "time":
                    start, end = self._parse_optional_range(
                        from_var.get(), to_var.get(), language=str(self.__dict__.get("ui_language", "nb"))
                    )
                    if start is None and end is None:
                        raise ValueError(self._t("export_options.range_required"))
                result.update(
                    {"scope": scope_var.get(), "format": format_var.get(), "start": start, "end": end}
                )
                dialog.destroy()
            except Exception as exc:
                messagebox.showerror(self._t("export.error_title"), str(exc), parent=dialog)

        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text=self._t("action.cancel"), command=dialog.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text=self._t("action.continue"), command=accept).pack(side="right")
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.bind("<Return>", lambda _event: accept())
        self.wait_window(dialog)
        return result or None

    def _write_export(
        self,
        title: str,
        stem: str,
        headers: list[str],
        rows: list[list[Any]],
        options: dict[str, Any],
    ) -> None:
        if not rows:
            messagebox.showinfo(self._t("export.error_title"), self._t("export.no_rows"), parent=self)
            return
        extension = ".csv" if options["format"] == "csv" else ".tsv"
        delimiter = "," if options["format"] == "csv" else "\t"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = filedialog.asksaveasfilename(
            parent=self,
            title=title,
            defaultextension=extension,
            initialfile=f"gutochat-{stem}-{self._station_file_stem()}-{stamp}{extension}",
            filetypes=[
                (self._t("export.filetype.csv"), "*.csv"),
                (self._t("export.filetype.tsv"), "*.tsv"),
                (self._t("common.all_files"), "*"),
            ],
        )
        if not filename:
            return
        count = write_delimited(Path(filename), headers, rows, delimiter=delimiter)
        messagebox.showinfo(
            self._t("export.done_title"),
            self._t("export.done_body", count=count, filename=filename),
            parent=self,
        )

    @staticmethod
    def _selected_mapped_rows(tree: ttk.Treeview, mapping: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        return [mapping[iid] for iid in tree.selection() if iid in mapping]

    def export_messages(self) -> None:
        options = self._choose_export_options(
            self._t("messages.export.options_title"),
            supports_time=True,
            privacy_note=self._t("messages.export.privacy_note"),
        )
        if not options:
            return
        try:
            scope = options["scope"]
            if scope == "visible":
                chosen = list(self.visible_message_rows)
            elif scope == "selected":
                if self.message_view_var.get() == "Samtalevisning":
                    key = self.selected_conversation_key
                    chosen = list(self.conversation_messages.get(key, [])) if key else []
                else:
                    chosen = self._selected_mapped_rows(
                        self.message_tree, self.message_tree_rows
                    )
            else:
                all_rows = self._get_all_message_rows(refresh=True)
                if scope == "time":
                    chosen = [
                        row for row in all_rows
                        if in_inclusive_range(row.get("timestamp"), options["start"], options["end"])
                    ]
                else:
                    chosen = all_rows
            rows: list[list[Any]] = []
            for row in chosen:
                broadcast = row.get("broadcast") or row.get("destination") in (65535, BROADCAST_MESH, "^all")
                rows.append(
                    [
                        iso_timestamp(row.get("timestamp")),
                        self._network_label(self._network_key_from_row(row)),
                        self._t(
                            "messages.details.direction_received"
                            if row.get("direction") == "received"
                            else "messages.details.direction_sent"
                        ),
                        self._label_from_row(row, "source"),
                        row.get("source", ""),
                        self._label_from_row(row, "destination"),
                        row.get("destination", ""),
                        self._t(
                            "messages.export.type.broadcast"
                            if broadcast
                            else "messages.export.type.direct"
                        ),
                        str(row.get("status", "")),
                        str(row.get("text", "")),
                    ]
                )
            self._write_export(
                self._t("messages.export.save_title"),
                "meldinger",
                [
                    self._t("messages.export.header.time"),
                    self._t("messages.export.header.network"),
                    self._t("messages.export.header.direction"),
                    self._t("messages.export.header.from"),
                    self._t("messages.export.header.from_id"),
                    self._t("messages.export.header.to"),
                    self._t("messages.export.header.to_id"),
                    self._t("messages.export.header.type"),
                    self._t("messages.export.header.status"),
                    self._t("messages.export.header.text"),
                ],
                rows, options,
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("messages.export.error_title"), str(exc), parent=self
            )

    def export_nodes(self) -> None:
        options = self._choose_export_options(
            self._t("nodes.export.options_title"), supports_time=True
        )
        if not options:
            return
        try:
            scope = options["scope"]
            if scope == "visible":
                chosen = list(self.visible_node_rows)
            elif scope == "selected":
                chosen = self._selected_mapped_rows(self.node_tree, self.node_tree_rows)
            else:
                all_rows = self._all_node_rows()
                chosen = (
                    [row for row in all_rows if in_inclusive_range(row.get("last_value"), options["start"], options["end"])]
                    if scope == "time" else all_rows
                )
            rows = [
                [
                    row["type"], row["network"], row["node_id"], row["num"],
                    row["long_name"], row["short_name"], row["role"], row["alias"],
                    self._t("common.yes") if row["favorite"] else self._t("common.no"),
                    iso_timestamp(row["last_value"]),
                    row["snr"], row["source"],
                    self._t("common.yes") if row["manual"] else self._t("common.no"),
                ]
                for row in chosen
            ]
            self._write_export(
                self._t("nodes.export.save_title"),
                "noder-kontakter",
                [
                    self._t("nodes.export.header.type"),
                    self._t("nodes.export.header.network"),
                    self._t("nodes.export.header.id"),
                    self._t("nodes.export.header.numeric_id"),
                    self._t("nodes.export.header.long_name"),
                    self._t("nodes.export.header.short_name"),
                    self._t("nodes.export.header.role"),
                    self._t("nodes.export.header.alias"),
                    self._t("nodes.export.header.favorite"),
                    self._t("nodes.export.header.last"),
                    self._t("nodes.export.header.snr"),
                    self._t("nodes.export.header.source"),
                    self._t("nodes.export.header.manual"),
                ],
                rows, options,
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("nodes.export.error_title"), str(exc), parent=self
            )

    def export_system_status(self) -> None:
        options = self._choose_export_options(
            self._t("system.export.options_title"), supports_time=False
        )
        if not options:
            return
        scope = options["scope"]
        all_rows = [
            {"component": component, "status": status, "details": details}
            for component, status, details in self._system_rows()
        ]
        if scope == "visible":
            chosen = list(self.visible_system_rows)
        elif scope == "selected":
            chosen = self._selected_mapped_rows(self.system_tree, self.system_tree_rows)
        else:
            chosen = all_rows
        exported_at = datetime.now().astimezone().isoformat(timespec="seconds")
        rows = [[exported_at, row["component"], row["status"], APP_VERSION, row["details"]] for row in chosen]
        self._write_export(
            self._t("system.export.save_title"),
            "systemstatus",
            [
                self._t("system.export.header.time"),
                self._t("system.export.header.component"),
                self._t("system.export.header.status"),
                self._t("system.export.header.version"),
                self._t("system.export.header.details"),
            ],
            rows, options,
        )

    def export_operations(self) -> None:
        options = self._choose_export_options(
            self._t("operations.export.options_title"),
            supports_time=True,
            privacy_note=self._t("operations.export.privacy_note"),
        )
        if not options:
            return
        try:
            scope = options["scope"]
            if scope == "visible":
                chosen = list(self.visible_queue_rows)
            elif scope == "selected":
                chosen = self._selected_mapped_rows(self.queue_tree, self.queue_item_refs)
            elif scope == "time":
                chosen = [
                    row for row in self.queue_rows
                    if in_inclusive_range(row.get("created_at"), options["start"], options["end"])
                ]
            else:
                chosen = list(self.queue_rows)
            exported_at = datetime.now().astimezone().isoformat(timespec="seconds")
            rows: list[list[Any]] = []
            for row in chosen:
                max_attempts = row.get("max_attempts")
                attempts = int(row.get("attempts", 0) or 0)
                attempt_text = f"{attempts}/{int(max_attempts)}" if max_attempts not in (None, "") else attempts
                rows.append(
                    [
                        exported_at, self._queue_type(row), row.get("message_uid", ""),
                        self._queue_route(row), row.get("destination", ""), row.get("state", ""),
                        attempt_text, iso_timestamp(row.get("created_at")),
                        iso_timestamp(row.get("next_attempt_epoch")), iso_timestamp(row.get("expires_epoch")),
                        str(row.get("last_error", "")),
                    ]
                )
            self._write_export(
                self._t("operations.export.save_title"),
                "drift-ko",
                [
                    self._t("operations.export.header.time"),
                    self._t("operations.export.header.type"),
                    self._t("operations.export.header.uid"),
                    self._t("operations.export.header.route"),
                    self._t("operations.export.header.recipient"),
                    self._t("operations.export.header.state"),
                    self._t("operations.export.header.attempts"),
                    self._t("operations.export.header.created"),
                    self._t("operations.export.header.next"),
                    self._t("operations.export.header.expires"),
                    self._t("operations.export.header.error"),
                ],
                rows, options,
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("operations.export.error_title"), str(exc), parent=self
            )


    @staticmethod
    def _status_with_icon(status: str, direction: str = "") -> str:
        """Return an accessible symbol plus the existing status text."""
        text = " ".join(str(status or "").split())
        folded = text.casefold()
        if not text:
            return ""
        if "bekreftet av mottakernode" in folded:
            icon = "✓✓"
        elif "utløpt" in folded or "avbrutt" in folded or "ikke levert" in folded:
            icon = "✕"
        elif any(token in folded for token in ("feil", "nak", "ingen svar", "nytt forsøk")):
            icon = "⚠"
        elif "venter på mottakernode" in folded:
            icon = "⧗"
        elif any(token in folded for token in ("lagt i utboks", "venter på radio", "base-kø venter")):
            icon = "○"
        elif any(token in folded for token in ("lagret i base-kø", "overlevert", "videresendt")):
            icon = "⇢"
        elif "bekreftet" in folded or "ack" in folded:
            icon = "✓"
        elif "sendt" in folded:
            icon = "→"
        elif direction == "received" or "mottatt" in folded:
            icon = "←"
        else:
            icon = "•"
        return f"{icon} {text}"

    def _favorite_only_changed(self) -> None:
        self.ui_state["favorite_recipients_only"] = bool(
            self.favorite_only_var.get()
        )
        self._save_ui_state()
        self._refresh_recipient_combo()

    def _node_contact_identity(self, network_key: str, node: dict[str, Any]) -> str:
        if network_key == "waveshare":
            try:
                return str(int(node.get("num", node.get("id", 0))))
            except (TypeError, ValueError):
                return str(node.get("id", node.get("num", "")))
        raw = str(node.get("id") or "")
        try:
            return canonical_meshtastic_id(raw, node_num=node.get("num"))
        except (TypeError, ValueError):
            return raw

    def _node_is_favorite(self, network_key: str, node: dict[str, Any]) -> bool:
        identity = self._node_contact_identity(network_key, node)
        return self.contacts.favorite(network_key, identity) or self.contacts.favorite(
            network_key, str(node.get("id", ""))
        )

    def _message_table_selection_changed(self, _event: Any = None) -> None:
        selection = self.message_tree.selection()
        if not selection:
            return
        iid = self.message_tree.focus()
        if iid not in selection:
            iid = selection[-1]
        row = self.message_tree_rows.get(iid)
        if row is not None:
            self.selected_message_identity = self._message_row_identity(row)

    def _selected_message_row(self) -> dict[str, Any] | None:
        if self.message_view_var.get() == "Samtalevisning":
            rows = self.conversation_messages.get(self.selected_conversation_key, [])
            if self.selected_message_identity is not None:
                for row in rows:
                    if self._message_row_identity(row) == self.selected_message_identity:
                        return row
            return rows[-1] if rows else None
        selection = self.message_tree.selection()
        if not selection:
            return None
        iid = self.message_tree.focus()
        if iid not in selection:
            iid = selection[-1]
        return self.message_tree_rows.get(iid)

    def _message_action_menu_unmapped(self, _event: Any = None) -> None:
        self._message_action_menu_visible = False

    def _dismiss_message_action_menu(self) -> None:
        """Unpost the message action menu without affecting normal clicks."""
        try:
            self.message_action_menu.unpost()
        except (AttributeError, tk.TclError):
            pass
        try:
            self.message_action_menu.grab_release()
        except (AttributeError, tk.TclError):
            pass
        self._message_action_menu_visible = False

    def _dismiss_message_action_menu_event(self, _event: Any = None) -> None:
        self._dismiss_message_action_menu()

    def _dismiss_message_action_menu_on_left_click(self, event: Any) -> None:
        if not self._message_action_menu_visible:
            return
        if event.widget is self.message_action_menu:
            return
        self._dismiss_message_action_menu()

    def _schedule_message_action_focus_check(self, _event: Any = None) -> None:
        if not self._message_action_menu_visible:
            return
        if self._message_action_focus_after_id is not None:
            try:
                self.after_cancel(self._message_action_focus_after_id)
            except tk.TclError:
                pass
        self._message_action_focus_after_id = self.after_idle(
            self._dismiss_message_action_menu_if_focus_lost
        )

    def _dismiss_message_action_menu_if_focus_lost(self) -> None:
        self._message_action_focus_after_id = None
        if not self._message_action_menu_visible:
            return
        try:
            focused = self.focus_displayof()
        except tk.TclError:
            focused = None
        if focused is None:
            self._dismiss_message_action_menu()

    def _popup_message_action_menu(self, event: Any) -> str:
        self._dismiss_message_action_menu()
        try:
            self._message_action_menu_visible = True
            self.message_action_menu.tk_popup(event.x_root, event.y_root)
        except tk.TclError:
            self._message_action_menu_visible = False
        finally:
            try:
                self.message_action_menu.grab_release()
            except tk.TclError:
                pass
        return "break"

    def _show_message_action_menu(self, event: Any) -> str:
        iid = self.message_tree.identify_row(event.y)
        if iid and iid in self.message_tree_rows:
            if iid not in self.message_tree.selection():
                self.message_tree.selection_set(iid)
            self.message_tree.focus(iid)
            self._message_table_selection_changed()
        return self._popup_message_action_menu(event)

    def _select_conversation_message(
        self,
        tag: str,
        _event: Any = None,
        *,
        open_reply: bool = False,
    ) -> str:
        row = self.conversation_tag_rows.get(tag)
        if row is None:
            return "break"
        self.selected_message_identity = self._message_row_identity(row)
        self.conversation_text.tag_remove("selected_message", "1.0", "end")
        ranges = self.conversation_text.tag_ranges(tag)
        if len(ranges) >= 2:
            self.conversation_text.tag_add("selected_message", ranges[0], ranges[-1])
            self.conversation_text.tag_raise("selected_message")
        if open_reply:
            self._reply_selected_message()
        return "break"

    def _show_conversation_message_menu(self, tag: str, event: Any) -> str:
        self._select_conversation_message(tag, event)
        return self._popup_message_action_menu(event)

    def _set_compose_target_for_row(self, row: dict[str, Any]) -> None:
        network_key = self._network_key_from_row(row)
        if network_key not in self.network_order:
            raise ValueError(self._t("messages.error.network_missing"))
        self.network_combo.current(self.network_order.index(network_key))
        network = self.networks[network_key]
        values = self._message_type_values(network)
        self.type_combo["values"] = values
        key = self._conversation_key_for_row(row)
        is_broadcast = key[1] == "broadcast"
        self.type_combo.current(1 if is_broadcast else 0)
        self._refresh_recipient_combo()
        if is_broadcast:
            return

        side = "source" if row.get("direction") == "received" else "destination"
        raw_destination = row.get(side, "")
        desired = self._conversation_identity(network_key, raw_destination)
        selected = -1
        for index, item in enumerate(self.current_recipient_items):
            item_destination = item.get("destination", "")
            if self._conversation_identity(network_key, item_destination) == desired:
                selected = index
                break
        if selected < 0:
            destination: str | int = desired
            if network_key == "waveshare":
                try:
                    destination = int(desired)
                except ValueError:
                    pass
            label = self._label_from_row(row, side) or desired
            self.current_recipient_items.append(
                {"label": label, "destination": destination, "transient": True}
            )
            self.recipient_combo["values"] = [
                item["label"] for item in self.current_recipient_items
            ]
            selected = len(self.current_recipient_items) - 1
        self.recipient_combo.current(selected)
        self._recipient_changed()

    def _reply_selected_message(self, _event: Any = None) -> str | None:
        row = self._selected_message_row()
        if row is None:
            messagebox.showinfo(self._t("messages.reply_title"), self._t("messages.reply_select"), parent=self)
            return "break"
        try:
            self._set_compose_target_for_row(row)
            self.notebook.select(self.messages_tab)
            self.message_text.focus_set()
        except Exception as exc:
            messagebox.showerror(self._t("messages.reply_title"), str(exc), parent=self)
        return "break"

    @staticmethod
    def _strip_node_label_prefixes(label: str) -> str:
        """Remove display-only favorite/stale markers from message text."""
        text = str(label or "").strip()
        while True:
            for prefix in ("★ ", "⚠ "):
                if text.startswith(prefix):
                    text = text[len(prefix):].lstrip()
                    break
            else:
                return text

    def _quote_selected_message(self) -> None:
        row = self._selected_message_row()
        if row is None:
            messagebox.showinfo(self._t("messages.quote_title"), self._t("messages.reply_select"), parent=self)
            return
        try:
            self._set_compose_target_for_row(row)
            source = self._strip_node_label_prefixes(
                self._label_from_row(row, "source")
            )
            timestamp = self._format_timestamp(str(row.get("timestamp", "")))
            body = str(row.get("text", ""))
            quoted = "\n".join(f"> {line}" for line in body.splitlines() or [""])
            block = f"> {source} • {timestamp}\n{quoted}\n\n"
            current = self.message_text.get("1.0", "end-1c")
            if current and not current.endswith("\n"):
                self.message_text.insert("end", "\n")
            self.message_text.insert("end", block)
            self.message_text.see("end")
            self._update_counter()
            self.notebook.select(self.messages_tab)
            self.message_text.focus_set()
        except Exception as exc:
            messagebox.showerror(self._t("messages.quote_title"), str(exc), parent=self)

    def _show_table_for_message_selection(self) -> None:
        if self.message_view_var.get() != "Tabellvisning":
            self.message_view_var.set("Tabellvisning")
            self._message_view_changed()

    def select_all_visible_messages(self) -> None:
        self._show_table_for_message_selection()
        children = self.message_tree.get_children()
        if children:
            self.message_tree.selection_set(children)
            self.message_tree.focus(children[-1])
            self._message_table_selection_changed()

    def clear_message_selection(self) -> None:
        selection = self.message_tree.selection()
        if selection:
            self.message_tree.selection_remove(selection)
        self.selected_message_identity = None
        if hasattr(self, "conversation_text"):
            self.conversation_text.tag_remove("selected_message", "1.0", "end")

    def invert_message_selection(self) -> None:
        self._show_table_for_message_selection()
        children = list(self.message_tree.get_children())
        selected = set(self.message_tree.selection())
        inverted = [iid for iid in children if iid not in selected]
        self.message_tree.selection_set(inverted)
        if inverted:
            self.message_tree.focus(inverted[-1])
            self._message_table_selection_changed()

    def select_current_conversation_messages(self) -> None:
        key = self.selected_conversation_key
        if key is None:
            messagebox.showinfo(
                self._t("messages.select_conversation_title"),
                self._t("messages.select_conversation_body"),
                parent=self,
            )
            return
        self._show_table_for_message_selection()
        chosen = [
            iid for iid, row in self.message_tree_rows.items()
            if self._conversation_key_for_row(row) == key
        ]
        self.message_tree.selection_set(chosen)
        if chosen:
            self.message_tree.focus(chosen[-1])
            self._message_table_selection_changed()

    def copy_marked_messages(self) -> None:
        if self.message_view_var.get() == "Tabellvisning":
            rows = self._selected_mapped_rows(self.message_tree, self.message_tree_rows)
        else:
            row = self._selected_message_row()
            rows = [row] if row is not None else []
        if not rows:
            messagebox.showinfo(self._t("messages.copy_title"), self._t("messages.copy_select"), parent=self)
            return
        rows = sorted(rows, key=self._message_order_key)
        lines = []
        for row in rows:
            direction = self._t(
                "messages.filter.direction_received"
                if row.get("direction") == "received"
                else "messages.filter.direction_sent"
            )
            lines.append(
                f"{self._format_timestamp(str(row.get('timestamp', '')))}\t"
                f"{direction}\t{self._label_from_row(row, 'source')} → "
                f"{self._label_from_row(row, 'destination')}\t{row.get('text', '')}"
            )
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.update_idletasks()
        self.message_filter_result_label.configure(
            text=self._t("messages.copy_done", count=len(rows))
        )

    def selected_network_key(self) -> str:
        if not self.network_order:
            return ""
        index = self.network_combo.current()
        if index < 0:
            return self.network_order[0]
        return self.network_order[index]

    def selected_network(self) -> dict[str, Any]:
        return self.networks.get(self.selected_network_key(), {"key": "", "kind": "none", "label": self._t("modular.not_configured")})

    def _selection_changed(self, event: Any = None) -> None:
        if not self.network_order:
            self.type_combo.configure(values=(), state="disabled")
            self.type_combo.set(self._t("modular.not_configured"))
            self.send_button.configure(state="disabled")
            self._refresh_recipient_combo()
            return
        self.send_button.configure(state="normal")
        network = self.selected_network()
        values = self._message_type_values(network)
        current = self.type_combo.get()
        self.type_combo["values"] = values
        if current not in values:
            self.type_combo.current(0)
        self._refresh_recipient_combo()

    def _recipient_changed(self, event: Any = None) -> None:
        index = self.recipient_combo.current()
        if 0 <= index < len(self.current_recipient_items):
            destination = str(
                self.current_recipient_items[index].get("destination", "")
            )
            if destination and destination != "broadcast":
                self.last_recipient_by_network[self.selected_network_key()] = destination
                self._save_ui_state()
        self._update_route_preview(event)

    @staticmethod
    def _clean_node_name(value: Any) -> str:
        return " ".join(str(value or "").split())

    @staticmethod
    def _temporary_node_name(node: dict[str, Any]) -> bool:
        long_name = " ".join(str(node.get("long_name") or "").split())
        short_name = " ".join(str(node.get("short_name") or "").split())
        if not long_name.lower().startswith("meshtastic "):
            return False
        suffix = long_name.split()[-1].casefold() if long_name.split() else ""
        return bool(suffix and short_name.casefold() == suffix)

    def _gateway_status_for(self, network_key: str) -> dict[str, Any]:
        network = self.networks.get(network_key, {})
        if network.get("kind") == "mesh_local":
            return self.local_mesh_status.get(network_key, {})
        if network.get("kind") == "mesh_gateway":
            return self.gateway_status.get(network_key, {})
        return {}

    def _gateway_node_id(self, network_key: str) -> str:
        raw = str(self._gateway_status_for(network_key).get("local_id") or "").strip()
        if not raw:
            return ""
        try:
            return canonical_meshtastic_id(raw)
        except (TypeError, ValueError):
            return raw.lower()

    def _is_gateway_node(self, network_key: str, node: dict[str, Any]) -> bool:
        gateway_id = self._gateway_node_id(network_key)
        if not gateway_id:
            return False
        raw_id = str(node.get("id") or "").strip()
        try:
            node_id = canonical_meshtastic_id(raw_id, node_num=node.get("num"))
        except (TypeError, ValueError):
            node_id = raw_id.lower()
        return node_id.lower() == gateway_id.lower()

    def _gateway_role(self, network_key: str, node: dict[str, Any]) -> str:
        if not self._is_gateway_node(network_key, node):
            return ""
        network = self.networks.get(network_key, {})
        return self._t("nodes.role.local_gateway") if network.get("kind") == "mesh_local" else self._t("nodes.role.gateway_via_base")

    def _gateway_recipient_prefix(
        self, network_key: str, node: dict[str, Any]
    ) -> str:
        role = self._gateway_role(network_key, node)
        if not role:
            return ""
        short_name = self._clean_node_name(node.get("short_name"))
        return f"{role} {short_name}".strip()

    def _matching_node(
        self, network_key: str, destination: str | int
    ) -> dict[str, Any] | None:
        destination_text = str(destination).strip().lower()
        decimal_text = (
            destination_text[1:]
            if destination_text.startswith("!")
            else destination_text
        )
        numeric: int | None = None
        if decimal_text.isdecimal():
            try:
                numeric = int(decimal_text)
            except ValueError:
                numeric = None
        for node in self.node_cache.get(network_key, []):
            node_id = str(node.get("id", "")).strip().lower()
            try:
                node_num = int(node.get("num", -1))
            except (TypeError, ValueError):
                node_num = -1
            if (
                node_id == destination_text
                or str(node_num) == destination_text
                or (numeric is not None and node_num == numeric)
            ):
                return node
        return None

    def _long_name_is_ambiguous(
        self, network_key: str, node: dict[str, Any]
    ) -> bool:
        long_name = self._clean_node_name(node.get("long_name"))
        if not long_name:
            return False
        node_id = str(node.get("id", "")).strip().lower()
        matches = 0
        for candidate in self.node_cache.get(network_key, []):
            candidate_id = str(candidate.get("id", "")).strip().lower()
            candidate_name = self._clean_node_name(
                candidate.get("long_name")
            )
            if (
                candidate_id != node_id
                and candidate_name
                and candidate_name.casefold() == long_name.casefold()
            ):
                matches += 1
        return matches > 0

    def _node_is_stale(
        self, network_key: str, node: dict[str, Any]
    ) -> bool:
        """Return freshness for discovered nodes, not fixed Waveshare peers.

        Base and Field private Waveshare endpoints are configured peers. Their
        reachability is shown by the live radio/service status, so an old or
        missing node timestamp must not add a misleading warning marker.
        """
        if network_key == "waveshare":
            return False
        return NodeCatalog.is_stale(node, self.node_stale_hours)

    def _node_display(
        self,
        network_key: str,
        node: dict[str, Any],
        *,
        include_gateway_role: bool = False,
    ) -> str:
        raw_node_id = str(node.get("id", node.get("num", "")))
        node_num = node.get("num")
        node_id = raw_node_id
        if network_key.startswith("mesh"):
            try:
                numeric = int(node_num) if node_num not in (None, "") else None
                node_id = canonical_meshtastic_id(raw_node_id, node_num=numeric)
            except (TypeError, ValueError):
                node_id = raw_node_id
        alias = self.contacts.alias(network_key, node_id)
        if not alias and node_id != raw_node_id:
            alias = self.contacts.alias(network_key, raw_node_id)
        favorite = self.contacts.favorite(network_key, node_id)
        if not favorite and node_id != raw_node_id:
            favorite = self.contacts.favorite(network_key, raw_node_id)
        long_name = self._clean_node_name(node.get("long_name"))
        short_name = self._clean_node_name(node.get("short_name"))
        if self._long_name_is_ambiguous(network_key, node):
            if short_name and short_name.casefold() != long_name.casefold():
                identity = f"{long_name} / {short_name} ({node_id})"
            else:
                identity = f"{long_name} ({node_id})"
        else:
            name = long_name or short_name or node_id
            identity = f"{name} ({node_id})"
        prefix = "★ " if favorite else ""
        if LoRaChatApp._node_is_stale(self, network_key, node):
            prefix += "⚠ "
        if LoRaChatApp._temporary_node_name(node):
            identity = f"{identity} [midlertidig navn]"
        if include_gateway_role:
            gateway_prefix = self._gateway_recipient_prefix(network_key, node)
            if gateway_prefix:
                identity = f"{gateway_prefix} – {identity}"
        if alias:
            return f"{prefix}{alias} — {identity}"
        return f"{prefix}{identity}"

    def _sorted_nodes(
        self, network_key: str, *, for_recipients: bool = False
    ) -> list[dict[str, Any]]:
        nodes = list(self.node_cache.get(network_key, []))
        remembered = self.last_recipient_by_network.get(network_key, "")

        def destination(node: dict[str, Any]) -> str:
            if network_key == "waveshare":
                return str(node.get("num", ""))
            raw = str(node.get("id") or "")
            try:
                return canonical_meshtastic_id(raw, node_num=node.get("num"))
            except (TypeError, ValueError):
                return raw

        return sorted(
            nodes,
            key=lambda node: (
                # A gateway radio is a service endpoint rather than the usual
                # chat recipient.  Keep it last on both 868 and 433 even when
                # it was the previously selected destination.
                self._is_gateway_node(network_key, node),
                not self._node_is_favorite(network_key, node),
                False
                if (
                    for_recipients
                    and destination(node) == remembered
                    and not self._is_gateway_node(network_key, node)
                )
                else True,
                self._node_display(network_key, node).lower(),
            ),
        )

    def _refresh_recipient_combo(self) -> None:
        if not self.network_order:
            self.current_recipient_items = []
            self.current_recipient_network_key = ""
            self.recipient_combo.configure(values=(), state="disabled")
            self.recipient_combo.set(self._t("modular.not_configured"))
            if hasattr(self, "route_label"):
                self._update_route_preview()
            return
        network_key = self.selected_network_key()
        message_type = self._message_type_code()
        old_destination = None
        old_index = self.recipient_combo.current()
        if (
            self.current_recipient_network_key == network_key
            and 0 <= old_index < len(self.current_recipient_items)
        ):
            old_destination = str(self.current_recipient_items[old_index].get("destination"))
        self.current_recipient_items = []
        if message_type == "broadcast":
            label = self._t("messages.recipient.all_waveshare") if network_key == "waveshare" else self._t("messages.recipient.all_channel0")
            self.current_recipient_items = [{"label": label, "destination": "broadcast"}]
        else:
            for node in self._sorted_nodes(network_key, for_recipients=True):
                if (
                    hasattr(self, "favorite_only_var")
                    and self.favorite_only_var.get()
                    and not self._node_is_favorite(network_key, node)
                ):
                    continue
                destination: str | int
                if network_key == "waveshare":
                    destination = int(node["num"])
                else:
                    destination = str(node.get("id") or f"!{int(node['num']):08x}")
                self.current_recipient_items.append(
                    {
                        "label": self._node_display(
                            network_key, node, include_gateway_role=True
                        ),
                        "destination": destination,
                        "node": node,
                    }
                )
        self.current_recipient_network_key = network_key
        self.recipient_combo["values"] = [item["label"] for item in self.current_recipient_items]
        if self.current_recipient_items:
            chosen = 0
            preferred = (
                old_destination
                or self.last_recipient_by_network.get(network_key)
            )
            if preferred is not None:
                for index, item in enumerate(self.current_recipient_items):
                    if str(item.get("destination")) == str(preferred):
                        chosen = index
                        break
            self.recipient_combo.current(chosen)
        else:
            if hasattr(self, "favorite_only_var") and self.favorite_only_var.get():
                self.recipient_combo.set(self._t("messages.recipient.no_favorites"))
            else:
                self.recipient_combo.set(self._t("messages.recipient.no_known"))
        if hasattr(self, "route_label"):
            self._update_route_preview()
        else:
            self._update_counter()

    def _selected_recipient_item(self) -> dict[str, Any] | None:
        index = self.recipient_combo.current() if hasattr(self, "recipient_combo") else -1
        if 0 <= index < len(self.current_recipient_items):
            return self.current_recipient_items[index]
        return None

    def _gateway_compose_destination(self) -> str | int | None:
        """Return the actual gateway destination shown in the compose controls.

        A direct Mobile message must never be estimated as a broadcast while
        the node list from Base is still unavailable.  Returning ``None``
        makes both the route preview and byte counter show an explicit waiting
        state until a real recipient has been selected.
        """
        if self._message_type_code() != "direct":
            return "^all"
        item = self._selected_recipient_item()
        if not item:
            return None
        destination = item.get("destination")
        if destination in (None, "", "broadcast"):
            return None
        return destination

    @staticmethod
    def _meshtastic_text_usage(text: str) -> tuple[int, int]:
        return len(text.encode("utf-8")), MESH_TEXT_LIMIT

    def _validate_meshtastic_text(self, text: str) -> int:
        used, limit = self._meshtastic_text_usage(text)
        if used > limit:
            raise ValueError(
                self._t("messages.mesh_too_long", used=used, limit=limit)
            )
        return used

    def _update_route_preview(self, event: Any = None) -> None:
        if not self.network_order:
            self.route_label.configure(text=self._t("modular.no_network"))
            self._update_counter()
            return
        network = self.selected_network()
        direct = self._message_type_code() == "direct"
        recipient = self.recipient_combo.get() or self._t("messages.route.selected_recipient")
        if network["kind"] == "waveshare":
            route = (
                self._t(
                    "messages.route.waveshare",
                    station=self._station_display_name(),
                    recipient=recipient if direct else self._t("messages.route.all_waveshare"),
                )
            )
        elif network["kind"] == "mesh_local":
            route = (
                self._t(
                    "messages.route.mesh_local",
                    station=self._station_display_name(),
                    network=network["label"],
                    recipient=recipient,
                )
            )
        else:
            destination = self._gateway_compose_destination()
            if direct and destination is None:
                recipient = self._t("messages.route.waiting_base")
            route = (
                self._t(
                    "messages.route.mesh_via_base",
                    station=self._station_display_name(),
                    network=network["label"],
                    recipient=recipient,
                )
            )
        self.route_label.configure(text=route)
        self._update_counter()

    def _update_counter(self, event: Any = None) -> None:
        if not self.network_order:
            self.counter_label.configure(text=self._t("modular.no_send"))
            return
        text = self.message_text.get("1.0", "end-1c") if hasattr(self, "message_text") else ""
        text_bytes = len(text.encode("utf-8"))
        try:
            network = self.selected_network()
            if network["kind"] == "waveshare":
                used = text_bytes
                limit = self.max_text_bytes
                detail = self._t("messages.counter.waveshare", used=used, limit=limit)
                remaining = limit - used
            elif network["kind"] == "mesh_local":
                used, limit = self._meshtastic_text_usage(text)
                detail = self._t("messages.counter.mesh_local", used=used, limit=limit)
                remaining = limit - used
            else:
                destination = self._gateway_compose_destination()
                used_text, limit = self._meshtastic_text_usage(text)
                remaining = limit - used_text
                if destination is None:
                    detail = self._t(
                        "messages.counter.waiting_base", used=used_text, limit=limit
                    )
                else:
                    frame = encode_send(
                        "0" * 12,
                        str(network["key"]),
                        destination,
                        int(network.get("channel_index", 0)),
                        text,
                    )
                    wire_frame = _control_auth_for(self).encode_outbound(frame)
                    frames = fragment_frame(
                        wire_frame,
                        max_bytes=self.max_text_bytes,
                        max_fragments=self.max_fragments,
                        transfer_id="0" * 8,
                    )
                    used = frame_bytes(frame)
                    radio_bytes = sum(frame_bytes(item) for item in frames)
                    detail = self._t(
                        "messages.counter.gateway",
                        used=used,
                        frames=len(frames),
                        max_fragments=self.max_fragments,
                        radio_bytes=radio_bytes,
                        mesh_used=used_text,
                        limit=limit,
                    )
            suffix = "" if remaining >= 0 else self._t("messages.counter.too_long", count=abs(remaining))
            self.counter_label.configure(text=detail + suffix)
        except Exception as exc:
            self.counter_label.configure(
                text=self._t("messages.counter.error", bytes=text_bytes, error=exc)
            )

    def _send_gateway_frame(self, network: dict[str, Any], frame: str) -> list[str]:
        destination = int(network["gateway_address"])
        wire_frame = _control_auth_for(self).encode_outbound(frame)
        frames = fragment_frame(
            wire_frame,
            max_bytes=self.max_text_bytes,
            max_fragments=self.max_fragments,
        )
        policy = control_transport_policy(frame, destination)
        message_uids: list[str] = []
        for part in frames:
            request = {
                "command": "send",
                "destination": destination,
                "text": part,
            }
            request.update(policy)
            response = self.ws_client.call(request)
            message_uid = str(response.get("message_uid") or "")
            if message_uid:
                message_uids.append(message_uid)
        return message_uids

    def _send_gateway_status_frame(self, network: dict[str, Any], frame: str) -> list[str]:
        """Authenticate read-only status traffic with the status-only credential."""
        auth = _status_auth_for(self)
        if not auth.enabled:
            raise RuntimeError("REMOTE_STATUS_AUTH_NOT_CONFIGURED")
        destination = int(network["gateway_address"])
        wire_frame = auth.wrap(frame)
        frames = fragment_frame(
            wire_frame, max_bytes=self.max_text_bytes, max_fragments=self.max_fragments
        )
        policy = control_transport_policy(frame, destination)
        result: list[str] = []
        for part in frames:
            request = {"command": "send", "destination": destination, "text": part}
            request.update(policy)
            response = self.ws_client.call(request)
            uid = str(response.get("message_uid") or "")
            if uid:
                result.append(uid)
        return result

    def _send_gateway_privileged_frame(self, network: dict[str, Any], frame: str) -> list[str]:
        """Always authenticate privileged Field→Base requests; never fall back unsigned."""
        auth = _control_auth_for(self)
        if not auth.enabled:
            raise RuntimeError("REMOTE_CONTROL_AUTH_NOT_CONFIGURED")
        destination = int(network["gateway_address"])
        wire_frame = auth.wrap(frame)
        frames = fragment_frame(
            wire_frame, max_bytes=self.max_text_bytes, max_fragments=self.max_fragments
        )
        policy = control_transport_policy(frame, destination)
        result: list[str] = []
        for part in frames:
            request = {"command": "send", "destination": destination, "text": part}
            request.update(policy)
            response = self.ws_client.call(request)
            uid = str(response.get("message_uid") or "")
            if uid:
                result.append(uid)
        return result

    def _remote_base_network(self) -> tuple[str, dict[str, Any]] | None:
        preferred = str(self.remote_base_control_route).strip()
        if not preferred:
            return None
        network = self.networks.get(preferred)
        if network is None or network.get("kind") != "mesh_gateway":
            return None
        return preferred, network

    def _remote_base_status_network(self) -> tuple[str, dict[str, Any]] | None:
        preferred = str(self.remote_base_status_route).strip()
        if not preferred:
            return None
        network = self.networks.get(preferred)
        if network is None or network.get("kind") != "mesh_gateway":
            return None
        return preferred, network

    def _selected_recipient(self) -> dict[str, Any]:
        index = self.recipient_combo.current()
        if index < 0 or index >= len(self.current_recipient_items):
            raise ValueError(self._t("messages.recipient_required"))
        return self.current_recipient_items[index]

    def send_selected(self) -> None:
        if not self.network_order:
            messagebox.showinfo(PRODUCT_NAME, self._t("modular.no_send"), parent=self)
            return
        text = self.message_text.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning(self._t("messages.empty_title"), self._t("messages.empty_body"))
            return
        try:
            network = self.selected_network()
            if network["kind"] == "waveshare":
                recipient = self._selected_recipient()
                is_broadcast = recipient["destination"] == "broadcast"
                destination = 65535 if is_broadcast else int(recipient["destination"])
                self.ws_client.call(
                    {"command": "send", "destination": destination, "text": text}
                )
            elif network["kind"] == "mesh_local":
                recipient = self._selected_recipient()
                is_broadcast = recipient["destination"] == "broadcast"
                destination = "^all" if is_broadcast else recipient["destination"]
                self._validate_meshtastic_text(text)
                self.mesh_clients[network["key"]].call(
                    {
                        "command": "queue",
                        "destination": destination,
                        "channel_index": int(network.get("channel_index", 0)),
                        "text": text,
                        "source_label": self.node_name,
                    }
                )
            else:
                destination = self._gateway_compose_destination()
                if destination is None:
                    raise ValueError(self._t("messages.error.waiting_base_recipient"))
                self._validate_meshtastic_text(text)
                request_id = uuid.uuid4().hex[:12]
                command = encode_send(
                    request_id,
                    str(network["key"]),
                    destination,
                    int(network.get("channel_index", 0)),
                    text,
                )
                message_uids = self._send_gateway_frame(network, command)
                for message_uid in message_uids:
                    self.message_store.tag_gateway_request(message_uid, request_id)
            self.message_text.delete("1.0", "end")
            self._update_counter()
            self.message_text.focus_set()
            self.request_refresh()
        except Exception as exc:
            messagebox.showerror(self._t("messages.send_error_title"), str(exc))

    @staticmethod
    def _format_timestamp(value: str) -> str:
        try:
            return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return value

    @staticmethod
    def _format_node_time(node: dict[str, Any]) -> str:
        last_heard = node.get("last_heard")
        if last_heard not in (None, ""):
            try:
                return datetime.fromtimestamp(float(last_heard)).astimezone().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except Exception:
                pass
        return LoRaChatApp._format_timestamp(str(node.get("last_updated", "")))

    def _node_state(self, node: dict[str, Any], network_key: str = "") -> str:
        if network_key == "waveshare":
            return self._t("nodes.state.fixed")
        if LoRaChatApp._temporary_node_name(node):
            return self._t("nodes.state.temporary")
        stale = LoRaChatApp._node_is_stale(self, network_key, node)
        if bool(node.get("manual")) and not node.get("last_heard"):
            return self._t("nodes.state.manual")
        return self._t("nodes.state.stale" if stale else "nodes.state.recent")

    def _gateway_is_stale(self, status: dict[str, Any]) -> bool:
        last_seen = str(status.get("last_seen") or "")
        if not last_seen:
            return True
        try:
            age = time.time() - datetime.fromisoformat(last_seen).timestamp()
            return age > self.gateway_status_stale_seconds
        except Exception:
            return True

    def _network_label(self, key_or_name: str) -> str:
        networks = self.__dict__.get("networks", {})
        if key_or_name in networks:
            return str(networks[key_or_name]["label"])
        if key_or_name == "waveshare":
            return "Waveshare"
        if key_or_name == "aprs":
            return self._t("map.network.aprs")
        return key_or_name

    def _resolve_node_name(self, network_key: str, destination: str | int) -> str:
        if destination in {"^all", "4294967295", BROADCAST_MESH, "broadcast"}:
            return "Broadcast / kanal 0"
        destination_text = str(destination).strip().lower()
        decimal_text = (
            destination_text[1:]
            if destination_text.startswith("!")
            else destination_text
        )
        numeric: int | None = None
        if decimal_text.isdecimal():
            try:
                numeric = int(decimal_text)
            except ValueError:
                numeric = None
        node = self._matching_node(network_key, destination)
        if node is not None:
            return self._node_display(network_key, node)
        if network_key.startswith("mesh"):
            try:
                return canonical_meshtastic_id(destination, node_num=numeric)
            except (TypeError, ValueError):
                pass
        return str(destination)

    def _logical_control_rows(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Collapse LC3 fragment rows into one validated logical control row."""
        assembler = FragmentAssembler(max_fragments=self.max_fragments)
        control_auth = _control_auth_for(self)
        status_auth = _status_auth_for(self)
        groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
        result: list[dict[str, Any]] = []
        for row in messages:
            text = str(row.get("text", ""))
            control = parse_control(text)
            if not control or control.get("command") != "FRAGMENT":
                representative = dict(row)
                try:
                    if status_auth.is_authenticated_frame(text):
                        decoded, verified = status_auth.decode_inbound(text, live=False)
                        representative["_status_auth_envelope"] = text
                        representative["_status_authenticated"] = verified is not None
                    else:
                        decoded, verified = control_auth.decode_inbound(
                            text,
                            live=False,
                        )
                        if verified is not None:
                            representative["_control_auth_envelope"] = text
                            representative["_control_authenticated"] = True
                    representative["text"] = decoded
                    if verified is not None:
                        representative["_auth_key_id"] = verified.key_id
                        representative["_auth_nonce"] = verified.nonce
                        representative["_auth_timestamp"] = verified.timestamp
                except ValueError:
                    if control_auth.is_authenticated_frame(text) or status_auth.is_authenticated_frame(text):
                        continue
                    result.append(representative)
                    continue
                result.append(representative)
                continue
            key = (
                str(row.get("direction", "")),
                str(row.get("source", "")),
                str(row.get("destination", "")),
                str(control.get("transfer_id", "")),
            )
            groups.setdefault(key, []).append(row)
            try:
                complete = assembler.add(control, source_key=":".join(key[:3]))
            except Exception:
                continue
            if complete is None:
                continue
            rows = groups.get(key, [])
            representative = dict(rows[0] if rows else row)
            try:
                if status_auth.is_authenticated_frame(complete):
                    decoded, verified = status_auth.decode_inbound(complete, live=False)
                    representative["_status_auth_envelope"] = complete
                    representative["_status_authenticated"] = verified is not None
                else:
                    decoded, verified = control_auth.decode_inbound(
                        complete,
                        live=False,
                    )
                    if verified is not None:
                        representative["_control_auth_envelope"] = complete
                        representative["_control_authenticated"] = True
            except ValueError:
                if control_auth.is_authenticated_frame(complete) or status_auth.is_authenticated_frame(complete):
                    continue
                decoded = complete
                verified = None
            representative["text"] = decoded
            if verified is not None:
                representative["_auth_key_id"] = verified.key_id
                representative["_auth_nonce"] = verified.nonce
                representative["_auth_timestamp"] = verified.timestamp
            representative["fragment_count"] = len(rows)
            representative["updated_at"] = max(
                (str(item.get("updated_at") or item.get("timestamp") or "") for item in rows),
                default=str(row.get("updated_at", "")),
            )
            statuses = [str(item.get("status", "")) for item in rows]
            if statuses and all(status == "Bekreftet" for status in statuses):
                representative["status"] = "Bekreftet"
            elif statuses:
                representative["status"] = statuses[-1]
            result.append(representative)
        return result

    def _mark_node_sync_control(
        self, route: str, control: dict[str, Any]
    ) -> None:
        active = self.node_sync_active.get(route)
        if not active:
            return
        request_id = str(control.get("request_id", ""))
        command = str(control.get("command", ""))
        if command == "INFO" and request_id == str(active.get("info_request", "")):
            active["info_done"] = True
            if active.get("identity_done"):
                self._complete_sync_operation("info", route, request_id)
        elif command == "GWIDENT" and request_id == str(active.get("info_request", "")):
            active["identity_done"] = True
            if active.get("info_done"):
                self._complete_sync_operation("info", route, request_id)
        elif command == "NDONE" and request_id == str(active.get("node_request", "")):
            active["node_done"] = True
            self._complete_sync_operation("nodes", route, request_id)
        if (
            active.get("info_done")
            and active.get("identity_done")
            and active.get("node_done")
        ):
            self.node_sync_active.pop(route, None)

    def _sync_operation_pending(self, kind: str, route: str) -> bool:
        current = self.sync_request_current
        if current and current.get("kind") == kind and current.get("route") == route:
            return True
        return (kind, route) in self.sync_request_queue

    def _queue_sync_operation(
        self, kind: str, route: str, *, front: bool = False
    ) -> None:
        if self._sync_operation_pending(kind, route):
            return
        item = (kind, route)
        if front:
            self.sync_request_queue.insert(0, item)
        else:
            self.sync_request_queue.append(item)

    def _start_next_sync_operation(self) -> None:
        if self.sync_request_current is not None:
            return
        while self.sync_request_queue:
            kind, route = self.sync_request_queue.pop(0)
            network = self.networks.get(route)
            if not network or network.get("kind") != "mesh_gateway":
                continue
            now = time.monotonic()
            try:
                if kind == "info":
                    request_id = uuid.uuid4().hex[:8]
                    active = self.node_sync_active.setdefault(
                        route,
                        {
                            "started": now,
                            "info_request": "",
                            "node_request": "",
                            "info_done": False,
                            "identity_done": False,
                            "node_done": False,
                        },
                    )
                    active.update(
                        {
                            "started": now,
                            "info_request": request_id,
                            "info_done": False,
                            "identity_done": False,
                        }
                    )
                    self.sync_request_current = {
                        "kind": kind,
                        "route": route,
                        "request_id": request_id,
                        "started": now,
                    }
                    self._send_gateway_frame(
                        network, encode_info_request(request_id, route)
                    )
                    return
                if kind == "nodes":
                    request_id = uuid.uuid4().hex[:8]
                    active = self.node_sync_active.setdefault(
                        route,
                        {
                            "started": now,
                            "info_request": "",
                            "node_request": "",
                            "info_done": False,
                            "identity_done": False,
                            "node_done": False,
                        },
                    )
                    active.update(
                        {
                            "started": now,
                            "node_request": request_id,
                            "node_done": False,
                        }
                    )
                    self.sync_request_current = {
                        "kind": kind,
                        "route": route,
                        "request_id": request_id,
                        "started": now,
                    }
                    self._send_gateway_frame(
                        network,
                        encode_node_request(
                            request_id,
                            route,
                            self.catalog.remote_revision(route),
                        ),
                    )
                    return
                if kind == "positions":
                    request_id = uuid.uuid4().hex[:12]
                    self.position_sync_active[route] = (request_id, now)
                    self.sync_request_current = {
                        "kind": kind,
                        "route": route,
                        "request_id": request_id,
                        "started": now,
                    }
                    self._send_gateway_frame(
                        network,
                        encode_position_request(
                            request_id,
                            route,
                            self.position_store.remote_revision(route),
                        ),
                    )
                    return
                if kind == "position_history":
                    request_id = uuid.uuid4().hex[:12]
                    history_cursor = self.position_store.history_sync_cursor(route)
                    self.position_history_sync_active[route] = {
                        "request_id": request_id,
                        "started": now,
                        "failed": False,
                        "start_sequence": history_cursor,
                        "last_sequence": history_cursor,
                        "received_count": 0,
                    }
                    self.sync_request_current = {
                        "kind": kind,
                        "route": route,
                        "request_id": request_id,
                        "started": now,
                    }
                    self._send_gateway_frame(
                        network,
                        encode_position_history_request(
                            request_id,
                            route,
                            history_cursor,
                            self.position_history_sync_batch_size,
                        ),
                    )
                    return
                if kind == "aprs":
                    if not self.aprs_field_sync_enabled or self.aprs_replica_store is None:
                        continue
                    request_id = uuid.uuid4().hex[:12]
                    cursor = self.aprs_replica_store.remote_cursor()
                    bootstrap = cursor == 0
                    state = self.aprs_bootstrap_state.setdefault(
                        route, {"baseline": 0, "after": 0, "observations": []}
                    ) if bootstrap else None
                    start_sequence = int(state.get("after", 0)) if state is not None else cursor
                    self.aprs_sync_active[route] = {
                        "request_id": request_id, "started": now,
                        "start_cursor": cursor, "start_sequence": start_sequence,
                        "last_sequence": start_sequence, "observations": [],
                        "done_control": None, "failed": False,
                        "bootstrap": bootstrap,
                    }
                    self.sync_request_current = {
                        "kind": kind, "route": route, "request_id": request_id, "started": now,
                    }
                    self._send_gateway_frame(
                        network,
                        encode_aprs_history_request(
                            request_id, route, cursor, self.aprs_sync_batch_size,
                            snapshot_baseline=int(state.get("baseline", 0)) if state else 0,
                            snapshot_after=int(state.get("after", 0)) if state else 0,
                        ),
                    )
                    return
                if kind == "messages":
                    request_id = uuid.uuid4().hex[:12]
                    cursor = self.message_store.message_sync_cursor(route)
                    self.message_sync_active[route] = (request_id, now)
                    pages = getattr(self, "message_sync_pages", None)
                    if not isinstance(pages, dict):
                        pages = {}
                        self.message_sync_pages = pages
                    pages[route] = {
                        "request_id": request_id,
                        "start_cursor": cursor,
                        "events": {},
                        "failed": False,
                    }
                    self.sync_request_current = {
                        "kind": kind,
                        "route": route,
                        "request_id": request_id,
                        "started": now,
                    }
                    self._send_gateway_frame(
                        network,
                        encode_message_request(
                            request_id,
                            route,
                            cursor,
                            self.message_sync_batch_size,
                        ),
                    )
                    return
            except Exception as exc:
                self.sync_request_current = None
                self.node_sync_active.pop(route, None)
                self.message_sync_active.pop(route, None)
                getattr(self, "message_sync_pages", {}).pop(route, None)
                self.position_sync_active.pop(route, None)
                self.position_history_sync_active.pop(route, None)
                self.aprs_sync_active.pop(route, None)
                status = self.gateway_status.setdefault(route, {})
                status["error"] = f"Synkronisering: {exc}"

    def _complete_sync_operation(
        self,
        kind: str,
        route: str,
        request_id: str,
        *,
        repeat: bool = False,
    ) -> None:
        current = self.sync_request_current
        if not current:
            return
        if (
            current.get("kind") != kind
            or current.get("route") != route
            or str(current.get("request_id", "")) != str(request_id)
        ):
            return
        self.sync_request_current = None
        if repeat:
            self._queue_sync_operation(kind, route, front=True)
        self._start_next_sync_operation()

    def _apply_gateway_identity(
        self, route: str, control: dict[str, Any], timestamp: str
    ) -> bool:
        node_id = str(control.get("id") or "").strip()
        if not node_id:
            return False
        existing = self._matching_node(route, node_id) or {}
        node = {
            "num": int(control.get("num") or existing.get("num") or destination_to_num(node_id)),
            "id": node_id,
            "short_name": str(control.get("short_name") or existing.get("short_name") or ""),
            "long_name": str(control.get("long_name") or existing.get("long_name") or ""),
            "last_heard": existing.get("last_heard"),
            "snr": existing.get("snr"),
            "last_updated": timestamp,
        }
        changed = self.catalog.upsert(
            route,
            node,
            source=f"gateway:{route}",
        )
        status = self.gateway_status.setdefault(route, {})
        status.update(
            {
                "local_id": node_id,
                "local_num": node["num"],
                "local_name": node["long_name"],
                "local_short_name": node["short_name"],
                "last_seen": timestamp,
                "cached": False,
            }
        )
        self.catalog.save_gateway_status(route, status)
        return changed

    def _finalize_aprs_sync_if_ready(self, route: str, request_id: str) -> bool:
        active = self.aprs_sync_active.get(route)
        if not active or str(active.get("request_id", "")) != str(request_id):
            return False
        done = active.get("done_control")
        if done is None:
            return False

        expected_count = int(done.get("count", 0))
        observations = list(active.get("observations", []))
        if len(observations) < expected_count:
            return False

        failed = bool(active.get("failed"))
        if len(observations) > expected_count:
            failed = True

        observations.sort(key=lambda item: int(item[0]))
        sequences = [int(item[0]) for item in observations]
        done_sequence = int(done.get("sequence", 0))
        bootstrap = bool(active.get("bootstrap"))
        snapshot_baseline = int(done.get("snapshot_baseline", 0))
        snapshot_after = int(done.get("snapshot_after", 0))
        start_sequence = int(active.get("start_sequence", active.get("start_cursor", 0)))

        if bool(done.get("resync_required")):
            failed = True
            status = self.gateway_status.setdefault(route, {})
            status["error"] = "APRS-sync krever eksplisitt resync; lokal replika ble ikke slettet"
        if len(sequences) != len(set(sequences)):
            failed = True
        if sequences and sequences[0] <= start_sequence:
            failed = True
        if expected_count > 0 and (not sequences or sequences[-1] > done_sequence):
            failed = True
        if expected_count == 0 and done_sequence < start_sequence:
            failed = True
        if bootstrap and snapshot_after != done_sequence:
            failed = True

        self.aprs_sync_active.pop(route, None)
        if failed or self.aprs_replica_store is None:
            self.aprs_sync_more.discard(route)
            self.aprs_bootstrap_state.pop(route, None)
            self._complete_sync_operation("aprs", route, request_id)
            return True

        try:
            if bootstrap:
                state = self.aprs_bootstrap_state.setdefault(
                    route, {"baseline": 0, "after": 0, "observations": []}
                )
                prior_baseline = int(state.get("baseline", 0))
                if snapshot_baseline <= 0 or (prior_baseline and prior_baseline != snapshot_baseline):
                    raise ValueError("APRS_BOOTSTRAP_BASELINE_MISMATCH")
                if sequences and sequences[0] <= int(state.get("after", 0)):
                    raise ValueError("APRS_BOOTSTRAP_PAGE_SEQUENCE_INVALID")
                state["baseline"] = snapshot_baseline
                state["after"] = snapshot_after
                state["observations"].extend(observations)
                if bool(done.get("more")):
                    self.aprs_sync_more.add(route)
                    self._complete_sync_operation("aprs", route, request_id, repeat=True)
                    return True
                all_observations = sorted(
                    list(state.get("observations", [])), key=lambda item: int(item[0])
                )
                self.aprs_replica_store.apply_snapshot(
                    observations=all_observations,
                    baseline_sequence=snapshot_baseline,
                )
                self.aprs_bootstrap_state.pop(route, None)
            else:
                self.aprs_replica_store.apply_batch(
                    start_cursor=int(active.get("start_cursor", 0)),
                    observations=observations,
                    final_cursor=done_sequence,
                )
        except Exception as exc:
            self.aprs_sync_more.discard(route)
            self.aprs_bootstrap_state.pop(route, None)
            status = self.gateway_status.setdefault(route, {})
            status["error"] = f"APRS-sync avvist: {exc}"
            self._complete_sync_operation("aprs", route, request_id)
            return True

        self.last_offline_map_signature = None
        if not bootstrap and bool(done.get("more")):
            self.aprs_sync_more.add(route)
            self._complete_sync_operation("aprs", route, request_id, repeat=True)
        else:
            self.aprs_sync_more.discard(route)
            self._complete_sync_operation("aprs", route, request_id)
        return True

    def _process_controls(self, messages: list[dict[str, Any]]) -> None:
        control_auth = _control_auth_for(self)
        status_auth = _status_auth_for(self)
        changed_routes: set[str] = set()
        local_gateway_requests: set[str] = set()
        for candidate in messages:
            if candidate.get("direction") != "sent":
                continue
            parsed_candidate = parse_control(str(candidate.get("text", "")))
            if parsed_candidate and parsed_candidate.get("command") == "SEND":
                local_gateway_requests.add(str(parsed_candidate.get("request_id", "")))
        for row in messages:
            if row.get("direction") != "received":
                continue
            text = str(row.get("text", ""))
            control_key = (
                row.get("id"),
                row.get("message_uid"),
                row.get("timestamp"),
                text,
            )
            if control_key in self.processed_control_keys:
                continue
            status_envelope = str(row.get("_status_auth_envelope") or "")
            control_envelope = str(row.get("_control_auth_envelope") or "")
            if status_envelope:
                try:
                    status_auth.decode_inbound(status_envelope, live=True)
                except ValueError:
                    self.processed_control_keys.add(control_key)
                    continue
            elif control_envelope:
                try:
                    control_auth.decode_inbound(control_envelope, live=True)
                except ValueError:
                    self.processed_control_keys.add(control_key)
                    continue
            elif control_auth.require_authenticated and text.startswith("~L3|"):
                self.processed_control_keys.add(control_key)
                continue
            control = parse_control(text)
            if not control:
                continue
            self.processed_control_keys.add(control_key)
            command = control.get("command")
            if status_envelope and command != "BASE_STATUS":
                continue
            route = str(control.get("route", ""))
            if route not in self.networks:
                continue
            if command == "NODE":
                node = {
                    "num": int(control["num"]),
                    "id": str(control["id"]),
                    "short_name": str(control.get("short_name", "")),
                    "long_name": str(control.get("long_name", "")),
                    "last_heard": control.get("last_heard"),
                    "snr": control.get("snr"),
                    "last_updated": row.get("timestamp", ""),
                }
                changed = self.catalog.upsert(
                    route,
                    node,
                    source=f"gateway:{route}",
                    external_revision=int(control.get("revision", 0)),
                )
                if changed:
                    changed_routes.add(route)
            elif command == "NDONE":
                self._mark_node_sync_control(route, control)
                revision = int(control.get("revision", 0))
                if revision:
                    self.catalog.set_remote_revision(route, revision)
                status = self.gateway_status.setdefault(route, {})
                status.update(
                    {
                        "online": True,
                        "node_count": int(control.get("total_count", control.get("count", 0))),
                        "last_seen": row.get("timestamp", ""),
                        "cached": False,
                        "node_revision": revision,
                    }
                )
                self.catalog.save_gateway_status(route, status)
            elif command == "INFO":
                self._mark_node_sync_control(route, control)
                status = self.gateway_status.setdefault(route, {})
                status.update(
                    {
                        "online": bool(control["online"]),
                        "node_count": int(control["node_count"]),
                        "version": str(control["version"]),
                        "network_name": str(control["network_name"]),
                        "last_seen": row.get("timestamp", ""),
                        "cached": False,
                        "error": "",
                    }
                )
                self.catalog.save_gateway_status(route, status)
            elif command == "GWIDENT":
                self._mark_node_sync_control(route, control)
                self._apply_gateway_identity(
                    route, control, str(row.get("timestamp", ""))
                )
                changed_routes.add(route)
            elif command == "GWQUEUED":
                self.gateway_queue_status[str(control["request_id"])] = control
            elif command == "GWACK":
                self.gateway_acks[str(control["request_id"])] = control
            elif command == "GWDEL":
                self.gateway_deliveries[str(control["request_id"])] = control
            elif command == "GWNAK":
                self.gateway_naks[str(control["request_id"])] = str(control["reason"])
            elif command == "GWERR":
                self.gateway_errors[str(control["request_id"])] = str(control["error"])
            elif command == "MESHIN" and control.get("protocol") == "LC3":
                try:
                    source_num = destination_to_num(str(control.get("source_id", "0")))
                except Exception:
                    source_num = 0
                try:
                    destination_num = destination_to_num(control.get("destination", "^all"))
                except Exception:
                    destination_num = BROADCAST_MESH
                self.message_store.upsert_synced_message(
                    route,
                    {
                        "message_uid": str(
                            control.get("message_uid")
                            or f"live-{route}-{row.get('message_uid', row.get('id', ''))}"
                        ),
                        "timestamp": str(row.get("timestamp", "")),
                        "updated_at": str(row.get("updated_at") or row.get("timestamp", "")),
                        "direction": "received",
                        "source": source_num,
                        "destination": destination_num,
                        "broadcast": 1 if destination_num == BROADCAST_MESH else 0,
                        "text": str(control.get("text", "")),
                        "status": "Mottatt via Base-stasjon",
                        "network": self._network_label(route),
                        "source_label": str(control.get("source_label", "")),
                        "destination_label": self._resolve_node_name(
                            route, control.get("destination", "^all")
                        ),
                        "channel": int(control.get("channel", 0)),
                    },
                )
            elif command == "POS":
                active = self.position_sync_active.get(route)
                if not active or str(active[0]) != str(control.get("request_id", "")):
                    continue
                payload = dict(control.get("payload") or {})
                node_id = payload.get("node_id")
                revision = int(control.get("revision", 0))
                if not node_id or revision <= 0:
                    continue
                position_payload = {
                    key: payload.get(key)
                    for key in (
                        "latitude_i", "longitude_i", "altitude",
                        "location_source", "altitude_source",
                        "precision_bits", "sats_in_view",
                        "fix_quality", "fix_type",
                    )
                    if key in payload
                }
                position_epoch = payload.get("position_epoch")
                time_source = str(payload.get("position_time_source") or "")
                if position_epoch not in (None, ""):
                    if time_source == "time":
                        position_payload["time"] = position_epoch
                    elif time_source == "timestamp":
                        position_payload["timestamp"] = position_epoch
                packet_rx_epoch = (
                    position_epoch if time_source == "rxTime"
                    else None
                )
                self.position_store.upsert_latest(
                    route,
                    node_id,
                    position_payload,
                    num=payload.get("num"),
                    packet_rx_epoch=packet_rx_epoch,
                    received_epoch=payload.get("received_epoch"),
                    received_at=payload.get("received_at"),
                    source=str(payload.get("source") or f"gateway:{route}"),
                    packet_id=payload.get("packet_id", ""),
                    channel=payload.get("channel"),
                    rx_rssi=payload.get("rx_rssi"),
                    rx_snr=payload.get("rx_snr"),
                    external_revision=revision,
                    record_history=False,
                )
            elif command == "PDONE":
                active = self.position_sync_active.get(route)
                request_id = str(control.get("request_id", ""))
                if not active or str(active[0]) != request_id:
                    continue
                revision = int(control.get("revision", 0))
                self.position_store.set_remote_revision(route, revision)
                self.position_sync_active.pop(route, None)
                self._complete_sync_operation(
                    "positions", route, request_id
                )
            elif command == "HSYNC":
                active = self.position_history_sync_active.get(route)
                request_id = str(control.get("request_id", ""))
                if not active or str(active.get("request_id", "")) != request_id:
                    continue
                now_activity = time.monotonic()
                active["started"] = now_activity
                current = getattr(self, "sync_request_current", None)
                if (
                    current
                    and current.get("kind") == "position_history"
                    and current.get("route") == route
                    and str(current.get("request_id", "")) == request_id
                ):
                    current["started"] = now_activity
                payload = dict(control.get("payload") or {})
                node_id = payload.get("node_id")
                sequence = int(control.get("sequence", 0))
                last_sequence = int(active.get("last_sequence", 0))
                if not node_id or sequence <= last_sequence:
                    active["failed"] = True
                    continue
                try:
                    result = self.position_store.store_history_snapshot(
                        route,
                        node_id,
                        payload,
                        num=payload.get("num"),
                        external_sequence=sequence,
                        sync_origin=f"gateway:{route}",
                    )
                except Exception:
                    active["failed"] = True
                    continue
                if result not in {"created", "duplicate"}:
                    active["failed"] = True
                else:
                    active["last_sequence"] = sequence
                    active["received_count"] = int(
                        active.get("received_count", 0)
                    ) + 1
            elif command == "HDONE":
                active = self.position_history_sync_active.get(route)
                request_id = str(control.get("request_id", ""))
                if not active or str(active.get("request_id", "")) != request_id:
                    continue
                done_sequence = int(control.get("sequence", 0))
                expected_count = int(control.get("count", 0))
                received_count = int(active.get("received_count", 0))
                last_sequence = int(active.get("last_sequence", 0))
                failed = bool(active.get("failed"))
                if expected_count < 0 or received_count != expected_count:
                    failed = True
                if expected_count > 0 and last_sequence != done_sequence:
                    failed = True
                self.position_history_sync_active.pop(route, None)
                if failed:
                    self.position_history_sync_more.discard(route)
                    status = self.gateway_status.setdefault(route, {})
                    status["error"] = (
                        "Posisjonshistorikk inneholdt et ugyldig punkt; "
                        "cursor ble ikke flyttet"
                    )
                    self._complete_sync_operation(
                        "position_history",
                        route,
                        request_id,
                    )
                    continue
                self.position_store.set_history_sync_cursor(
                    route,
                    done_sequence,
                )
                self.last_position_history_signature = None
                if bool(control.get("more")):
                    self.position_history_sync_more.add(route)
                    self._complete_sync_operation(
                        "position_history",
                        route,
                        request_id,
                        repeat=True,
                    )
                else:
                    self.position_history_sync_more.discard(route)
                    self._complete_sync_operation(
                        "position_history",
                        route,
                        request_id,
                    )
            elif command == "ASYNC":
                active = self.aprs_sync_active.get(route)
                request_id = str(control.get("request_id", ""))
                if not active or str(active.get("request_id", "")) != request_id:
                    continue
                sequence = int(control.get("sequence", 0))
                payload = dict(control.get("payload") or {})
                if sequence <= int(active.get("start_sequence", active.get("start_cursor", 0))):
                    active["failed"] = True
                else:
                    observations = active.setdefault("observations", [])
                    duplicate = next((item for item in observations if int(item[0]) == sequence), None)
                    if duplicate is None:
                        observations.append((sequence, payload))
                    elif dict(duplicate[1]) != payload:
                        active["failed"] = True
                    active["last_sequence"] = max(
                        int(active.get("last_sequence", 0)), sequence
                    )
                now_activity = time.monotonic()
                active["started"] = now_activity
                current = getattr(self, "sync_request_current", None)
                if (
                    current
                    and current.get("kind") == "aprs"
                    and current.get("route") == route
                    and str(current.get("request_id", "")) == request_id
                ):
                    current["started"] = now_activity
                self._finalize_aprs_sync_if_ready(route, request_id)
            elif command == "ADONE":
                active = self.aprs_sync_active.get(route)
                request_id = str(control.get("request_id", ""))
                if not active or str(active.get("request_id", "")) != request_id:
                    continue
                prior_done = active.get("done_control")
                if prior_done is not None and dict(prior_done) != dict(control):
                    active["failed"] = True
                else:
                    active["done_control"] = dict(control)
                now_activity = time.monotonic()
                active["started"] = now_activity
                current = getattr(self, "sync_request_current", None)
                if (
                    current
                    and current.get("kind") == "aprs"
                    and current.get("route") == route
                    and str(current.get("request_id", "")) == request_id
                ):
                    current["started"] = now_activity
                self._finalize_aprs_sync_if_ready(route, request_id)
            elif command == "BASE_STATUS":
                if not bool(row.get("_status_authenticated")):
                    continue
                resource = str(control.get("resource", ""))
                if resource not in self.remote_base_status:
                    continue
                self.remote_base_status[resource] = {
                    "state": str(control.get("state", "UNKNOWN_DEGRADED")),
                    "verified": bool(control.get("verified")),
                    "reason_code": str(control.get("reason_code", "")),
                    "updated_mono": time.monotonic(),
                    "request_id": str(control.get("request_id", "")),
                }
                self._remember_remote_base_verified_status(
                    resource, self.remote_base_status[resource]
                )
                self._handle_remote_base_status_sequence(control)
            elif command == "BASE_CONTROL_RESULT":
                if not bool(row.get("_control_authenticated")):
                    continue
                request_id = str(control.get("request_id", ""))
                pending = self.remote_base_pending.pop(request_id, None)
                resource = str(control.get("resource", ""))
                if resource in self.remote_base_status:
                    self.remote_base_status[resource] = {
                        "state": str(control.get("state", "UNKNOWN_DEGRADED")),
                        "verified": bool(control.get("verified")),
                        "reason_code": str(control.get("reason_code", "")),
                        "updated_mono": time.monotonic(),
                        "request_id": request_id,
                    }
                    self._remember_remote_base_verified_status(
                        resource, self.remote_base_status[resource]
                    )
                if pending is not None:
                    self.after(0, lambda c=dict(control): self._finish_remote_base_control(c))
            elif command == "MSYNC":
                request_id = str(control.get("request_id", ""))
                active = self.message_sync_active.get(route)
                page = getattr(self, "message_sync_pages", {}).get(route)
                if (
                    not active
                    or str(active[0]) != request_id
                    or not page
                    or str(page.get("request_id", "")) != request_id
                ):
                    continue
                sequence = int(control.get("sequence", 0))
                start_cursor = int(page.get("start_cursor", 0))
                event = {
                    "sequence": sequence,
                    "event_type": str(control.get("event_type", "")),
                    "payload": dict(control.get("payload") or {}),
                }
                if sequence <= start_cursor:
                    page["failed"] = True
                else:
                    events = page.setdefault("events", {})
                    prior = events.get(sequence)
                    if prior is None:
                        events[sequence] = event
                    elif dict(prior) != event:
                        page["failed"] = True
                now_activity = time.monotonic()
                self.message_sync_active[route] = (request_id, now_activity)
                current = self.sync_request_current
                if (
                    current
                    and current.get("kind") == "messages"
                    and current.get("route") == route
                    and str(current.get("request_id", "")) == request_id
                ):
                    current["started"] = now_activity
            elif command == "MDONE":
                request_id = str(control.get("request_id", ""))
                active = self.message_sync_active.get(route)
                page = getattr(self, "message_sync_pages", {}).get(route)
                if (
                    not active
                    or str(active[0]) != request_id
                    or not page
                    or str(page.get("request_id", "")) != request_id
                ):
                    continue
                start_cursor = int(page.get("start_cursor", 0))
                done_sequence = int(control.get("sequence", 0))
                expected_count = int(control.get("count", -1))
                event_map = dict(page.get("events") or {})
                events = [event_map[key] for key in sorted(event_map)]
                failed = bool(page.get("failed"))
                if expected_count < 0 or len(events) != expected_count:
                    failed = True
                if expected_count == 0:
                    if done_sequence != start_cursor:
                        failed = True
                else:
                    sequences = [int(event.get("sequence", 0)) for event in events]
                    if (
                        not sequences
                        or any(sequence <= start_cursor for sequence in sequences)
                        or len(set(sequences)) != len(sequences)
                        or max(sequences) != done_sequence
                    ):
                        failed = True

                self.message_sync_active.pop(route, None)
                getattr(self, "message_sync_pages", {}).pop(route, None)
                if failed:
                    self.message_sync_more.discard(route)
                    status = self.gateway_status.setdefault(route, {})
                    status["error"] = (
                        "Meldingssynkronisering ufullstendig; "
                        "meldinger og cursor ble ikke committed"
                    )
                    self._complete_sync_operation("messages", route, request_id)
                    continue
                try:
                    statuses = self.message_store.apply_message_sync_page(
                        route,
                        start_cursor=start_cursor,
                        events=events,
                        final_sequence=done_sequence,
                        expected_count=expected_count,
                        local_gateway_requests=local_gateway_requests,
                    )
                except Exception as exc:
                    self.message_sync_more.discard(route)
                    status = self.gateway_status.setdefault(route, {})
                    status["error"] = f"Meldingssynkronisering avvist: {exc}"
                    self._complete_sync_operation("messages", route, request_id)
                    continue
                self.synced_gateway_status.update(statuses)
                if bool(control.get("more")):
                    self.message_sync_more.add(route)
                    self._complete_sync_operation(
                        "messages", route, request_id, repeat=True
                    )
                else:
                    self.message_sync_more.discard(route)
                    self._complete_sync_operation("messages", route, request_id)
        if len(self.processed_control_keys) > 5000:
            visible_keys = {
                (row.get("id"), row.get("message_uid"), row.get("timestamp"), str(row.get("text", "")))
                for row in messages
                if row.get("direction") == "received"
            }
            self.processed_control_keys.intersection_update(visible_keys)
        for route in changed_routes:
            self._reload_catalog_network(route)
        if changed_routes:
            self._refresh_recipient_combo()

    def _virtual_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in messages:
            text = str(row.get("text", ""))
            control = parse_control(text)
            if control:
                command = control.get("command")
                if command == "SEND" and row.get("direction") == "sent":
                    req = str(control["request_id"])
                    direct = str(control.get("destination")) not in {"^all", "4294967295"}
                    if req in self.gateway_errors:
                        status = f"Gatewayfeil: {self.gateway_errors[req]}"
                    elif req in self.gateway_deliveries:
                        status = "Bekreftet av mottakernode"
                    elif req in self.gateway_naks:
                        status = f"Ikke bekreftet: {self.gateway_naks[req]}"
                    elif req in self.synced_gateway_status:
                        status = self.synced_gateway_status[req]
                    elif req in self.gateway_acks:
                        status = (
                            "Venter på mottakernode"
                            if direct
                            else "Overlevert til Meshtastic-radio"
                        )
                    elif req in self.gateway_queue_status:
                        queued = self.gateway_queue_status[req]
                        state = str(queued.get("state", "queued"))
                        detail = str(queued.get("detail", ""))
                        attempts = int(queued.get("attempts", 0))
                        labels = {
                            "queued": "Lagret i Base-kø",
                            "retry_wait": "Base-kø venter på nytt forsøk",
                            "sending": "Base sender meldingen",
                            "waiting_ack": "Venter på mottakernode",
                            "sent": "Overlevert til Meshtastic-radio",
                            "delivered": "Bekreftet av mottakernode",
                            "failed": "Ikke levert fra Base-kø",
                        }
                        status = labels.get(state, f"Base-kø: {state}")
                        if attempts:
                            status += f" (forsøk {attempts})"
                        if detail:
                            status += f": {detail}"
                    elif str(row.get("status", "")) not in {
                        "", "Lagt i utboks", "Venter på ACK", "Bekreftet",
                        "Prøver igjen (2/3)", "Prøver igjen (3/3)",
                    }:
                        # A synchronized Base status is persisted on the local
                        # carrier row in RC1, so the final state survives restart.
                        status = str(row.get("status"))
                    elif row.get("status") == "Bekreftet":
                        status = "Base-stasjonen mottok kommandoen"
                    else:
                        status = str(row.get("status", "Lagt i utboks"))
                    result.append(
                        {
                            **row,
                            "network": self._network_label(str(control["route"])),
                            "direction": "sent",
                            "source_label": self.node_name,
                            "destination_label": self._resolve_node_name(
                                str(control["route"]), control["destination"]
                            ),
                            "text": str(control["text"]),
                            "status": status,
                        }
                    )
                elif command == "MESHIN" and row.get("direction") == "received":
                    # LC3 inbound frames are materialized into the local
                    # message table by _process_controls and then kept current
                    # through incremental sync.  LC2 has no original message
                    # UID, so it remains a virtual compatibility row.
                    if control.get("protocol") == "LC3":
                        continue
                    was_truncated = bool(control.get("truncated", False))
                    shown_text = str(control["text"])
                    if was_truncated:
                        shown_text += "  [Meldingen ble avkortet på gatewayveien]"
                    result.append(
                        {
                            **row,
                            "network": self._network_label(str(control["route"])),
                            "direction": "received",
                            "source_label": str(control["source_label"]),
                            "destination_label": self._resolve_node_name(
                                str(control["route"]), control["destination"]
                            ),
                            "text": shown_text,
                            "status": (
                                "Mottatt via Base-stasjon – avkortet"
                                if was_truncated
                                else "Mottatt via Base-stasjon"
                            ),
                            "snr": None,
                        }
                    )
                continue
            if is_control(text):
                continue
            result.append(row)
        return result

    def _message_signature(self, messages: list[dict[str, Any]]) -> tuple[Any, ...]:
        return tuple(
            (
                item.get("id"),
                item.get("updated_at"),
                item.get("status"),
                item.get("text"),
                item.get("network"),
            )
            for item in messages
        )

    def _label_from_row(self, row: dict[str, Any], side: str) -> str:
        label = str(row.get(f"{side}_label") or "")
        value = row.get(side, "")
        network = str(row.get("network") or "Waveshare")
        if side == "destination":
            try:
                numeric = int(value)
            except (TypeError, ValueError):
                numeric = None
            if network.startswith("Meshtastic") and numeric == BROADCAST_MESH:
                return "Broadcast / kanal 0"
            if network == "Waveshare" and numeric == 65535:
                return "Broadcast"
        if network.startswith("Meshtastic"):
            route = str(row.get("sync_origin") or "")
            if route not in self.networks:
                route = next(
                    (
                        key for key, item in self.networks.items()
                        if str(item.get("label")) == network
                    ),
                    "",
                )
            label_is_numeric_id = bool(
                label and label.lstrip("!").isdecimal()
            )
            node = self._matching_node(route, value) if route else None
            if route and (not label or label_is_numeric_id):
                resolved = self._resolve_node_name(route, value)
                if resolved:
                    return resolved
            if route and node is not None and label:
                node_id = str(node.get("id", ""))
                try:
                    canonical_id = canonical_meshtastic_id(
                        node_id, node_num=int(node.get("num", value))
                    )
                except (TypeError, ValueError):
                    canonical_id = node_id
                alias = self.contacts.alias(route, canonical_id)
                if not alias and canonical_id != node_id:
                    alias = self.contacts.alias(route, node_id)
                if alias and label.casefold() == alias.casefold():
                    return label
                generated_labels = {
                    self._clean_node_name(node.get("long_name")).casefold(),
                    self._clean_node_name(node.get("short_name")).casefold(),
                    node_id.casefold(),
                    canonical_id.casefold(),
                    str(node.get("num", "")).casefold(),
                    ("!" + str(node.get("num", ""))).casefold(),
                }
                generated_labels.discard("")
                if label.casefold() in generated_labels:
                    return self._node_display(route, node)
            if label_is_numeric_id:
                try:
                    return canonical_meshtastic_id(label, node_num=int(value))
                except (TypeError, ValueError):
                    return canonical_meshtastic_id(label)
        if label:
            return label
        return str(value)

    def _network_key_from_row(self, row: dict[str, Any]) -> str:
        networks = self.__dict__.get("networks", {})
        route = str(row.get("sync_origin") or "")
        if route in networks:
            return route
        network_name = str(row.get("network") or "Waveshare")
        if network_name in {"Waveshare", "Privat Waveshare 868"}:
            return "waveshare"
        for key, network in networks.items():
            if str(network.get("label")) == network_name:
                return key
        return network_name

    def _conversation_identity(
        self,
        network_key: str,
        value: Any,
        *,
        node_num: Any = None,
    ) -> str:
        if network_key == "waveshare":
            try:
                return str(int(value))
            except (TypeError, ValueError):
                return str(value)
        try:
            numeric = int(node_num if node_num not in (None, "") else value)
        except (TypeError, ValueError):
            numeric = None
        try:
            return canonical_meshtastic_id(value, node_num=numeric).lower()
        except (TypeError, ValueError):
            return str(value).strip().lower()

    def _conversation_key_for_row(
        self, row: dict[str, Any]
    ) -> tuple[str, str, str]:
        network_key = self._network_key_from_row(row)
        try:
            destination = int(row.get("destination"))
        except (TypeError, ValueError):
            destination = None
        is_broadcast = bool(row.get("broadcast")) or (
            network_key == "waveshare" and destination == 65535
        ) or (
            network_key != "waveshare" and destination == BROADCAST_MESH
        )
        if is_broadcast:
            return (network_key, "broadcast", "broadcast")
        side = "source" if row.get("direction") == "received" else "destination"
        value = row.get(side, "")
        return (
            network_key,
            "direct",
            self._conversation_identity(network_key, value),
        )

    def _conversation_key_for_node(
        self,
        network_key: str,
        node_id: str,
        node_num: Any = None,
    ) -> tuple[str, str, str]:
        return (
            network_key,
            "direct",
            self._conversation_identity(network_key, node_id, node_num=node_num),
        )

    @staticmethod
    def _message_order_key(row: dict[str, Any]) -> tuple[str, int]:
        try:
            row_id = int(row.get("id") or 0)
        except (TypeError, ValueError):
            row_id = 0
        return (
            str(row.get("timestamp") or ""),
            row_id,
        )

    def _message_row_identity(self, row: dict[str, Any]) -> tuple[Any, ...]:
        durable_id = (
            row.get("message_uid")
            or row.get("gateway_request_id")
            or row.get("remote_message_id")
            or row.get("id")
        )
        return (
            self._network_key_from_row(row),
            durable_id,
            str(row.get("direction") or ""),
            str(row.get("timestamp") or ""),
        )

    def _conversation_display(
        self,
        key: tuple[str, str, str],
        rows: list[dict[str, Any]],
    ) -> tuple[str, str]:
        network_key, kind, _identity = key
        network_label = self._network_label(network_key)
        if kind == "broadcast":
            label = self._t(
                "messages.conversation.broadcast_waveshare"
                if network_key == "waveshare"
                else "messages.conversation.broadcast_mesh"
            )
            return label, network_label
        latest = max(rows, key=self._message_order_key)
        side = "source" if latest.get("direction") == "received" else "destination"
        label = self._label_from_row(latest, side)
        if self.contacts.favorite(network_key, key[2]):
            label = f"★ {label}"
        return label, network_label

    def _show_message_view(self) -> None:
        if not hasattr(self, "message_table_frame"):
            return
        self.message_table_frame.pack_forget()
        self.message_conversation_frame.pack_forget()
        if self.message_view_var.get() == "Samtalevisning":
            self.message_conversation_frame.pack(fill="both", expand=True)
            self.message_view_help_label.configure(
                text=self._t("messages.view.help_conversation")
            )
        else:
            self.message_table_frame.pack(fill="both", expand=True)
            self.message_view_help_label.configure(
                text=self._t("messages.view.help_table")
            )

    def _message_view_changed(self) -> None:
        self.ui_state["message_view"] = self.message_view_var.get()
        self._save_ui_state()
        self._show_message_view()
        if self.message_view_var.get() == "Samtalevisning":
            self._render_conversations(self.visible_message_rows)

    def _render_message_table(self, messages: list[dict[str, Any]]) -> None:
        selected_identities = {
            self._message_row_identity(self.message_tree_rows[iid])
            for iid in self.message_tree.selection()
            if iid in self.message_tree_rows
        }
        children = self.message_tree.get_children()
        if children:
            self.message_tree.delete(*children)
        self.message_tree_rows.clear()
        selected_iids: list[str] = []
        for index, row in enumerate(messages):
            direction = self._t(
                "messages.details.direction_received"
                if row.get("direction") == "received"
                else "messages.details.direction_sent"
            )
            signal = "—"
            if row.get("packet_rssi") is not None:
                signal = f"{row['packet_rssi']} dBm"
            elif row.get("ack_rssi") is not None:
                signal = f"{row['ack_rssi']} dBm ACK"
            if row.get("snr") is not None:
                signal += f" / {float(row['snr']):.1f} dB"
            iid = self.message_tree.insert(
                "", "end", iid=f"message:{index}",
                values=(
                    self._format_timestamp(str(row.get("timestamp", ""))),
                    self._network_label(self._network_key_from_row(row)),
                    direction,
                    self._label_from_row(row, "source"),
                    self._label_from_row(row, "destination"),
                    self._status_with_icon(
                        str(row.get("status", "")), str(row.get("direction", ""))
                    ),
                    signal,
                    str(row.get("text", "")),
                ),
            )
            self.message_tree_rows[iid] = row
            if self._message_row_identity(row) in selected_identities:
                selected_iids.append(iid)
        if selected_iids:
            self.message_tree.selection_set(selected_iids)
            self.message_tree.focus(selected_iids[-1])
        children = self.message_tree.get_children()
        if children:
            self.message_tree.see(children[-1])

    def _render_conversations(self, messages: list[dict[str, Any]]) -> None:
        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for row in messages:
            groups.setdefault(self._conversation_key_for_row(row), []).append(row)
        for rows in groups.values():
            rows.sort(key=self._message_order_key)
        self.conversation_messages = groups

        desired = self.pending_conversation_key or self.selected_conversation_key
        self.pending_conversation_key = None
        children = self.conversation_tree.get_children()
        if children:
            self.conversation_tree.delete(*children)
        self.conversation_tree_rows.clear()

        ordered = sorted(
            groups.items(),
            key=lambda item: self._message_order_key(item[1][-1]),
            reverse=True,
        )
        selected_iid = ""
        for index, (key, rows) in enumerate(ordered):
            label, network_label = self._conversation_display(key, rows)
            latest = rows[-1]
            iid = self.conversation_tree.insert(
                "",
                "end",
                iid=f"conversation:{index}",
                values=(
                    f"{network_label} – {label}",
                    len(rows),
                    self._format_timestamp(str(latest.get("timestamp", ""))),
                ),
            )
            self.conversation_tree_rows[iid] = key
            if key == desired:
                selected_iid = iid

        if not selected_iid and ordered:
            selected_iid = "conversation:0"
        if selected_iid:
            self.conversation_tree.selection_set(selected_iid)
            self.conversation_tree.focus(selected_iid)
            self.conversation_tree.see(selected_iid)
            self.selected_conversation_key = self.conversation_tree_rows[selected_iid]
            self._render_selected_conversation()
        else:
            self.selected_conversation_key = None
            self._render_conversation_transcript(None, [])

    def _conversation_selected(self, _event: Any = None) -> None:
        selection = self.conversation_tree.selection()
        if not selection:
            return
        key = self.conversation_tree_rows.get(selection[0])
        if key is None:
            return
        self.selected_conversation_key = key
        self._render_selected_conversation()

    def _render_selected_conversation(self) -> None:
        key = self.selected_conversation_key
        if key is None:
            self._render_conversation_transcript(None, [])
            return
        rows = self.conversation_messages.get(key, [])
        self._render_conversation_transcript(key, rows)

    def _render_conversation_transcript(
        self,
        key: tuple[str, str, str] | None,
        rows: list[dict[str, Any]],
    ) -> None:
        same_conversation = key is not None and key == self.rendered_conversation_key
        previous_view = self.conversation_text.yview() if same_conversation else (0.0, 1.0)
        was_at_bottom = not same_conversation or previous_view[1] >= 0.985
        self.conversation_text.configure(state="normal")
        self.conversation_text.delete("1.0", "end")
        self.conversation_tag_rows.clear()
        if key is None or not rows:
            self.conversation_header_label.configure(text=self._t("messages.no_conversation"))
            self.conversation_text.insert(
                "end",
                self._t("messages.no_filter_matches") + "\n",
                "empty",
            )
            self.conversation_text.configure(state="disabled")
            self.rendered_conversation_key = key
            return

        label, network_label = self._conversation_display(key, rows)
        self.conversation_header_label.configure(
            text=self._t(
                "messages.conversation.header",
                network=network_label,
                label=label,
                count=len(rows),
            )
        )
        for index, row in enumerate(rows):
            sent = row.get("direction") != "received"
            timestamp = self._format_timestamp(str(row.get("timestamp", "")))
            text = str(row.get("text", ""))
            status = self._status_with_icon(
                str(row.get("status", "")), str(row.get("direction", ""))
            )
            source = self._label_from_row(row, "source")
            destination = self._label_from_row(row, "destination")
            message_tag = f"conversation_message_{index}"
            self.conversation_tag_rows[message_tag] = row
            start_index = self.conversation_text.index("end-1c")
            if sent:
                meta = self._t("messages.conversation.sent_meta", time=timestamp, destination=destination) + "\n"
                self.conversation_text.insert(
                    "end", meta, ("sent_meta", message_tag)
                )
                self.conversation_text.insert(
                    "end", text + "\n", ("sent_body", message_tag)
                )
                if status:
                    self.conversation_text.insert(
                        "end", status + "\n", ("sent_status", message_tag)
                    )
            else:
                meta = self._t("messages.conversation.received_meta", source=source, time=timestamp) + "\n"
                self.conversation_text.insert(
                    "end", meta, ("received_meta", message_tag)
                )
                self.conversation_text.insert(
                    "end", text + "\n", ("received_body", message_tag)
                )
                if status:
                    self.conversation_text.insert(
                        "end", status + "\n", ("received_status", message_tag)
                    )
            end_index = self.conversation_text.index("end-1c")
            self.conversation_text.tag_bind(
                message_tag,
                "<Button-1>",
                lambda event, tag=message_tag: self._select_conversation_message(tag, event),
            )
            self.conversation_text.tag_bind(
                message_tag,
                "<Double-1>",
                lambda event, tag=message_tag: self._select_conversation_message(
                    tag, event, open_reply=True
                ),
            )
            self.conversation_text.tag_bind(
                message_tag,
                "<Button-3>",
                lambda event, tag=message_tag: self._show_conversation_message_menu(
                    tag, event
                ),
            )
            if self._message_row_identity(row) == self.selected_message_identity:
                self.conversation_text.tag_add(
                    "selected_message", start_index, end_index
                )
        self.conversation_text.tag_raise("selected_message")
        self.conversation_text.configure(state="disabled")
        self.rendered_conversation_key = key
        if was_at_bottom:
            self.conversation_text.see("end")
        else:
            self.conversation_text.yview_moveto(previous_view[0])

    def _render_messages(self, messages: list[dict[str, Any]]) -> None:
        self.visible_message_rows = list(messages)
        self._render_message_table(messages)
        self._render_conversations(messages)

    def _refresh_local_mesh_nodes(self) -> None:
        for key, client in self.mesh_clients.items():
            try:
                status = client.call({"command": "status"})["status"]
                response = client.call({"command": "nodes", "since_revision": 0})
                nodes = response["nodes"]
                self.local_mesh_status[key] = status
                for node in nodes:
                    node.setdefault(
                        "last_updated",
                        datetime.now().astimezone().isoformat(timespec="seconds"),
                    )
                    self.catalog.upsert(key, node, source=f"local:{key}")
                self._reload_catalog_network(key)
            except Exception as exc:
                self.local_mesh_status[key] = {"online": False, "last_error": str(exc)}
                self._reload_catalog_network(key)

    def request_all_nodes(self, *, force: bool = False) -> None:
        now = time.monotonic()
        self._expire_sync_locks(now)
        self._refresh_local_mesh_nodes()
        skipped: list[str] = []
        started: list[str] = []
        # APRS has one authoritative Base source.  Keep ordinary node/message/
        # position sync multi-route, but queue APRS only on the explicitly
        # preferred Base route (normally mesh868).  This avoids duplicate or
        # stalled APRS requests on mesh433/mesh433f, whose services do not own
        # the APRS presentation provider.
        aprs_route = None
        if bool(getattr(self, "aprs_field_sync_enabled", False)):
            remote = self._remote_base_network()
            if remote is not None:
                aprs_route = remote[0]
        for key in self.network_order:
            network = self.networks[key]
            if network["kind"] != "mesh_gateway":
                continue
            active = self.node_sync_active.get(key)
            if (
                active
                and now - float(active.get("started", 0.0)) < self.sync_lock_seconds
            ) or self._sync_operation_pending("info", key) or self._sync_operation_pending(
                "nodes", key
            ) or self._sync_operation_pending("positions", key):
                skipped.append(str(network["label"]))
                continue
            if self._sync_operation_pending("position_history", key):
                skipped.append(str(network["label"]))
                continue
            try:
                self.node_sync_active[key] = {
                    "node_request": "",
                    "info_request": "",
                    "node_done": False,
                    "info_done": False,
                    "identity_done": False,
                    "started": now,
                }
                self._queue_sync_operation("info", key)
                self._queue_sync_operation("nodes", key)
                self._queue_sync_operation("positions", key)
                self._queue_sync_operation("position_history", key)
                if aprs_route == key:
                    self._queue_sync_operation("aprs", key)
                started.append(str(network["label"]))
            except Exception as exc:
                status = self.gateway_status.setdefault(key, {})
                status["error"] = str(exc)
                status["cached"] = True
                self.catalog.save_gateway_status(key, status)
        self._start_next_sync_operation()
        self.last_gateway_request = now
        self.last_local_node_refresh = now
        self._refresh_recipient_combo()
        self._refresh_node_tree()
        if force and skipped and not started:
            self.operations_result_label.configure(
                text=_text_for(self, "operations.sync.already", items=", ".join(skipped))
            )

    def request_position_sync(self, route: str, *, force: bool = False) -> None:
        network = self.networks.get(route)
        if not network or network.get("kind") != "mesh_gateway":
            return
        now = time.monotonic()
        self._expire_sync_locks(now)
        active = self.position_sync_active.get(route)
        if (
            active and now - active[1] < self.sync_lock_seconds
        ) or self._sync_operation_pending("positions", route):
            return
        self._queue_sync_operation("positions", route)
        self._start_next_sync_operation()

    def request_position_history_sync(
        self,
        route: str,
        *,
        force: bool = False,
    ) -> None:
        network = self.networks.get(route)
        if not network or network.get("kind") != "mesh_gateway":
            return
        now = time.monotonic()
        self._expire_sync_locks(now)
        active = self.position_history_sync_active.get(route)
        if (
            active
            and now - float(active.get("started", 0.0)) < self.sync_lock_seconds
        ) or self._sync_operation_pending("position_history", route):
            return
        self._queue_sync_operation("position_history", route)
        self._start_next_sync_operation()

    def request_all_position_history(self) -> None:
        started = False
        for key in self.network_order:
            if self.networks[key].get("kind") == "mesh_gateway":
                self.request_position_history_sync(key, force=True)
                started = True
        if started:
            self.position_history_status_var.set(self._t("position.sync.queued"))
        else:
            self._refresh_position_history_view(force=True)

    def request_aprs_sync(self, route: str, *, force: bool = False) -> None:
        if not self.aprs_field_sync_enabled or self.aprs_replica_store is None:
            return
        network = self.networks.get(route)
        if not network or network.get("kind") != "mesh_gateway":
            return
        now = time.monotonic()
        self._expire_sync_locks(now)
        active = self.aprs_sync_active.get(route)
        if (active and now - float(active.get("started", 0.0)) < self.sync_lock_seconds) \
                or self._sync_operation_pending("aprs", route):
            return
        self._queue_sync_operation("aprs", route)
        self._start_next_sync_operation()

    def request_all_aprs(self) -> None:
        if not self.aprs_field_sync_enabled:
            return
        remote = self._remote_base_network()
        if remote is not None:
            self.request_aprs_sync(remote[0])

    def request_message_sync(self, route: str, *, force: bool = False) -> None:
        network = self.networks.get(route)
        if not network or network.get("kind") != "mesh_gateway":
            return
        now = time.monotonic()
        self._expire_sync_locks(now)
        active = self.message_sync_active.get(route)
        if (
            active and now - active[1] < self.sync_lock_seconds
        ) or self._sync_operation_pending("messages", route):
            return
        self._queue_sync_operation("messages", route)
        self._start_next_sync_operation()

    def request_all_messages(self) -> None:
        for key in self.network_order:
            if self.networks[key].get("kind") == "mesh_gateway":
                self.request_message_sync(key)
        self.last_message_sync_request = time.monotonic()

    def _refresh_node_tree(self) -> None:
        try:
            all_rows = self._all_node_rows()
            rows = self._filter_node_rows(all_rows)
            self._render_node_rows(rows)
            self.node_filter_result_label.configure(text=self._t("nodes.result.count", shown=len(rows), total=len(all_rows)))
            self._refresh_position_privacy_status()
        except Exception as exc:
            self.node_filter_result_label.configure(
                text=self._t("nodes.filter_error_body", error=exc)
            )

    def _selected_node_identity(self) -> tuple[str, str] | None:
        selected = self.node_tree.selection()
        if not selected:
            messagebox.showwarning(self._t("nodes.select_title"), self._t("nodes.select_body"))
            return None
        return self.node_tree_items.get(selected[0])

    def add_manual_node(self) -> None:
        mesh_keys = [
            key for key in self.network_order if self.networks[key]["kind"] != "waveshare"
        ]
        if not mesh_keys:
            messagebox.showwarning(self._t("nodes.no_meshtastic_title"), self._t("nodes.no_meshtastic_body"))
            return
        dialog = tk.Toplevel(self)
        dialog.title(self._t("nodes.add_known_title"))
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=self._t("nodes.network")).grid(row=0, column=0, sticky="w", pady=4)
        network_combo = ttk.Combobox(frame, state="readonly", width=30)
        network_combo["values"] = [self.networks[key]["label"] for key in mesh_keys]
        selected_key = self.selected_network_key()
        network_combo.current(mesh_keys.index(selected_key) if selected_key in mesh_keys else 0)
        network_combo.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        ttk.Label(frame, text=self._t("nodes.node_id")).grid(row=1, column=0, sticky="w", pady=4)
        node_var = tk.StringVar(value="!")
        node_entry = ttk.Entry(frame, textvariable=node_var, width=32)
        node_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        ttk.Label(frame, text=self._t("nodes.optional_name")).grid(row=2, column=0, sticky="w", pady=4)
        name_var = tk.StringVar()
        ttk.Entry(frame, textvariable=name_var, width=32).grid(
            row=2, column=1, sticky="ew", padx=(8, 0), pady=4
        )
        ttk.Label(
            frame,
            text=self._t("nodes.manual_hint"),
            wraplength=390,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 10))

        def save() -> None:
            try:
                key = mesh_keys[network_combo.current()]
                self.catalog.add_manual(key, node_var.get(), name_var.get())
                self._reload_catalog_network(key)
                self._refresh_node_tree()
                self._refresh_recipient_combo()
                dialog.destroy()
            except Exception as exc:
                messagebox.showerror(self._t("nodes.invalid_id"), str(exc), parent=dialog)

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text=self._t("action.cancel"), command=dialog.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text=self._t("emergency.action.save"), command=save).pack(side="right")
        node_entry.focus_set()
        dialog.bind("<Return>", lambda event: save())
        dialog.bind("<Escape>", lambda event: dialog.destroy())
        self.wait_window(dialog)

    def set_selected_alias(self) -> None:
        identity = self._selected_node_identity()
        if not identity:
            return
        network, node_id = identity
        current = self.contacts.alias(network, node_id)
        alias = simpledialog.askstring(
            self._t("nodes.alias.title"),
            self._t("nodes.alias.prompt", node_id=node_id),
            initialvalue=current,
            parent=self,
        )
        if alias is None:
            return
        self.contacts.set_alias(network, node_id, alias)
        self._refresh_node_tree()
        self._refresh_recipient_combo()
        self._render_messages(list(self.visible_message_rows))

    def toggle_selected_favorite(self) -> None:
        identity = self._selected_node_identity()
        if not identity:
            return
        network, node_id = identity
        self.contacts.set_favorite(
            network, node_id, not self.contacts.favorite(network, node_id)
        )
        self._refresh_node_tree()
        self._refresh_recipient_combo()
        self._render_messages(list(self.visible_message_rows))

    def _contact_export_metadata(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for network, nodes in self.node_cache.items():
            for node in nodes:
                node_id = str(node.get("id", node.get("num", "")))
                rows.append(
                    {
                        "network": network,
                        "node_id": node_id,
                        "long_name": str(node.get("long_name", "")),
                        "short_name": str(node.get("short_name", "")),
                        "manual": bool(node.get("manual", False)),
                    }
                )
        return rows

    def export_contacts(self) -> None:
        filename = filedialog.asksaveasfilename(
            parent=self,
            title=self._t("nodes.contacts.export_title"),
            defaultextension=".json",
            filetypes=[
                (self._t("nodes.contacts.filetype"), "*.json"),
                (self._t("common.all_files"), "*"),
            ],
            initialfile=f"gutochat-kontakter-{datetime.now():%Y%m%d}.json",
        )
        if not filename:
            return
        try:
            count = self.contacts.export_file(
                Path(filename), self._contact_export_metadata()
            )
            messagebox.showinfo(
                self._t("nodes.contacts.export_done_title"),
                self._t("nodes.contacts.export_done_body", count=count, filename=filename),
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(self._t("nodes.contacts.export_error_title"), str(exc), parent=self)

    def import_contacts(self) -> None:
        filename = filedialog.askopenfilename(
            parent=self,
            title=self._t("nodes.contacts.import_title"),
            filetypes=[
                (self._t("nodes.contacts.filetype"), "*.json"),
                (self._t("common.all_files"), "*"),
            ],
        )
        if not filename:
            return
        replace = messagebox.askyesnocancel(
            self._t("nodes.contacts.import_choice_title"),
            self._t("nodes.contacts.import_choice_body"),
            parent=self,
        )
        if replace is None:
            return
        try:
            imported = self.contacts.import_file(Path(filename), replace=replace)
            for item in imported:
                network = str(item["network"])
                node_id = str(item["node_id"])
                if network == "waveshare" or network not in self.networks:
                    continue
                known = any(
                    str(node.get("id", "")) == node_id
                    for node in self.node_cache.get(network, [])
                )
                if not known:
                    name = str(item.get("long_name") or item.get("alias") or "")
                    try:
                        self.catalog.add_manual(network, node_id, name)
                    except Exception:
                        pass
                self._reload_catalog_network(network)
            self._refresh_node_tree()
            self._refresh_recipient_combo()
            messagebox.showinfo(
                self._t("nodes.contacts.import_done_title"),
                self._t("nodes.contacts.import_done_body", count=len(imported)),
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(self._t("nodes.contacts.import_error_title"), str(exc), parent=self)

    def use_selected_node(self) -> None:
        identity = self._selected_node_identity()
        if not identity:
            return
        network_key, node_id = identity
        network_index = self.network_order.index(network_key)
        self.network_combo.current(network_index)
        self.type_combo["values"] = self._message_type_values(self.networks[network_key])
        self.type_combo.current(0)
        self._refresh_recipient_combo()
        for index, item in enumerate(self.current_recipient_items):
            if str(item.get("destination")) == node_id or str(item.get("node", {}).get("id")) == node_id:
                self.recipient_combo.current(index)
                self.last_recipient_by_network[network_key] = str(
                    item.get("destination")
                )
                self._save_ui_state()
                break
        self._update_route_preview()
        self.notebook.select(self.messages_tab)
        self.message_text.focus_set()

    def open_selected_node_conversation(self) -> None:
        identity = self._selected_node_identity()
        if not identity:
            return
        network_key, node_id = identity
        selected = self.node_tree.selection()
        node_row = self.node_tree_rows.get(selected[0], {}) if selected else {}
        node = dict(node_row.get("node") or {})
        node_num = node.get("num", node_row.get("num"))
        target_key = self._conversation_key_for_node(
            network_key, node_id, node_num
        )

        self.message_network_filter_var.set(
            str(self.networks.get(network_key, {}).get("label", self._t("messages.filter.network_all")))
        )
        contact_name = str(
            node_row.get("alias")
            or node_row.get("long_name")
            or node_row.get("short_name")
            or node_id
        )
        self.message_contact_filter_var.set(contact_name)
        self.message_view_var.set("Samtalevisning")
        self._message_view_changed()
        self.pending_conversation_key = target_key
        self.notebook.select(self.messages_tab)
        self._apply_message_filters()
        try:
            self.conversation_tree.focus_set()
        except tk.TclError:
            pass

    def _update_system_tree(
        self, rows: list[tuple[str, str, str]] | None = None
    ) -> None:
        source = rows or self._system_rows()
        all_rows = [
            {"component": component, "status": status, "details": details}
            for component, status, details in source
        ]
        filtered = self._filter_system_rows(all_rows)
        self._render_system_rows(filtered)
        self.system_filter_result_label.configure(
            text=self._t(
                "system.result.snapshot",
                shown=len(filtered),
                total=len(all_rows),
            )
        )

    def run_self_test(self) -> None:
        self.request_all_nodes()
        problems: list[str] = []
        try:
            ws = self.ws_client.call({"command": "status"})["status"]
            if self.private_radio_enabled and not ws.get("radio_online"):
                problems.append(self._t("system.self_test.ws_radio_offline"))
        except Exception as exc:
            problems.append(self._t("system.self_test.ws_service_error", error=exc))
        for key, client in self.mesh_clients.items():
            try:
                status = client.call({"command": "status"})["status"]
                if not status.get("online"):
                    problems.append(
                        self._t("system.self_test.mesh_offline", network=self.networks[key]["label"])
                    )
            except Exception as exc:
                problems.append(
                    self._t(
                        "system.self_test.mesh_service_error",
                        network=self.networks[key]["label"],
                        error=exc,
                    )
                )
        if problems:
            text = self._t(
                "system.self_test.problems_body",
                problems="\n".join(f"• {p}" for p in problems),
            )
            self.self_test_label.configure(text=self._t("system.self_test.problems"))
            messagebox.showwarning(self._t("system.self_test.warning_title"), text)
        else:
            self.self_test_label.configure(text=self._t("system.self_test.local_ok"))
            messagebox.showinfo(
                self._t("system.self_test.warning_title"),
                self._t("system.self_test.ok_body"),
            )

    def _emergency_category_label(self, category: Any) -> str:
        value = str(category or "")
        key = EMERGENCY_CATEGORY_KEYS.get(value)
        return self._t(key) if key else value

    def _emergency_category_value(self, label: str) -> str:
        for value in TEMPLATE_CATEGORIES:
            if self._emergency_category_label(value) == label:
                return value
        raise ValueError(f"Unknown emergency category label: {label}")

    def _emergency_severity_label(self, severity: Any) -> str:
        key = EMERGENCY_SEVERITY_KEYS.get(severity)
        return self._t(key) if key else self._t("emergency.severity.unknown")

    def _emergency_severity_value(self, label: str) -> str | None:
        for value in (None, *TEMPLATE_SEVERITIES):
            if self._emergency_severity_label(value) == label:
                return value
        raise ValueError(f"Unknown emergency severity label: {label}")

    @staticmethod
    def _emergency_preview(text: str, limit: int = 140) -> str:
        preview = " ↵ ".join(part.strip() for part in text.splitlines()).strip()
        if len(preview) > limit:
            return preview[: limit - 1].rstrip() + "…"
        return preview

    def _refresh_emergency_templates(self, select_id: str | None = None) -> None:
        previous = select_id
        if previous is None and hasattr(self, "emergency_tree"):
            selection = self.emergency_tree.selection()
            previous = str(selection[0]) if selection else None
        templates = self.emergency_templates.list_templates()
        self.emergency_template_rows = {
            str(template["id"]): template for template in templates
        }
        for item_id in self.emergency_tree.get_children():
            self.emergency_tree.delete(item_id)
        for template in templates:
            template_id = str(template["id"])
            self.emergency_tree.insert(
                "",
                "end",
                iid=template_id,
                values=(
                    template["name"],
                    self._emergency_category_label(template["category"]),
                    self._emergency_severity_label(template.get("severity")),
                    self._t("emergency.yes") if template["requires_confirmation"] else self._t("emergency.no"),
                    self._emergency_preview(str(template["text"])),
                ),
            )
        chosen = None
        if previous and previous in self.emergency_template_rows:
            chosen = previous
        elif templates:
            chosen = str(templates[0]["id"])
        if chosen:
            self.emergency_tree.selection_set(chosen)
            self.emergency_tree.focus(chosen)
            self.emergency_tree.see(chosen)
        self._emergency_template_selection_changed()

    def _selected_emergency_template(self) -> dict[str, Any] | None:
        selection = self.emergency_tree.selection()
        if not selection:
            return None
        return self.emergency_template_rows.get(str(selection[0]))

    def _emergency_template_selection_changed(self, _event: Any = None) -> None:
        template = self._selected_emergency_template()
        state = "normal" if template is not None else "disabled"
        for button in (
            self.emergency_edit_button,
            self.emergency_copy_button,
            self.emergency_delete_button,
            self.emergency_use_button,
        ):
            button.configure(state=state)

        rows = list(self.emergency_tree.get_children())
        selected_id = str(template["id"]) if template else ""
        selected_index = rows.index(selected_id) if selected_id in rows else -1
        self.emergency_move_up_button.configure(
            state="normal" if selected_index > 0 else "disabled"
        )
        self.emergency_move_down_button.configure(
            state=(
                "normal"
                if selected_index >= 0 and selected_index < len(rows) - 1
                else "disabled"
            )
        )

        details = ""
        if template is not None:
            confirmation = (
                self._t("emergency.confirmation.load")
                if template["requires_confirmation"]
                else self._t("emergency.no")
            )
            details = self._t(
                "emergency.details",
                name=template["name"],
                category=self._emergency_category_label(template["category"]),
                severity=self._emergency_severity_label(template.get("severity")),
                confirmation=confirmation,
                text=template["text"],
            )
        self.emergency_details_text.configure(state="normal")
        self.emergency_details_text.delete("1.0", "end")
        if details:
            self.emergency_details_text.insert("1.0", details)
        self.emergency_details_text.configure(state="disabled")
        count = len(self.emergency_template_rows)
        self.emergency_status_label.configure(
            text=self._t(
                "emergency.count.one" if count == 1 else "emergency.count.many",
                count=count,
            )
        )

    def _show_emergency_template_editor(
        self, template: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        dialog = tk.Toplevel(self)
        dialog.title(self._t("emergency.editor.edit") if template else self._t("emergency.editor.new"))
        dialog.transient(self)
        dialog.resizable(True, True)
        dialog.minsize(620, 470)
        container = ttk.Frame(dialog, padding=14)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(4, weight=1)

        name_var = tk.StringVar(
            value=str(template.get("name", "")) if template else ""
        )
        category_value = str(template.get("category", "Status")) if template else "Status"
        category_var = tk.StringVar(value=self._emergency_category_label(category_value))
        severity_var = tk.StringVar(
            value=self._emergency_severity_label(
                template.get("severity") if template else None
            )
        )
        confirmation_var = tk.BooleanVar(
            value=(
                bool(template.get("requires_confirmation", False))
                if template
                else False
            )
        )

        ttk.Label(container, text=self._t("emergency.field.name")).grid(row=0, column=0, sticky="w")
        name_entry = ttk.Entry(container, textvariable=name_var, width=50)
        name_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(container, text=self._t("emergency.field.category")).grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        category_combo = ttk.Combobox(
            container,
            state="readonly",
            values=[self._emergency_category_label(value) for value in TEMPLATE_CATEGORIES],
            textvariable=category_var,
            width=25,
        )
        category_combo.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Label(container, text=self._t("emergency.field.severity")).grid(
            row=2, column=0, sticky="w", pady=(8, 0)
        )
        ttk.Combobox(
            container,
            state="readonly",
            values=[self._emergency_severity_label(value) for value in (None, *TEMPLATE_SEVERITIES)],
            textvariable=severity_var,
            width=25,
        ).grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Checkbutton(
            container,
            text=self._t("emergency.field.confirmation"),
            variable=confirmation_var,
        ).grid(row=3, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Label(container, text=self._t("emergency.field.message")).grid(
            row=4, column=0, sticky="nw", pady=(10, 0)
        )
        text_frame = ttk.Frame(container)
        text_frame.grid(row=4, column=1, sticky="nsew", padx=(8, 0), pady=(10, 0))
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        text_widget = tk.Text(text_frame, wrap="word", undo=True, height=10)
        text_scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=text_widget.yview
        )
        text_widget.configure(yscrollcommand=text_scroll.set)
        text_widget.grid(row=0, column=0, sticky="nsew")
        text_scroll.grid(row=0, column=1, sticky="ns")
        if template:
            text_widget.insert("1.0", str(template.get("text", "")))
        ttk.Label(
            container,
            text=self._t(
                "emergency.placeholder_help",
                placeholders=", ".join("{" + name + "}" for name in ALLOWED_PLACEHOLDERS),
            ),
            wraplength=520,
            justify="left",
        ).grid(row=5, column=1, sticky="w", padx=(8, 0), pady=(6, 0))

        result: dict[str, Any] = {}

        def save() -> None:
            name = name_var.get().strip()
            text_value = text_widget.get("1.0", "end-1c")
            if not name:
                messagebox.showwarning(
                    self._t("emergency.dialog.template"), self._t("emergency.warning.name"), parent=dialog
                )
                name_entry.focus_set()
                return
            if not text_value.strip():
                messagebox.showwarning(
                    self._t("emergency.dialog.template"), self._t("emergency.warning.message"), parent=dialog
                )
                text_widget.focus_set()
                return
            try:
                extract_placeholders(text_value)
            except ValueError as exc:
                messagebox.showwarning(
                    self._t("emergency.dialog.template"), str(exc), parent=dialog
                )
                text_widget.focus_set()
                return
            result.update(
                {
                    "name": name,
                    "category": self._emergency_category_value(category_var.get()),
                    "severity": self._emergency_severity_value(severity_var.get()),
                    "text": text_value,
                    "requires_confirmation": bool(confirmation_var.get()),
                }
            )
            dialog.destroy()

        def cancel() -> None:
            dialog.destroy()

        buttons = ttk.Frame(container)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text=self._t("action.cancel"), command=cancel).pack(side="right")
        ttk.Button(buttons, text=self._t("emergency.action.save"), command=save).pack(
            side="right", padx=(0, 8)
        )
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        dialog.bind("<Escape>", lambda _event: cancel())
        dialog.bind("<Control-Return>", lambda _event: save())
        dialog.update_idletasks()
        dialog.grab_set()
        name_entry.focus_set()
        self.wait_window(dialog)
        return result or None

    def new_emergency_template(self) -> None:
        values = self._show_emergency_template_editor()
        if values is None:
            return
        try:
            created = self.emergency_templates.create_template(**values)
            self._refresh_emergency_templates(str(created["id"]))
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.dialog.template"), self._t("emergency.error.create", error=exc), parent=self
            )

    def edit_selected_emergency_template(self) -> None:
        template = self._selected_emergency_template()
        if template is None:
            messagebox.showinfo(self._t("emergency.dialog.template"), self._t("emergency.select_first"), parent=self)
            return
        values = self._show_emergency_template_editor(template)
        if values is None:
            return
        try:
            updated = self.emergency_templates.update_template(
                str(template["id"]), **values
            )
            self._refresh_emergency_templates(str(updated["id"]))
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.dialog.template"),
                self._t("emergency.error.save", error=exc),
                parent=self,
            )

    def copy_selected_emergency_template(self) -> None:
        template = self._selected_emergency_template()
        if template is None:
            messagebox.showinfo(self._t("emergency.dialog.template"), self._t("emergency.select_first"), parent=self)
            return
        try:
            copied = self.emergency_templates.copy_template(str(template["id"]))
            self._refresh_emergency_templates(str(copied["id"]))
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.dialog.template"), self._t("emergency.error.copy", error=exc), parent=self
            )

    def delete_selected_emergency_template(self) -> None:
        template = self._selected_emergency_template()
        if template is None:
            messagebox.showinfo(self._t("emergency.dialog.template"), self._t("emergency.select_first"), parent=self)
            return
        if not messagebox.askyesno(
            self._t("emergency.delete.title"),
            self._t("emergency.delete.confirm", name=template["name"]),
            parent=self,
        ):
            return
        try:
            self.emergency_templates.delete_template(str(template["id"]))
            self._refresh_emergency_templates()
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.dialog.template"), self._t("emergency.error.delete", error=exc), parent=self
            )

    def move_selected_emergency_template(self, direction: int) -> None:
        template = self._selected_emergency_template()
        if template is None:
            return
        try:
            self.emergency_templates.move_template(str(template["id"]), direction)
            self._refresh_emergency_templates(str(template["id"]))
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.dialog.template"), self._t("emergency.error.move", error=exc), parent=self
            )

    def _emergency_recipient_label(self) -> str:
        item = self._selected_recipient_item()
        if item is None:
            raise ValueError(self._t("emergency.recipient.choose"))
        destination = item.get("destination")
        if destination in ("broadcast", "^all", BROADCAST_MESH, 65535):
            return self._t("emergency.recipient.all")
        label = str(item.get("label") or self.recipient_combo.get()).strip()
        if not label:
            raise ValueError(self._t("emergency.recipient.missing"))
        return label

    def _emergency_position_options(self) -> list[dict[str, Any]]:
        """Return latest trusted positions for explicit preview selection."""
        options: list[dict[str, Any]] = []
        now_epoch = int(time.time())
        for row in self.position_store.list_latest():
            network = str(row.get("network", ""))
            node_id = str(row.get("node_id", ""))
            if not network or not node_id:
                continue
            label = self.contacts.alias(network, node_id) or self._resolve_node_name(
                network,
                node_id,
            )
            age_seconds = max(0, now_epoch - int(row.get("position_epoch", 0)))
            option = dict(row)
            option["age_seconds"] = age_seconds
            option["label"] = self._t(
                "emergency.position.option",
                network=self._network_label(network),
                label=label or node_id,
                node_id=node_id,
                age=self._format_position_duration(age_seconds),
                source=str(row.get("source") or self._t("emergency.position.unknown_source")),
            )
            options.append(option)
        options.sort(key=lambda item: str(item["label"]).casefold())
        return options

    def _show_emergency_template_preview(self, template: dict[str, Any]) -> None:
        """Render a mandatory preview and only copy the approved text to compose."""
        template_text = str(template["text"])
        try:
            placeholders = extract_placeholders(template_text)
            recipient = (
                self._emergency_recipient_label()
                if "MOTTAKER" in placeholders
                else None
            )
        except Exception as exc:
            messagebox.showerror(self._t("emergency.dialog.template"), str(exc), parent=self)
            return

        fixed_time = datetime.now().astimezone()
        position_options = (
            self._emergency_position_options()
            if "POSISJON" in placeholders
            else []
        )
        position_by_label = {str(item["label"]): item for item in position_options}

        dialog = tk.Toplevel(self)
        dialog.title(self._t("emergency.preview.dialog_title", name=template["name"]))
        dialog.transient(self)
        dialog.resizable(True, True)
        dialog.minsize(680, 520)
        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        preview_row = 0

        ttk.Label(frame, text=self._t("emergency.preview.template")).grid(row=preview_row, column=0, sticky="w")
        ttk.Label(frame, text=str(template["name"])).grid(
            row=preview_row, column=1, sticky="w", padx=(10, 0)
        )
        preview_row += 1
        ttk.Label(frame, text=self._t("emergency.preview.severity")).grid(
            row=preview_row, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Label(
            frame,
            text=self._emergency_severity_label(template.get("severity")),
        ).grid(row=preview_row, column=1, sticky="w", padx=(10, 0), pady=(6, 0))
        preview_row += 1

        callsign_var = tk.StringVar(value=self.station_callsign)
        if "KALLESIGNAL" in placeholders:
            ttk.Label(frame, text=self._t("emergency.preview.callsign")).grid(
                row=preview_row, column=0, sticky="w", pady=(8, 0)
            )
            callsign_entry = ttk.Entry(frame, textvariable=callsign_var)
            callsign_entry.grid(
                row=preview_row, column=1, sticky="ew", padx=(10, 0), pady=(8, 0)
            )
            preview_row += 1
        if "MOTTAKER" in placeholders:
            ttk.Label(frame, text=self._t("emergency.preview.recipient")).grid(
                row=preview_row, column=0, sticky="w", pady=(8, 0)
            )
            ttk.Label(frame, text=recipient or "").grid(
                row=preview_row, column=1, sticky="w", padx=(10, 0), pady=(8, 0)
            )
            preview_row += 1

        position_var = tk.StringVar()
        exact_position_var = tk.BooleanVar(value=False)
        position_info_var = tk.StringVar()
        if "POSISJON" in placeholders:
            ttk.Label(frame, text=self._t("emergency.preview.position_node")).grid(
                row=preview_row, column=0, sticky="w", pady=(8, 0)
            )
            position_combo = ttk.Combobox(
                frame,
                state="readonly",
                textvariable=position_var,
                values=[str(item["label"]) for item in position_options],
                width=70,
            )
            position_combo.grid(
                row=preview_row, column=1, sticky="ew", padx=(10, 0), pady=(8, 0)
            )
            preview_row += 1
            precision_frame = ttk.Frame(frame)
            precision_frame.grid(
                row=preview_row, column=1, sticky="w", padx=(10, 0), pady=(4, 0)
            )
            ttk.Radiobutton(
                precision_frame,
                text=self._t("emergency.preview.precision_reduced"),
                value=False,
                variable=exact_position_var,
            ).pack(anchor="w")
            ttk.Radiobutton(
                precision_frame,
                text=self._t("emergency.preview.precision_full"),
                value=True,
                variable=exact_position_var,
            ).pack(anchor="w", pady=(3, 0))
            preview_row += 1
            ttk.Label(
                frame,
                textvariable=position_info_var,
                wraplength=560,
                justify="left",
            ).grid(
                row=preview_row,
                column=1,
                sticky="w",
                padx=(10, 0),
                pady=(4, 0),
            )
            preview_row += 1

        ttk.Label(frame, text=self._t("emergency.preview.heading")).grid(
            row=preview_row, column=0, sticky="nw", pady=(12, 0)
        )
        preview_widget = tk.Text(frame, height=12, wrap="word", state="disabled")
        preview_widget.grid(
            row=preview_row,
            column=1,
            sticky="nsew",
            padx=(10, 0),
            pady=(12, 0),
        )
        frame.rowconfigure(preview_row, weight=1)
        preview_row += 1
        status_var = tk.StringVar(
            value=self._t("emergency.preview.initial")
        )
        ttk.Label(
            frame,
            textvariable=status_var,
            wraplength=600,
            justify="left",
        ).grid(row=preview_row, column=0, columnspan=2, sticky="w", pady=(8, 0))
        preview_row += 1

        rendered_text: dict[str, str] = {"value": ""}

        def render_preview(event: Any = None) -> None:
            try:
                selected_position = None
                if "POSISJON" in placeholders:
                    option = position_by_label.get(position_var.get())
                    if option is None:
                        raise ValueError(self._t("emergency.preview.choose_position"))
                    selected_position = format_position(
                        int(option["latitude_i"]),
                        int(option["longitude_i"]),
                        exact=bool(exact_position_var.get()),
                    )
                    age = int(option["age_seconds"])
                    state = self._t(
                        "emergency.position.stale"
                        if age > self.position_store.stale_minutes() * 60
                        else "emergency.position.fresh"
                    )
                    position_info_var.set(
                        self._t(
                            "emergency.preview.position_info",
                            state=state,
                            age=self._format_position_duration(age),
                            source=str(option.get("source") or self._t("common.unknown")),
                        )
                    )
                preview = render_template(
                    template_text,
                    callsign=callsign_var.get(),
                    recipient=recipient,
                    position=selected_position,
                    preview_time=fixed_time,
                )
                rendered_text["value"] = preview.text
                preview_widget.configure(state="normal")
                preview_widget.delete("1.0", "end")
                preview_widget.insert("1.0", preview.text)
                preview_widget.configure(state="disabled")
                used = len(preview.text.encode("utf-8"))
                status_var.set(
                    self._t(
                        "emergency.preview.stats",
                        chars=len(preview.text),
                        bytes=used,
                    )
                )
            except Exception as exc:
                rendered_text["value"] = ""
                preview_widget.configure(state="normal")
                preview_widget.delete("1.0", "end")
                preview_widget.insert("1.0", self._t("emergency.preview.error", error=exc))
                preview_widget.configure(state="disabled")
                status_var.set(self._t("emergency.preview.missing"))

        def apply_preview() -> None:
            render_preview()
            text_value = rendered_text["value"]
            if not text_value:
                return
            if "POSISJON" in placeholders:
                option = position_by_label[position_var.get()]
                if bool(exact_position_var.get()):
                    if not messagebox.askyesno(
                        self._t("emergency.confirm.exact_title"),
                        self._t("emergency.confirm.exact"),
                        parent=dialog,
                    ):
                        return
                if int(option["age_seconds"]) > self.position_store.stale_minutes() * 60:
                    if not messagebox.askyesno(
                        self._t("emergency.confirm.stale_title"),
                        self._t("emergency.confirm.stale"),
                        parent=dialog,
                    ):
                        return
            if bool(template.get("requires_confirmation")):
                if not messagebox.askyesno(
                    self._t("emergency.confirm.extra_title"),
                    self._t("emergency.confirm.extra"),
                    parent=dialog,
                ):
                    return
            dialog.destroy()
            self.use_emergency_template(text_value)

        if "KALLESIGNAL" in placeholders:
            callsign_var.trace_add("write", lambda *_args: render_preview())
        if "POSISJON" in placeholders:
            position_combo.bind("<<ComboboxSelected>>", render_preview)
            exact_position_var.trace_add("write", lambda *_args: render_preview())
        buttons = ttk.Frame(frame)
        buttons.grid(row=preview_row, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text=self._t("action.cancel"), command=dialog.destroy).pack(side="right")
        ttk.Button(
            buttons,
            text=self._t("emergency.preview.apply"),
            command=apply_preview,
        ).pack(side="right", padx=(0, 8))
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        render_preview()
        dialog.grab_set()
        self.wait_window(dialog)

    def use_selected_emergency_template(self) -> None:
        template = self._selected_emergency_template()
        if template is None:
            messagebox.showinfo(self._t("emergency.dialog.template"), self._t("emergency.select_first"), parent=self)
            return
        self._show_emergency_template_preview(template)

    def export_emergency_templates(self) -> None:
        filename = filedialog.asksaveasfilename(
            parent=self,
            title=self._t("emergency.export.title"),
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), (self._t("common.all_files"), "*.*")],
            initialfile=(
                "lorachat-beredskapsmaler-"
                + datetime.now().strftime("%Y%m%d-%H%M%S")
                + ".json"
            ),
        )
        if not filename:
            return
        try:
            count = self.emergency_templates.export_file(Path(filename))
            messagebox.showinfo(
                self._t("export.title"),
                self._t("emergency.export.done", count=count, filename=filename),
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("export.title"),
                self._t("emergency.export.failed", error=exc),
                parent=self,
            )

    def import_emergency_templates(self) -> None:
        filename = filedialog.askopenfilename(
            parent=self,
            title=self._t("emergency.import.title"),
            filetypes=[("JSON", "*.json"), (self._t("common.all_files"), "*.*")],
        )
        if not filename:
            return
        try:
            try:
                report = self.emergency_templates.import_file(Path(filename))
            except TemplateConflictError as conflict:
                choice = messagebox.askyesnocancel(
                    self._t("emergency.import.conflict_title"),
                    self._t(
                        "emergency.import.conflict_body",
                        count=len(conflict.template_ids),
                    ),
                    parent=self,
                )
                if choice is None:
                    return
                mode = "copy" if choice else "skip"
                report = self.emergency_templates.import_file(
                    Path(filename), conflict_mode=mode
                )
            self._refresh_emergency_templates()
            messagebox.showinfo(
                self._t("emergency.import.title"),
                self._t(
                    "emergency.import.report",
                    total=report["total"],
                    imported=report["imported"],
                    copied=report["copied"],
                    skipped=report["skipped"],
                ),
                parent=self,
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("emergency.import.title"),
                self._t("emergency.import.failed", error=exc),
                parent=self,
            )

    def use_emergency_template(self, text: str) -> None:
        self.notebook.select(self.messages_tab)
        self.message_text.delete("1.0", "end")
        self.message_text.insert("1.0", text)
        self._update_counter()
        self.message_text.focus_set()

    def _show_message_details(self, event: Any = None) -> None:
        row = self._selected_message_row()
        if row is None:
            return
        signal = "—"
        if row.get("packet_rssi") is not None:
            signal = f"{row['packet_rssi']} dBm"
        elif row.get("ack_rssi") is not None:
            signal = f"{row['ack_rssi']} dBm ACK"
        if row.get("snr") is not None:
            signal += f" / {float(row['snr']):.1f} dB"
        values = [
            self._format_timestamp(str(row.get("timestamp", ""))),
            self._network_label(self._network_key_from_row(row)),
            self._t(
                "messages.details.direction_received"
                if row.get("direction") == "received"
                else "messages.details.direction_sent"
            ),
            self._label_from_row(row, "source"),
            self._label_from_row(row, "destination"),
            self._status_with_icon(
                str(row.get("status", "")), str(row.get("direction", ""))
            ),
            signal,
            str(row.get("text", "")),
        ]
        labels = [
            self._t("messages.details.time"),
            self._t("messages.details.network"),
            self._t("messages.details.direction"),
            self._t("messages.details.from"),
            self._t("messages.details.to"),
            self._t("messages.details.status"),
            self._t("messages.details.signal"),
            self._t("messages.details.message"),
        ]
        messagebox.showinfo(
            self._t("messages.details_title"),
            "\n".join(f"{label}: {value}" for label, value in zip(labels, values)),
            parent=self,
        )

    @staticmethod
    def _duration_text(seconds: float, *, language: str = "nb") -> str:
        seconds = max(0, int(seconds))
        if seconds < 60:
            return translate("operations.duration.seconds", language, seconds=seconds)
        minutes, seconds = divmod(seconds, 60)
        if minutes < 60:
            return translate("operations.duration.minutes", language, minutes=minutes, seconds=seconds)
        hours, minutes = divmod(minutes, 60)
        return translate("operations.duration.hours", language, hours=hours, minutes=minutes)

    def _expire_sync_locks(self, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        in_flight = self.sync_request_current
        if (
            in_flight
            and current - float(in_flight.get("started", 0.0))
            >= self.sync_lock_seconds
        ):
            route = str(in_flight.get("route", ""))
            self.sync_request_current = None
            self.sync_request_queue = [
                item for item in self.sync_request_queue if item[1] != route
            ]
            self.node_sync_active.pop(route, None)
            self.message_sync_active.pop(route, None)
            getattr(self, "message_sync_pages", {}).pop(route, None)
            self.position_sync_active.pop(route, None)
            self.position_history_sync_active.pop(route, None)
            getattr(self, "aprs_sync_active", {}).pop(route, None)
            getattr(self, "aprs_sync_more", set()).discard(route)
            self.message_sync_more.discard(route)
            self.position_history_sync_more.discard(route)
            status = self.gateway_status.setdefault(route, {})
            status["error"] = "Synkronisering utløpt før komplett svar"
        for route, active in list(self.node_sync_active.items()):
            if current - float(active.get("started", 0.0)) >= self.sync_lock_seconds:
                self.node_sync_active.pop(route, None)
        for route, active in list(self.position_sync_active.items()):
            if current - float(active[1]) >= self.sync_lock_seconds:
                self.position_sync_active.pop(route, None)
        for route, active in list(self.position_history_sync_active.items()):
            if current - float(active.get("started", 0.0)) >= self.sync_lock_seconds:
                self.position_history_sync_active.pop(route, None)
                self.position_history_sync_more.discard(route)
        aprs_active = getattr(self, "aprs_sync_active", {})
        aprs_more = getattr(self, "aprs_sync_more", set())
        for route, active in list(aprs_active.items()):
            if current - float(active.get("started", 0.0)) >= self.sync_lock_seconds:
                aprs_active.pop(route, None)
                aprs_more.discard(route)
        for route, active in list(self.message_sync_active.items()):
            if current - float(active[1]) >= self.sync_lock_seconds:
                self.message_sync_active.pop(route, None)
                getattr(self, "message_sync_pages", {}).pop(route, None)
                self.message_sync_more.discard(route)
        self._start_next_sync_operation()

    def _sync_status_text(self) -> str:
        self._expire_sync_locks()
        parts: list[str] = []
        for route, active in self.node_sync_active.items():
            label = self._network_label(route)
            done = []
            if active.get("info_done"):
                done.append(self._t("operations.sync.status_received"))
            if active.get("node_done"):
                done.append(self._t("operations.sync.nodes_received"))
            suffix = self._t("operations.sync.received_suffix", items=", ".join(done)) if done else ""
            parts.append(self._t("operations.sync.nodes_running", network=label, suffix=suffix))
        for route in self.position_sync_active:
            parts.append(self._t("operations.sync.positions_running", network=self._network_label(route)))
        for route in self.position_history_sync_active:
            parts.append(self._t("operations.sync.history_running", network=self._network_label(route)))
        for route in self.message_sync_active:
            parts.append(self._t("operations.sync.messages_running", network=self._network_label(route)))
        for route in getattr(self, "aprs_sync_active", {}):
            parts.append(f"APRS-sync via {self._network_label(route)}")
        details = "; ".join(parts) if parts else self._t("operations.sync.none")
        return self._t("operations.sync.summary", details=details)

    def _refresh_queue_view(self, *, force: bool = False) -> None:
        now_mono = time.monotonic()
        if not force and now_mono - self.last_queue_refresh < self.queue_refresh_interval:
            return
        try:
            rows: list[dict[str, Any]] = []
            for row in self.ws_client.call({"command": "outbox"}).get("outbox", []):
                item = dict(row)
                item["_queue_source"] = "waveshare"
                item["_tree_id"] = "ws:" + str(item.get("message_uid", ""))
                rows.append(item)
            for key, client in self.mesh_clients.items():
                try:
                    response = client.call({"command": "outbox"})
                except Exception:
                    continue
                status = self.local_mesh_status.get(key, {})
                for row in response.get("outbox", []):
                    item = dict(row)
                    request_id = str(item.get("request_id", ""))
                    item.update(
                        {
                            "_queue_source": "gateway",
                            "_queue_key": key,
                            "_tree_id": f"gw:{key}:{request_id}",
                            "message_uid": request_id,
                            "traffic_class": "gateway",
                            "control_route": key,
                            "control_command": "store-and-forward",
                            "max_attempts": status.get("gateway_store_forward_max_attempts"),
                        }
                    )
                    rows.append(item)
            self.queue_rows = rows
            signature = tuple(
                (
                    row.get("_tree_id"), row.get("state"), row.get("attempts"),
                    row.get("priority"), row.get("last_attempt_epoch"),
                    row.get("next_attempt_epoch"), row.get("expires_epoch"),
                    row.get("last_error"),
                )
                for row in rows
            )
            if force or signature != self.last_queue_signature:
                filtered_rows = self._filter_queue_rows(rows)
                self._render_queue_rows(filtered_rows)
                self.queue_filter_result_label.configure(
                    text=self._t(
                        "operations.result.count",
                        shown=len(filtered_rows),
                        total=len(rows),
                    )
                )
                self.last_queue_signature = signature

            sync_count = sum(1 for row in rows if str(row.get("traffic_class")) == "sync")
            gateway_count = sum(1 for row in rows if str(row.get("traffic_class")) == "gateway")
            user_count = len(rows) - sync_count - gateway_count
            held_count = sum(1 for row in rows if str(row.get("state")) == "expired_hold")
            gateway_parts: list[str] = []
            for key, status in self.local_mesh_status.items():
                gateway_parts.append(
                    self._t(
                        "operations.queue.gateway_part",
                        network=self._network_label(key),
                        count=status.get("gateway_store_forward_pending", 0),
                    )
                )
            gateway_text = "; ".join(gateway_parts) if gateway_parts else self._t("operations.queue.no_gateway")
            self.queue_summary_label.configure(
                text=self._t(
                    "operations.queue.summary",
                    users=user_count,
                    sync=sync_count,
                    gateway=gateway_count,
                    held=held_count,
                    gateways=gateway_text,
                )
            )
            self.queue_health_label.configure(
                text=self._queue_health_text(
                    rows,
                    self.ws_status,
                    self.local_mesh_status,
                    language=str(self.__dict__.get("ui_language", "nb")),
                )
            )
            sync_text = self._sync_status_text()
            self.sync_status_label.configure(text=sync_text)
            active_sync = bool(
                self.node_sync_active
                or self.position_sync_active
                or self.message_sync_active
                or self.aprs_sync_active
            )
            self.node_refresh_button.configure(state="disabled" if active_sync else "normal")
            self.last_queue_refresh = now_mono
        except Exception as exc:
            self.queue_summary_label.configure(
                text=self._t("operations.queue.read_error", error=exc)
            )
            self.queue_health_label.configure(text=self._t("operations.long_unavailable"))

    def _selected_queue_row(self) -> dict[str, Any] | None:
        selected = self.queue_tree.selection()
        if not selected:
            return None
        return self.queue_item_refs.get(str(selected[0]))

    def retry_selected_outbox(self) -> None:
        row = self._selected_queue_row()
        if not row:
            messagebox.showinfo(self._t("operations.select.title"), self._t("operations.select.body"))
            return
        uid = str(row.get("message_uid", ""))
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                self.mesh_clients[key].call({"command": "retry", "request_id": uid})
            else:
                self.ws_client.call({"command": "retry", "message_uid": uid})
            self.operations_result_label.configure(
                text=self._t("operations.action.retry_done", uid=uid)
            )
            self._refresh_queue_view(force=True)
        except Exception as exc:
            messagebox.showerror(self._t("operations.select.title"), str(exc))

    def pause_selected_outbox(self) -> None:
        row = self._selected_queue_row()
        if not row:
            messagebox.showinfo(self._t("operations.select.title"), self._t("operations.select.body"))
            return
        uid = str(row.get("message_uid", ""))
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                self.mesh_clients[key].call({"command": "pause", "request_id": uid})
            else:
                self.ws_client.call({"command": "pause", "message_uid": uid})
            self.operations_result_label.configure(
                text=self._t("operations.action.pause_done", uid=uid)
            )
            self._refresh_queue_view(force=True)
        except Exception as exc:
            messagebox.showerror(self._t("operations.select.title"), str(exc))

    def resume_selected_outbox(self) -> None:
        row = self._selected_queue_row()
        if not row:
            messagebox.showinfo(self._t("operations.select.title"), self._t("operations.select.body"))
            return
        uid = str(row.get("message_uid", ""))
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                self.mesh_clients[key].call({"command": "resume", "request_id": uid})
            else:
                self.ws_client.call({"command": "resume", "message_uid": uid})
            self.operations_result_label.configure(
                text=self._t("operations.action.resume_done", uid=uid)
            )
            self._refresh_queue_view(force=True)
        except Exception as exc:
            messagebox.showerror(self._t("operations.select.title"), str(exc))

    def renew_selected_outbox(self) -> None:
        row = self._selected_queue_row()
        if not row:
            messagebox.showinfo(self._t("operations.select.title"), self._t("operations.select.body"))
            return
        uid = str(row.get("message_uid", ""))
        if str(row.get("state", "")) != "expired_hold":
            messagebox.showinfo(
                self._t("operations.select.title"),
                self._t("operations.action.renew_only"),
                parent=self,
            )
            return
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                self.mesh_clients[key].call({"command": "renew", "request_id": uid})
            else:
                self.ws_client.call({"command": "renew", "message_uid": uid})
            self.operations_result_label.configure(
                text=self._t("operations.action.renew_done", uid=uid)
            )
            self._refresh_queue_view(force=True)
        except Exception as exc:
            messagebox.showerror(self._t("operations.select.title"), str(exc))

    def cancel_selected_outbox(self) -> None:
        row = self._selected_queue_row()
        if not row:
            messagebox.showinfo(self._t("operations.select.title"), self._t("operations.select.body"))
            return
        uid = str(row.get("message_uid", ""))
        if not messagebox.askyesno(
            self._t("operations.cancel.title"),
            self._t("operations.cancel.body"),
        ):
            return
        try:
            if row.get("_queue_source") == "gateway":
                key = str(row.get("_queue_key", ""))
                self.mesh_clients[key].call({"command": "cancel", "request_id": uid})
            else:
                self.ws_client.call({"command": "cancel", "message_uid": uid})
            self.operations_result_label.configure(
                text=self._t("operations.action.cancel_done", uid=uid)
            )
            self._refresh_queue_view(force=True)
        except Exception as exc:
            messagebox.showerror(self._t("operations.select.title"), str(exc))

    def run_database_maintenance(self) -> None:
        if getattr(self, "_maintenance_busy", False):
            return
        self._maintenance_busy = True
        self._maintenance_results = queue.Queue()
        self.operations_result_label.configure(text=self._t("operations.maintenance.running"))
        threading.Thread(target=self._database_maintenance_worker, daemon=True).start()
        self._maintenance_after_id = self.after(100, self._poll_database_maintenance)

    def _database_maintenance_worker(self) -> None:
        try:
            job = self.ws_client.call({"command": "maintenance_start"})["maintenance_job"]
            job_id = job["job_id"]
            while not getattr(self, "_gui_closing", False):
                if job.get("state") == "done":
                    self._maintenance_results.put(("done", job["result"]))
                    return
                if job.get("state") == "failed":
                    raise RuntimeError(job.get("error", "Maintenance failed"))
                if job.get("state") != "running":
                    raise RuntimeError("Unknown maintenance job state")
                time.sleep(1.0)
                job = self.ws_client.call({"command": "maintenance_status", "job_id": job_id})["maintenance_job"]
                if job.get("job_id") != job_id:
                    raise RuntimeError("Maintenance job no longer available")
        except Exception:
            self._maintenance_results.put(("unconfirmed", None))

    def _poll_database_maintenance(self) -> None:
        self._maintenance_after_id = None
        if getattr(self, "_gui_closing", False):
            return
        try:
            state, result = self._maintenance_results.get_nowait()
        except queue.Empty:
            self._maintenance_after_id = self.after(100, self._poll_database_maintenance)
            return
        self._maintenance_busy = False
        if state == "done":
            self.operations_result_label.configure(text=self._t(
                "operations.maintenance.done", integrity=result.get("integrity", "?"),
                control=result.get("removed_control", 0), expired=result.get("removed_expired", 0),
                fragments=result.get("removed_fragments", 0)))
            self._refresh_queue_view(force=True)
        else:
            self.operations_result_label.configure(text=self._t("operations.maintenance.unconfirmed"))
            messagebox.showwarning(self._t("operations.maintenance.error_title"),
                                   self._t("operations.maintenance.unconfirmed"))


    def export_diagnostics(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path_text = filedialog.asksaveasfilename(
            title=self._t("operations.diagnostics.save_title"),
            defaultextension=".zip",
            initialfile=f"gutochat-diagnostikk-{self._station_file_stem()}-{stamp}.zip",
            filetypes=[(self._t("operations.diagnostics.filetype"), "*.zip")],
        )
        if not path_text:
            return
        try:
            self.operations_result_label.configure(text=self._t("operations.diagnostics.collecting"))
            self.update_idletasks()
            result = write_bundle(Path(path_text), self.config, role=self.role)
            self.operations_result_label.configure(
                text=self._t("operations.diagnostics.saved", result=result)
            )
            messagebox.showinfo(
                self._t("operations.diagnostics.done_title"),
                self._t("operations.diagnostics.done_body", result=result),
            )
        except Exception as exc:
            messagebox.showerror(
                self._t("operations.diagnostics.done_title"),
                self._t("operations.diagnostics.error_body", error=exc),
            )

    def _schedule_refresh(self, delay_ms: int | None = None) -> None:
        """Schedule one refresh and replace any older scheduled refresh."""
        if self.refresh_after_id is not None:
            try:
                self.after_cancel(self.refresh_after_id)
            except tk.TclError:
                pass
            self.refresh_after_id = None
        delay = self.refresh_interval_ms if delay_ms is None else max(0, int(delay_ms))
        self.refresh_after_id = self.after(delay, self.refresh)

    def request_refresh(self) -> None:
        """Request one prompt refresh and debounce repeated button presses."""
        try:
            button = getattr(self, "refresh_button", None)
            if button is not None:
                button.configure(state="disabled", text=_text_for(self, "common.refreshing"))
                self.after(
                    1000,
                    lambda: button.configure(state="normal", text=_text_for(self, "action.refresh_now")),
                )
        except (tk.TclError, AttributeError):
            pass
        self._schedule_refresh(50)

    def _close(self) -> None:
        self._gui_closing = True
        maintenance_after_id = getattr(self, "_maintenance_after_id", None)
        if maintenance_after_id is not None:
            try:
                self.after_cancel(maintenance_after_id)
            except tk.TclError:
                pass
            self._maintenance_after_id = None
        if self.message_refresh_poll_after_id is not None:
            try:
                self.after_cancel(self.message_refresh_poll_after_id)
            except tk.TclError:
                pass
            self.message_refresh_poll_after_id = None
        if self.map_refresh_poll_after_id is not None:
            try:
                self.after_cancel(self.map_refresh_poll_after_id)
            except tk.TclError:
                pass
            self.map_refresh_poll_after_id = None
        if self.online_map_render_poll_after_id is not None:
            try:
                self.after_cancel(self.online_map_render_poll_after_id)
            except tk.TclError:
                pass
            self.online_map_render_poll_after_id = None
        if self.offline_map_redraw_after_id is not None:
            try:
                self.after_cancel(self.offline_map_redraw_after_id)
            except tk.TclError:
                pass
            self.offline_map_redraw_after_id = None
        if self.refresh_after_id is not None:
            try:
                self.after_cancel(self.refresh_after_id)
            except tk.TclError:
                pass
            self.refresh_after_id = None
        self.destroy()

    def _node_view_signature(self) -> tuple[Any, ...]:
        rows: list[tuple[Any, ...]] = []
        positions = self._position_index()
        now_epoch = int(time.time())
        stale_minutes = self.position_store.stale_minutes()
        for key in self.network_order:
            for node in self._sorted_nodes(key):
                node_id = str(node.get("id", node.get("num", "")))
                position_key = self._node_position_key(
                    key, node_id, node.get("num")
                )
                position = positions.get(position_key) if position_key else None
                _position_display, position_age, _position_state = (
                    self._position_display_fields(
                        position,
                        now_epoch=now_epoch,
                        stale_minutes=stale_minutes,
                    )
                )
                rows.append(
                    (
                        key,
                        node_id,
                        self.contacts.alias(key, node_id),
                        self.contacts.favorite(key, node_id),
                        str(node.get("long_name", "")),
                        str(node.get("short_name", "")),
                        self._format_node_time(node),
                        self._node_state(node, key),
                        int(position.get("revision", 0)) if position else 0,
                        int(position.get("position_epoch", 0)) if position else 0,
                        int(position.get("latitude_i", 0)) if position else 0,
                        int(position.get("longitude_i", 0)) if position else 0,
                        position.get("altitude") if position else None,
                        position_age,
                    )
                )
        return tuple(rows)

    def _capability_label(self, capability: str) -> str:
        return self._t(f"capability.{capability}")

    def _capability_summary(self) -> str:
        view = self.capability_view
        if not view["enforced"]:
            return self._t("system.detail.capabilities_legacy")
        enabled = set(view["enabled"])
        parts = [
            self._t(
                "system.detail.capability_item",
                name=self._capability_label(capability),
                state=self._t(
                    "system.detail.capability_enabled"
                    if capability in enabled
                    else "system.detail.capability_disabled"
                ),
            )
            for capability in CAPABILITY_ORDER
        ]
        blocked = len(self.capability_blocked_networks)
        if blocked:
            parts.append(self._t("system.detail.capability_blocked", count=blocked))
        return "  •  ".join(parts)

    def _remember_remote_base_verified_status(
        self, resource: str, status: dict[str, Any]
    ) -> None:
        state = str(status.get("state", "UNKNOWN_DEGRADED")).upper()
        if status.get("verified") is not True or state not in {"ON", "OFF"}:
            return
        if resource not in self.remote_base_last_verified_status:
            return
        self.remote_base_last_verified_status[resource] = {
            "state": state,
            "verified": True,
            "reason_code": str(status.get("reason_code", "")),
            "updated_mono": float(status.get("updated_mono", time.monotonic())),
            "request_id": str(status.get("request_id", "")),
        }

    def _remote_base_status_fresh(self, resource: str) -> dict[str, Any]:
        status = dict(self.remote_base_status.get(resource, {}))
        age = time.monotonic() - float(status.get("updated_mono", 0.0))
        if age > self.remote_base_status_ttl_seconds or status.get("verified") is not True:
            status.update({"state": "UNKNOWN_DEGRADED", "verified": False})
        return status

    def _remote_base_status_view(self, resource: str) -> dict[str, Any]:
        """Return presentation state without weakening the remote-write gate."""
        current = dict(self.remote_base_status.get(resource, {}))
        current_state = str(current.get("state", "UNKNOWN_DEGRADED")).upper()
        current_age = time.monotonic() - float(current.get("updated_mono", 0.0))
        if (
            current.get("verified") is True
            and current_state in {"ON", "OFF"}
            and current_age <= self.remote_base_status_ttl_seconds
        ):
            current.update({
                "state": current_state,
                "fresh": True,
                "stale": False,
                "age_seconds": max(0.0, current_age),
            })
            return current

        previous = dict(self.remote_base_last_verified_status.get(resource, {}))
        previous_state = str(previous.get("state", "UNKNOWN_DEGRADED")).upper()
        if previous.get("verified") is True and previous_state in {"ON", "OFF"}:
            previous_age = time.monotonic() - float(previous.get("updated_mono", 0.0))
            previous.update({
                "state": previous_state,
                "fresh": False,
                "stale": True,
                "age_seconds": max(0.0, previous_age),
            })
            return previous

        return {
            "state": "UNKNOWN_DEGRADED",
            "verified": False,
            "fresh": False,
            "stale": False,
            "age_seconds": None,
        }

    def _remote_map_publication_host_proxy_managed(
        self, status: dict[str, Any] | None = None
    ) -> bool:
        value = status if status is not None else self._remote_base_status_fresh("MAP_PUB")
        return host_proxy_managed(value)

    def _remote_base_status_refresh_enabled(self) -> bool:
        """Allow dedicated authenticated read-only Base status independently of write control."""
        if self.role != "field" or not self.remote_base_status_enabled:
            return False
        if self._remote_base_status_network() is None:
            return False
        return _status_auth_for(self).enabled

    def _remote_base_status_sequence_active(self) -> bool:
        return isinstance(self.remote_base_status_sequence, dict)

    def _fail_remote_base_status_sequence(self) -> None:
        sequence = self.remote_base_status_sequence
        self.remote_base_status_sequence = None
        if isinstance(sequence, dict):
            resources = ("MAP_PUB", "APRS_IS_UPLINK")
            index = max(0, min(int(sequence.get("index", 0)), len(resources) - 1))
            for resource in resources[index:]:
                self.remote_base_status[resource] = {
                    "state": "UNKNOWN_DEGRADED",
                    "verified": False,
                    "updated_mono": 0.0,
                }
        self._configure_remote_base_buttons()

    def _expire_remote_base_status_sequence(
        self, now: float | None = None
    ) -> None:
        sequence = self.remote_base_status_sequence
        if not isinstance(sequence, dict):
            return
        if sequence.get("phase") != "WAIT_RESPONSE":
            return
        current = time.monotonic() if now is None else float(now)
        started = float(sequence.get("started", current))
        if current - started <= self.remote_base_status_sequence_timeout_seconds:
            return
        self._fail_remote_base_status_sequence()

    def _continue_remote_base_status_sequence(
        self, completed_request_id: str
    ) -> None:
        sequence = self.remote_base_status_sequence
        if not isinstance(sequence, dict):
            return
        if sequence.get("phase") != "GUARD":
            return
        if str(sequence.get("request_id", "")) != str(completed_request_id):
            return

        remote = self._remote_base_status_network()
        if remote is None or not _status_auth_for(self).enabled:
            self._fail_remote_base_status_sequence()
            return

        route, network = remote
        if route != str(sequence.get("route", "")):
            self._fail_remote_base_status_sequence()
            return

        resource = "APRS_IS_UPLINK"
        request_id = uuid.uuid4().hex[:12]

        sequence.update({
            "phase": "WAIT_RESPONSE",
            "index": 1,
            "resource": resource,
            "request_id": request_id,
            "started": time.monotonic(),
        })

        try:
            message_uids = self._send_gateway_status_frame(
                network,
                encode_base_status_request(request_id, route, resource),
            )
            if not message_uids:
                raise RuntimeError("REMOTE_STATUS_REQUEST_NOT_QUEUED")
        except Exception:
            self._fail_remote_base_status_sequence()
            return

        self._configure_remote_base_buttons()

    def _handle_remote_base_status_sequence(
        self, control: dict[str, Any]
    ) -> None:
        sequence = self.remote_base_status_sequence
        if not isinstance(sequence, dict):
            return
        if sequence.get("phase") != "WAIT_RESPONSE":
            return

        resource = str(control.get("resource", ""))
        request_id = str(control.get("request_id", ""))

        if resource != str(sequence.get("resource", "")):
            return
        if request_id != str(sequence.get("request_id", "")):
            return

        # _process_controls has already required dedicated status authentication before
        # calling this helper.  A non-verified Base status never advances the
        # sequence.
        if control.get("verified") is not True:
            self._fail_remote_base_status_sequence()
            return

        if int(sequence.get("index", 0)) == 0 and resource == "MAP_PUB":
            sequence["phase"] = "GUARD"
            sequence["started"] = time.monotonic()
            self._configure_remote_base_buttons()
            self.after(
                self.remote_base_status_guard_ms,
                lambda rid=request_id:
                    self._continue_remote_base_status_sequence(rid),
            )
            return

        if int(sequence.get("index", 0)) == 1 and resource == "APRS_IS_UPLINK":
            self.remote_base_status_sequence = None
            self._configure_remote_base_buttons()

    def _configure_remote_base_buttons(self) -> None:
        if not hasattr(self, "remote_map_publication_button"):
            return
        control_enabled = self.remote_base_control_enabled and _control_auth_for(self).enabled
        status_refresh_enabled = self._remote_base_status_refresh_enabled()
        sequence_active = self._remote_base_status_sequence_active()
        if hasattr(self, "remote_base_status_button"):
            self.remote_base_status_button.configure(
                state="normal" if status_refresh_enabled and not sequence_active else "disabled"
            )
        map_status = self._remote_base_status_fresh("MAP_PUB")
        aprs_status = self._remote_base_status_fresh("APRS_IS_UPLINK")
        map_view = self._remote_base_status_view("MAP_PUB")
        aprs_view = self._remote_base_status_view("APRS_IS_UPLINK")
        map_button_enabled, map_action_key = map_action_policy(
            enabled=control_enabled,
            sequence_active=sequence_active,
            map_status=map_status,
            map_view=map_view,
        )
        self.remote_map_publication_button.configure(
            state="normal" if map_button_enabled else "disabled",
            text=self._t(map_action_key),
        )
        if control_enabled and not sequence_active and aprs_status.get("state") in {"ON", "OFF"}:
            self.remote_aprs_igate_button.configure(
                state="normal",
                text=self._t(
                    "system.aprs_igate.action.deactivate"
                    if aprs_status.get("state") == "ON"
                    else "system.aprs_igate.action.activate"
                ),
            )
        else:
            self.remote_aprs_igate_button.configure(
                state="disabled",
                text=self._t(
                    "system.aprs_igate.action.stale"
                    if control_enabled and not sequence_active and aprs_view.get("stale")
                    else "system.aprs_igate.action.safe_deactivate"
                ),
            )

    def request_remote_base_statuses(self, *, force: bool = False) -> None:
        if not self._remote_base_status_refresh_enabled():
            self._configure_remote_base_buttons()
            return
        if self._remote_base_status_sequence_active():
            self._configure_remote_base_buttons()
            return
        remote = self._remote_base_status_network()
        if remote is None or not _status_auth_for(self).enabled:
            self._configure_remote_base_buttons()
            return
        now = time.monotonic()
        if not force and now - self.last_remote_base_status_request < 10.0:
            return

        route, network = remote
        resource = "MAP_PUB"
        request_id = uuid.uuid4().hex[:12]

        for name in self.remote_base_status:
            self.remote_base_status[name] = {
                "state": "UNKNOWN_DEGRADED",
                "verified": False,
                "updated_mono": 0.0,
            }

        self.remote_base_status_sequence = {
            "phase": "WAIT_RESPONSE",
            "index": 0,
            "route": route,
            "resource": resource,
            "request_id": request_id,
            "started": now,
        }
        self._configure_remote_base_buttons()

        try:
            message_uids = self._send_gateway_status_frame(
                network,
                encode_base_status_request(request_id, route, resource),
            )
            if not message_uids:
                raise RuntimeError("REMOTE_STATUS_REQUEST_NOT_QUEUED")
            self.last_remote_base_status_request = now
        except Exception:
            self._fail_remote_base_status_sequence()

    def _remote_base_control_action(self, resource: str) -> None:
        resource = str(resource).upper()
        status = self._remote_base_status_fresh(resource)
        source = str(status.get("state", "UNKNOWN_DEGRADED"))
        if not self.remote_base_control_enabled or source not in {"ON", "OFF"}:
            return
        target = "OFF" if source == "ON" else "ON"
        if resource == "MAP_PUB":
            title = self._t(
                "system.map_publication.confirm.deactivate.title"
                if target == "OFF" else "system.map_publication.confirm.activate.title"
            )
            managed = self._remote_map_publication_host_proxy_managed(status)
            if managed:
                body = self._t(
                    "system.map_publication.confirm.host_proxy_deactivate.body"
                    if target == "OFF" else "system.map_publication.confirm.host_proxy_activate.body"
                )
            else:
                body = self._t(
                    "system.map_publication.confirm.deactivate.body"
                    if target == "OFF" else "system.map_publication.confirm.activate.body"
                )
            body += "\n\nUtføres på Base-stasjonen via verifisert fjernkontroll."
            if not messagebox.askyesno(title, body, parent=self, default=messagebox.NO):
                return
        elif target == "ON":
            if not messagebox.askyesno(
                self._t("system.aprs_igate.confirm.title"),
                self._t("system.aprs_igate.confirm.body") +
                "\n\nUtføres på Base-stasjonen via verifisert fjernkontroll.",
                parent=self, default=messagebox.NO,
            ):
                return
        remote = self._remote_base_network()
        if remote is None:
            return
        route, network = remote
        request_id = uuid.uuid4().hex
        try:
            self.remote_base_pending[request_id] = {
                "resource": resource, "source_state": source, "target_state": target,
                "started": time.monotonic(),
            }
            self._send_gateway_privileged_frame(
                network,
                encode_base_control_request(request_id, route, resource, source, target),
            )
            if resource == "MAP_PUB":
                self.remote_map_publication_button.configure(
                    state="disabled", text=self._t("system.map_publication.action.working")
                )
            else:
                self.remote_aprs_igate_button.configure(
                    state="disabled", text=self._t("system.aprs_igate.action.working")
                )
        except Exception:
            self.remote_base_pending.pop(request_id, None)
            self.request_remote_base_statuses(force=True)

    def _finish_remote_base_control(self, control: dict[str, Any]) -> None:
        resource = str(control.get("resource", ""))
        ok = bool(control.get("ok")) and bool(control.get("verified"))
        state = str(control.get("state", "UNKNOWN_DEGRADED"))
        reason = str(control.get("reason_code", ""))
        self._configure_remote_base_buttons()
        if ok:
            title = (self._t("system.map_publication.result.title") if resource == "MAP_PUB"
                     else self._t("system.aprs_igate.result.title"))
            messagebox.showinfo(title, f"Base-status verifisert: {state}", parent=self)
        else:
            title = (self._t("system.map_publication.result.title") if resource == "MAP_PUB"
                     else self._t("system.aprs_igate.result.title"))
            messagebox.showerror(title, f"Base-handlingen ble ikke verifisert ({reason}).", parent=self)
        self.request_remote_base_statuses(force=True)

    def _field_aprs_is_system_status(self) -> tuple[str, str]:
        """Read local direct APRS-IS operator state without creating control or doing I/O."""
        control = self.field_aprs_is_live_gui
        if control is None:
            return (
                self._t("system.field_aprs_is.state.off"),
                self._t("system.field_aprs_is.detail.off"),
            )

        snapshot = control.snapshot()
        state = str(snapshot.state).upper()
        if bool(snapshot.running) or state == "RUNNING":
            detail_key = (
                "system.field_aprs_is.detail.stopping"
                if bool(snapshot.stop_requested)
                else "system.field_aprs_is.detail.running"
            )
            return (self._t("system.field_aprs_is.state.running"), self._t(detail_key))
        if state == "ARMED":
            return (
                self._t("system.field_aprs_is.state.armed"),
                self._t("system.field_aprs_is.detail.armed"),
            )

        result = self.field_aprs_is_live_thread_result
        if result is not None and not bool(getattr(result, "success", False)):
            return (
                self._t("system.field_aprs_is.state.degraded"),
                self._t(
                    "system.field_aprs_is.detail.degraded",
                    error=str(getattr(result, "error", "")) or self._t("position.detail.unknown"),
                ),
            )
        if result is not None and bool(getattr(result, "success", False)):
            return (
                self._t("system.field_aprs_is.state.off"),
                self._t(
                    "system.field_aprs_is.detail.off_last_success",
                    packets=int(getattr(result, "packets_received", 0)),
                    positions=int(getattr(result, "positions_parsed", 0)),
                ),
            )
        return (
            self._t("system.field_aprs_is.state.off"),
            self._t("system.field_aprs_is.detail.off"),
        )

    def _system_rows(self) -> list[tuple[str, str, str]]:
        unknown = self._t("position.detail.unknown")
        rows: list[tuple[str, str, str]] = [
            (
                self._t("system.component.program"),
                "OK",
                self._t(
                    "system.detail.program",
                    version=APP_VERSION,
                    station=self._station_display_name(),
                ),
            ),
            (
                self._t("system.component.ws_radio"),
                (self._t("modular.not_configured") if not self.private_radio_enabled else ("OK" if self.ws_status.get("radio_online") else self._t("system.state.error"))),
                (self._t("modular.private_radio_detail") if not self.private_radio_enabled else self._t(
                    "system.detail.ws",
                    address=self.ws_status.get("address", self.local_address),
                    frequency=self.ws_status.get("frequency_mhz", "?"),
                    serial=self.ws_status.get("serial_port", "?"),
                )),
            ),
        ]
        if self.capability_view["enforced"]:
            rows.append(
                (
                    self._t("system.component.hardware_profile"),
                    "OK",
                    self._t(
                        "system.detail.hardware_profile",
                        profile=self.capability_view["profile_id"],
                        version=self.capability_view["profile_version"],
                        support=self.capability_view["support_class"],
                    ),
                )
            )
        rows.append(
            (
                self._t("system.component.capabilities"),
                "OK",
                self._capability_summary(),
            )
        )
        integrity = str(self.ws_status.get("database_integrity", unknown))
        integrity_checked_at = str(self.ws_status.get("database_integrity_checked_at", ""))
        integrity_current_session = self.ws_status.get("database_integrity_current_session", True)
        if integrity_checked_at and not integrity_current_session:
            integrity = integrity + " — " + self._t("system.database.previous_session")
        maintenance = str(self.ws_status.get("last_maintenance", ""))
        rows.append(
            (
                self._t("system.component.database"),
                "OK" if str(self.ws_status.get("database_integrity", "")).lower() == "ok" else self._t("system.state.check"),
                self._t(
                    "system.detail.database",
                    integrity=(integrity + " (" + self._t("system.database.checked_at", time=self._format_timestamp(integrity_checked_at)) + ")") if integrity_checked_at else integrity,
                    maintenance=(
                        self._format_timestamp(maintenance) if maintenance else unknown
                    ),
                ),
            )
        )
        position_status = self.position_store.aggregate_status()
        position_enabled = bool(position_status.get("storage_enabled"))
        rows.append(
            (
                self._t("system.component.position_storage"),
                "OK" if position_enabled else self._t("system.state.off"),
                self._t(
                    "system.detail.position",
                    state=self._t(
                        "system.detail.position.active"
                        if position_enabled
                        else "system.detail.position.inactive"
                    ),
                    latest=int(position_status.get("position_count", 0)),
                    history=int(position_status.get("history_count", 0)),
                    minutes=int(position_status.get("stale_minutes", 0)),
                ),
            )
        )
        for key in self.network_order:
            network = self.networks[key]
            if network["kind"] == "mesh_local":
                status = self.local_mesh_status.get(key, {})
                receive_state, receive_detail = receive_health_presentation(status, self._t)
                rows.append(
                    (
                        network["label"],
                        receive_state,
                        self._t(
                            "system.detail.mesh_local",
                            nodes=status.get("node_count", 0),
                            queue=status.get("gateway_store_forward_pending", 0),
                            version=status.get("service_version", "?"),
                            error=status.get("last_error", ""),
                        ) + " • " + receive_detail,
                    )
                )
            elif network["kind"] == "mesh_gateway":
                status = self.gateway_status.get(key, {})
                stale = self._gateway_is_stale(status)
                state = (
                    self._t("system.state.stale")
                    if stale
                    else ("OK" if status.get("online") else self._t("system.state.error"))
                )
                rows.append(
                    (
                        self._t("shell.status.gateway", network=network["label"], state="").rstrip(),
                        state,
                        self._t(
                            "system.detail.mesh_gateway",
                            nodes=status.get("node_count", "?"),
                            version=status.get("version", "?"),
                            last=self._format_timestamp(str(status.get("last_seen", ""))),
                            message_sync=self.message_store.message_sync_cursor(key),
                            position_sync=self.position_store.history_sync_cursor(key),
                            stale_note=(
                                self._t("system.detail.mesh_gateway_stale") if stale else ""
                            ),
                            error=status.get("error", ""),
                        ) + " • " + self._t("mesh.receive.remote"),
                    )
                )
        if self.role == "field":
            direct_aprs_state, direct_aprs_detail = self._field_aprs_is_system_status()
            rows.append((
                self._t("system.component.field_direct_aprs_is"),
                direct_aprs_state,
                direct_aprs_detail,
            ))
            map_remote = self._remote_base_status_view("MAP_PUB")
            aprs_remote = self._remote_base_status_view("APRS_IS_UPLINK")

            def remote_detail(status: dict[str, Any], resource: str) -> str:
                return self._t(remote_detail_key(status, resource))

            rows.append((
                self._t("system.component.map_publication") + " (Base)",
                str(map_remote.get("state", "UNKNOWN_DEGRADED")),
                remote_detail(map_remote, "MAP_PUB"),
            ))
            rows.append((
                self._t("system.component.aprs_igate") + " (Base)",
                str(aprs_remote.get("state", "UNKNOWN_DEGRADED")),
                remote_detail(aprs_remote, "APRS_IS_UPLINK"),
            ))
            self._configure_remote_base_buttons()
        return rows

    def _fetch_visible_history(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Fetch enough filtered carrier pages for the configured history.

        The common case needs one page of 250 rows. Extra pages are requested
        only when LC3 fragmentation means those rows collapse into fewer than
        250 logical messages.
        """
        page_size = self.message_list_limit
        before_id: int | None = None
        carrier_rows: list[dict[str, Any]] = []
        logical_messages: list[dict[str, Any]] = []
        visible: list[dict[str, Any]] = []

        for _ in range(self.max_fragments + 1):
            request: dict[str, Any] = {
                "command": "list_display",
                "limit": page_size,
            }
            if before_id is not None:
                request["before_id"] = before_id
            page = self.ws_client.call(
                request, timeout=self.message_history_timeout_seconds
            )["messages"]
            if not page:
                break

            carrier_rows = list(page) + carrier_rows
            logical_messages = self._logical_control_rows(carrier_rows)
            visible = self._virtual_messages(logical_messages)
            if len(visible) >= self.message_list_limit:
                break

            ids = [int(row["id"]) for row in page if row.get("id") is not None]
            if not ids or len(page) < page_size:
                break
            before_id = min(ids)

        return logical_messages, visible[-self.message_list_limit :]

    def _active_tab_is(self, tab: Any) -> bool:
        """Return whether *tab* is selected without performing any I/O."""
        try:
            return self.notebook.select() == str(tab)
        except (AttributeError, tk.TclError):
            return False

    def _on_notebook_tab_changed(self, _event: Any = None) -> None:
        """Paint the selected tab before starting any potentially slow refresh."""
        if self._active_tab_is(self.messages_tab):
            self._start_message_history_refresh(force=True)
        if self._active_tab_is(self.map_tab):
            self._start_map_refresh(force=False)
        if self._active_tab_is(self.online_map_tab):
            # Local/read-only refresh only; selecting the tab never fetches OSM.
            self._refresh_online_map_rows()
        # A short grace interval lets ttk.Notebook paint the new page before
        # status/control refresh work resumes. This changes scheduling only.
        self._schedule_refresh(75)

    def _message_history_refresh_due(
        self, *, force: bool = False, now: float | None = None
    ) -> bool:
        if force:
            return True
        current = time.monotonic() if now is None else float(now)
        interval = (
            self.message_refresh_active_seconds
            if self._active_tab_is(self.messages_tab)
            else self.message_refresh_inactive_seconds
        )
        return current - self.last_message_history_refresh_started >= interval

    def _start_message_history_refresh(self, *, force: bool = False) -> None:
        """Start at most one background visible-history read.

        ApiClient.call opens one socket per request, so the worker shares no
        persistent socket with Tk. The worker only computes Python data; all
        widget/store mutation remains on Tk's main thread.
        """
        if self._gui_closing or not self._message_history_refresh_due(force=force):
            return
        if self.message_refresh_running:
            self.message_refresh_pending = self.message_refresh_pending or force
            return
        self.message_refresh_running = True
        self.message_refresh_pending = False
        self.message_refresh_generation += 1
        generation = self.message_refresh_generation
        self.last_message_history_refresh_started = time.monotonic()
        threading.Thread(
            target=self._message_history_refresh_worker,
            args=(generation,),
            name="message-history-refresh",
            daemon=True,
        ).start()

    def _message_history_refresh_worker(self, generation: int) -> None:
        try:
            logical_messages, visible = self._fetch_visible_history()
            result: dict[str, Any] = {
                "generation": generation,
                "ok": True,
                "logical_messages": logical_messages,
                "visible": visible,
            }
        except Exception as exc:
            result = {
                "generation": generation,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        self.message_refresh_queue.put(result)

    def _apply_message_history_snapshot(
        self,
        logical_messages: list[dict[str, Any]],
        visible: list[dict[str, Any]],
    ) -> None:
        """Apply one worker result on Tk's main thread."""
        self.last_messages = logical_messages
        self.recent_message_rows = list(visible)
        signature = self._message_signature(visible)
        if signature == self.last_signature:
            return

        self.all_message_rows_cache = None
        self.all_message_rows_cache_signature = None
        # Keep background history fresh even when another tab is selected, but
        # defer Tree/Text rendering until Messages is actually visible.
        if not self._active_tab_is(self.messages_tab):
            return

        if not self._message_filters_active():
            self._render_messages(visible)
            self.message_filter_result_label.configure(
                text=self._t("messages.result.recent", count=len(visible))
            )
        else:
            try:
                recent_ids = {
                    self._message_row_identity(row) for row in visible
                }
                retained = [
                    row
                    for row in self.visible_message_rows
                    if self._message_row_identity(row) not in recent_ids
                ]
                recent_filtered = self._filter_message_rows(visible)
                merged = retained + recent_filtered
                deduplicated: dict[tuple[Any, ...], dict[str, Any]] = {}
                for row in merged:
                    deduplicated[self._message_row_identity(row)] = row
                refreshed = sorted(
                    deduplicated.values(), key=self._message_order_key
                )
                self._render_messages(refreshed)
                self.message_filter_result_label.configure(
                    text=self._t("messages.result.auto", count=len(refreshed))
                )
            except Exception as exc:
                self.message_filter_result_label.configure(
                    text=self._t("messages.result.auto_error", error=exc)
                )
        self.last_signature = signature

    def _poll_message_refresh_results(self) -> None:
        """Drain completed worker reads from Tk's event loop."""
        if self._gui_closing:
            return
        while True:
            try:
                result = self.message_refresh_queue.get_nowait()
            except queue.Empty:
                break
            self.message_refresh_running = False
            if result.get("ok"):
                self._apply_message_history_snapshot(
                    list(result.get("logical_messages", [])),
                    list(result.get("visible", [])),
                )
            else:
                # The local radio status is maintained by the short synchronous
                # status probe. A history refresh failure must not claim that the
                # radio service itself is unavailable.
                status_text = self._t("shell.refresh_degraded")
                footer_text = str(result.get("error", "GUI refresh failed"))
                if status_text != self.last_status_text:
                    self.status_label.configure(text=status_text)
                    self.last_status_text = status_text
                if footer_text != self.last_footer_text:
                    self.footer_label.configure(text=footer_text)
                    self.last_footer_text = footer_text
            if self.message_refresh_pending:
                self.message_refresh_pending = False
                self._start_message_history_refresh(force=True)
        self.message_refresh_poll_after_id = self.after(
            25, self._poll_message_refresh_results
        )

    def refresh(self) -> None:
        # R2 keeps slow message-history I/O off Tk's main loop. Field retains
        # its explicit-only Base status/control policy and all parity semantics.
        self.refresh_after_id = None
        if self.refresh_running:
            self._schedule_refresh()
            return
        self.refresh_running = True
        local_service_verified = False
        try:
            self.ws_status = self.ws_client.call({"command": "status"})["status"]
            local_service_verified = True
            control_rows = self.ws_client.call(
                {"command": "list_controls", "limit": 500}
            )["messages"]
            logical_controls = self._logical_control_rows(control_rows)
            self._process_controls(logical_controls)
            self._expire_remote_base_status_sequence()
            self._start_message_history_refresh()

            now = time.monotonic()
            if now - self.last_local_node_refresh > 15:
                self._refresh_local_mesh_nodes()
                self._refresh_recipient_combo()
                self.last_local_node_refresh = now
            if now - self.last_gateway_request > 300:
                self.request_all_nodes()
            if now - self.last_message_sync_request > self.message_sync_interval:
                self.request_all_messages()
                self.request_all_aprs()
            # Remote Base status remains explicit-only. R2 does not add RF
            # polling or alter the remote control authorization model.

            if self._active_tab_is(self.operations_tab):
                self._refresh_queue_view()

            if self._active_tab_is(self.nodes_tab):
                node_signature = self._node_view_signature()
                if node_signature != self.last_node_signature:
                    self._refresh_node_tree()
                    self.last_node_signature = node_signature

            if self._active_tab_is(self.position_history_tab):
                self._refresh_position_history_view()
            if self._active_tab_is(self.map_tab):
                self._start_map_refresh()

            if self._active_tab_is(self.system_tab):
                system_rows = self._system_rows()
                system_signature = tuple(system_rows)
                if system_signature != self.last_system_signature:
                    self._update_system_tree(system_rows)
                    self.last_system_signature = system_signature

            status_parts = [
                (self._t("modular.core_ready") if not self.private_radio_enabled else self._t(
                    "shell.status.ws_ok"
                    if self.ws_status.get("radio_online")
                    else "shell.status.ws_offline"
                ))
            ]
            for key in self.network_order:
                network = self.networks[key]
                if network["kind"] == "mesh_local":
                    online = self.local_mesh_status.get(key, {}).get("online")
                    status_parts.append(
                        self._t(
                            "shell.status.network_ok"
                            if online
                            else "shell.status.network_offline",
                            network=network["label"],
                        )
                    )
                elif network["kind"] == "mesh_gateway":
                    gateway = self.gateway_status.get(key, {})
                    if self._gateway_is_stale(gateway):
                        text = self._t(
                            "shell.status.gateway_stale"
                            if gateway
                            else "shell.status.gateway_waiting"
                        )
                    else:
                        text = self._t(
                            "shell.status.gateway_ok"
                            if gateway.get("online")
                            else "shell.status.gateway_offline"
                        )
                    status_parts.append(
                        self._t(
                            "shell.status.gateway",
                            network=network["label"],
                            state=text,
                        )
                    )
            status_text = "● " + " | ".join(status_parts)
            if status_text != self.last_status_text:
                self.status_label.configure(text=status_text)
                self.last_status_text = status_text

            footer_text = self._t(
                "shell.footer",
                serial=self.ws_status.get("serial_port", "?"),
                acks=self.ws_status.get("pending_acks", 0),
                outbox=self.ws_status.get(
                    "outbox_pending", self.ws_status.get("queue_size", 0)
                ),
                nodes=sum(len(v) for v in self.node_cache.values()),
            )
            if not self.private_radio_enabled:
                footer_text = self._t("modular.core_footer", nodes=sum(len(v) for v in self.node_cache.values()))
            if footer_text != self.last_footer_text:
                self.footer_label.configure(text=footer_text)
                self.last_footer_text = footer_text
        except Exception as exc:
            status_text = self._t(
                "shell.refresh_degraded"
                if local_service_verified
                else "shell.local_unavailable"
            )
            footer_text = str(exc)
            if status_text != self.last_status_text:
                self.status_label.configure(text=status_text)
                self.last_status_text = status_text
            if footer_text != self.last_footer_text:
                self.footer_label.configure(text=footer_text)
                self.last_footer_text = footer_text
        finally:
            self.refresh_running = False
            self._schedule_refresh()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    from hardware_profile_runtime import load_runtime_config

    config = load_runtime_config(Path(args.config))
    from field_base_parity_policy import apply_field_base_parity_policy
    config = apply_field_base_parity_policy(config)
    from installer_client import connect_installer

    coordinator = connect_installer(Path(args.config))
    LoRaChatApp(config, setup_coordinator=coordinator).mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
