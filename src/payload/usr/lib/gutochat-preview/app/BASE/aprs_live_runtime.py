#!/usr/bin/env python3
"""Hardened optional APRS-IS receive-only lifecycle for GuToMap.

APRS integration is deliberately isolated from GuToChat/Meshtastic:
- disabled unless explicitly enabled;
- live ingest requires a separate APRS SQLite database;
- receive-only APRS-IS semantics (pass -1, no APRS transmit API);
- bounded sessions with optional continuous reconnect;
- exponential reconnect backoff that is interruptible by shutdown;
- network/APRS failures are contained inside the APRS worker thread;
- diagnostics contain counters/state only, never raw APRS packets, comments,
  login identities, filters or server response payloads;
- the worker never calls Tk or any radio/gateway service.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import logging
import os
from pathlib import Path
import threading
import time
from typing import Callable

from aprs_a2_runtime_bridge import A2SingleWriterBridge
from aprs_is_client import AprsIsClient, AprsIsConfig, AprsIsIngestStats, Connector
from aprs_ingest_owner import AprsIngestOwner, default_ingest_lock_path
from aprs_parser import AprsParseError, parse_tnc2_line
from aprs_store import AprsStore


LOGGER = logging.getLogger("gutochat.aprs.live")
LOGGER.addHandler(logging.NullHandler())


@dataclass(frozen=True)
class AprsLiveRuntimeConfig:
    database_path: Path
    login: str
    latitude: float
    longitude: float
    radius_km: float = 200.0
    host: str = "euro.aprs2.net"
    port: int = 14580
    max_packets: int = 100
    max_seconds: float = 120.0
    continuous: bool = False
    reconnect_initial_seconds: float = 1.0
    reconnect_max_seconds: float = 60.0
    successful_reconnect_delay_seconds: float = 1.0
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 1.0
    shutdown_timeout_seconds: float = 5.0
    ownership_lock_path: Path | None = None
    owner_role: str = "gui"
    aprs_is_receive_enabled: bool = True

    def __post_init__(self) -> None:
        db = Path(self.database_path).expanduser()
        if not db.is_absolute():
            raise ValueError("APRS live database path must be absolute")
        max_packets = int(self.max_packets)
        max_seconds = float(self.max_seconds)
        if not 1 <= max_packets <= 10_000:
            raise ValueError("APRS live max_packets must be within 1..10000")
        if not 1.0 <= max_seconds <= 3600.0:
            raise ValueError("APRS live max_seconds must be within 1..3600")
        reconnect_initial = float(self.reconnect_initial_seconds)
        reconnect_max = float(self.reconnect_max_seconds)
        reconnect_success = float(self.successful_reconnect_delay_seconds)
        connect_timeout = float(self.connect_timeout_seconds)
        read_timeout = float(self.read_timeout_seconds)
        shutdown_timeout = float(self.shutdown_timeout_seconds)
        if not 0.05 <= reconnect_initial <= 300.0:
            raise ValueError(
                "APRS reconnect initial delay must be within 0.05..300 seconds"
            )
        if not reconnect_initial <= reconnect_max <= 3600.0:
            raise ValueError(
                "APRS reconnect max delay must be >= initial and <=3600 seconds"
            )
        if not 0.0 <= reconnect_success <= 60.0:
            raise ValueError(
                "APRS successful reconnect delay must be within 0..60 seconds"
            )
        if not 0.1 <= connect_timeout <= 30.0:
            raise ValueError("APRS connect timeout must be within 0.1..30 seconds")
        if not 1.0 <= read_timeout <= 30.0:
            raise ValueError("APRS read timeout must be within 1..30 seconds")
        if not 0.1 <= shutdown_timeout <= 30.0:
            raise ValueError("APRS shutdown timeout must be within 0.1..30 seconds")

        object.__setattr__(self, "database_path", db.resolve())
        object.__setattr__(self, "max_packets", max_packets)
        object.__setattr__(self, "max_seconds", max_seconds)
        object.__setattr__(self, "continuous", bool(self.continuous))
        object.__setattr__(self, "reconnect_initial_seconds", reconnect_initial)
        object.__setattr__(self, "reconnect_max_seconds", reconnect_max)
        object.__setattr__(self, "successful_reconnect_delay_seconds", reconnect_success)
        object.__setattr__(self, "connect_timeout_seconds", connect_timeout)
        object.__setattr__(self, "read_timeout_seconds", read_timeout)
        object.__setattr__(self, "shutdown_timeout_seconds", shutdown_timeout)
        lock_path = self.ownership_lock_path
        if lock_path is None:
            lock_path = default_ingest_lock_path(db)
        else:
            lock_path = Path(lock_path).expanduser()
            if not lock_path.is_absolute():
                raise ValueError("APRS ingest lock path must be absolute")
            lock_path = Path(os.path.abspath(lock_path))
        owner_role = str(self.owner_role).strip().lower()
        if owner_role not in {"gui", "headless", "test"}:
            raise ValueError("Invalid APRS ingest owner role")
        object.__setattr__(self, "ownership_lock_path", lock_path)
        object.__setattr__(self, "owner_role", owner_role)
        object.__setattr__(self, "aprs_is_receive_enabled", bool(self.aprs_is_receive_enabled))

    def aprs_is_config(self) -> AprsIsConfig:
        return AprsIsConfig.for_range(
            login=self.login,
            latitude=self.latitude,
            longitude=self.longitude,
            radius_km=self.radius_km,
            host=self.host,
            port=self.port,
            software_version="2.5.0-beta4-A1H1",
            connect_timeout_seconds=self.connect_timeout_seconds,
            read_timeout_seconds=self.read_timeout_seconds,
        )


@dataclass(frozen=True)
class AprsLiveRuntimeSnapshot:
    state: str
    error: str
    stats: dict[str, object]
    diagnostics: dict[str, object]


_STATS_COUNTER_FIELDS = tuple(
    field.name
    for field in fields(AprsIsIngestStats)
    if field.name
    not in {
        "server_identification",
        "login_response",
        "packet_limit_reached",
        "time_limit_reached",
        "elapsed_seconds",
        "stop_requested",
        "peer_eof",
    }
)


def _empty_diagnostic_stats() -> dict[str, object]:
    stats: dict[str, object] = {name: 0 for name in _STATS_COUNTER_FIELDS}
    stats.update(
        {
            "packet_limit_reached": False,
            "time_limit_reached": False,
            "peer_eof": False,
            "stop_requested": False,
            "elapsed_seconds": 0.0,
            "server_identification_seen": False,
            "login_acknowledged": False,
        }
    )
    return stats


def _diagnostic_stats(stats: AprsIsIngestStats) -> dict[str, object]:
    """Return privacy-safe counters without raw server/login text."""
    result = {name: int(getattr(stats, name)) for name in _STATS_COUNTER_FIELDS}
    result.update(
        {
            "packet_limit_reached": bool(stats.packet_limit_reached),
            "time_limit_reached": bool(stats.time_limit_reached),
            "peer_eof": bool(getattr(stats, "peer_eof", False)),
            "stop_requested": bool(stats.stop_requested),
            "elapsed_seconds": float(stats.elapsed_seconds),
            "server_identification_seen": bool(stats.server_identification),
            "login_acknowledged": bool(stats.login_response),
        }
    )
    return result


def _safe_error_code(exc: BaseException) -> str:
    """Return an error code that cannot leak packet/config/path contents."""
    name = type(exc).__name__
    errno = getattr(exc, "errno", None)
    if isinstance(errno, int):
        return f"{name}:errno={errno}"
    return name


def _same_file_or_path(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        if first.exists() and second.exists():
            return os.path.samefile(first, second)
    except OSError:
        pass
    return False


class AprsLiveRuntime:
    """Run bounded or reconnecting APRS-IS ingest in one isolated worker."""

    def __init__(
        self,
        config: AprsLiveRuntimeConfig,
        *,
        connector: Connector | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._connector = connector
        self._clock = clock
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._state = "idle"
        self._error = ""
        self._stats = _empty_diagnostic_stats()
        self._session_count = 0
        self._reconnect_count = 0
        self._session_failures = 0
        self._connection_failures = 0
        self._consecutive_failures = 0
        self._current_backoff_seconds = 0.0
        self._last_success_epoch: float | None = None
        self._last_packet_epoch: float | None = None
        self._shutdown_clean = True
        self._ownership: AprsIngestOwner | None = None
        self._a2_bridge = A2SingleWriterBridge()

    @property
    def running(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def _set_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    def snapshot(self) -> AprsLiveRuntimeSnapshot:
        with self._lock:
            return AprsLiveRuntimeSnapshot(
                state=self._state,
                error=self._error,
                stats=dict(self._stats),
                diagnostics={
                    "continuous": bool(self.config.continuous),
                    "session_count": int(self._session_count),
                    "reconnect_count": int(self._reconnect_count),
                    "session_failures": int(self._session_failures),
                    "connection_failures": int(self._connection_failures),
                    "consecutive_failures": int(self._consecutive_failures),
                    "current_backoff_seconds": float(self._current_backoff_seconds),
                    "last_success_epoch": self._last_success_epoch,
                    "last_packet_epoch": self._last_packet_epoch,
                    "shutdown_clean": bool(self._shutdown_clean),
                    "owner_role": self.config.owner_role,
                    "ownership_active": bool(self._ownership is not None and self._ownership.active),
                    "receive_only": True,
                    "aprs_is_receive_enabled": bool(self.config.aprs_is_receive_enabled),
                    "aprs_transmit": False,
                    "cross_network_routing": False,
                },
            )

    def start(self) -> None:
        if self.running:
            raise RuntimeError("APRS live runtime is already running")
        ownership = AprsIngestOwner(
            self.config.ownership_lock_path,
            role=self.config.owner_role,
        )
        ownership.acquire()
        self._ownership = ownership
        self._stop_event.clear()
        with self._lock:
            self._state = "starting"
            self._error = ""
            self._stats = _empty_diagnostic_stats()
            self._session_count = 0
            self._reconnect_count = 0
            self._session_failures = 0
            self._connection_failures = 0
            self._consecutive_failures = 0
            self._current_backoff_seconds = 0.0
            self._last_success_epoch = None
            self._last_packet_epoch = None
            self._shutdown_clean = True
        thread = threading.Thread(
            target=self._worker,
            name="gutochat-aprs-live",
            daemon=True,
        )
        self._thread = thread
        try:
            thread.start()
        except Exception:
            self._thread = None
            self._release_ownership()
            raise

    def stop(self, *, join_timeout: float | None = None) -> bool:
        self._stop_event.set()
        self._a2_bridge.cancel_pending()
        thread = self._thread
        if thread is None:
            return True
        timeout = (
            self.config.shutdown_timeout_seconds
            if join_timeout is None
            else max(0.0, float(join_timeout))
        )
        thread.join(timeout=timeout)
        clean = not thread.is_alive()
        with self._lock:
            self._shutdown_clean = clean
            if not clean:
                self._state = "shutdown_timeout"
                self._error = "shutdown_timeout"
        if not clean:
            LOGGER.warning("event=shutdown_timeout")
        return clean

    def _on_packet(self, _line: str) -> None:
        # The raw line is intentionally ignored. Diagnostics retain time only.
        with self._lock:
            self._last_packet_epoch = float(self._clock())

    def submit_a2_event(
        self,
        event: dict[str, object],
        receiver_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        """Queue one A2 event without allowing the submitter to own SQLite."""
        if not self.running:
            return {
                "persisted": False,
                "bridge_result": "runtime_not_running",
            }
        return self._a2_bridge.submit(
            event,
            receiver_id,
            timeout_seconds=timeout_seconds,
        )

    @staticmethod
    def _persist_a2_event(
        store: AprsStore,
        event: dict[str, object],
        receiver_id: str,
    ) -> dict[str, object]:
        """Persist receipt first, then the APRS domain observation."""
        if not str(receiver_id).strip():
            return {
                "persisted": False,
                "bridge_result": "invalid_receiver",
            }

        if (
            event.get("schema") != "gutchat.aprs.rx.v1"
            or event.get("network") != "classic_aprs_rf"
            or event.get("direction") != "rx"
        ):
            return {
                "persisted": False,
                "bridge_result": "invalid_event_contract",
            }

        raw_tnc2 = event.get("raw_tnc2")
        received_at = event.get("received_at")

        if not isinstance(raw_tnc2, str) or not isinstance(received_at, str):
            return {
                "persisted": False,
                "bridge_result": "invalid_event_payload",
            }

        try:
            receipt = store.begin_a2_receipt(
                event,
                receiver_id,
            )
        except (TypeError, ValueError):
            return {
                "persisted": False,
                "bridge_result": "receipt_error",
            }
        except Exception:
            return {
                "persisted": False,
                "bridge_result": "receipt_store_error",
            }

        receipt_key = str(
            receipt.get("receipt_key", "")
        )
        receipt_store_result = str(
            receipt.get("receipt_store_result", "")
        )
        processing_state = str(
            receipt.get("processing_state", "")
        )

        if processing_state == "domain_persisted":
            cached_domain = receipt.get(
                "domain_store_result"
            )
            cached_observation = receipt.get(
                "observation_key"
            )

            if (
                cached_domain
                not in {
                    "created",
                    "updated",
                    "duplicate",
                    "older",
                }
                or not isinstance(cached_observation, str)
                or not cached_observation
            ):
                return {
                    "persisted": False,
                    "bridge_result": "receipt_state_error",
                    "receipt_store_result": receipt_store_result,
                }

            return {
                "persisted": True,
                "bridge_result": "persisted",
                "receipt_store_result": receipt_store_result,
                "domain_store_result": cached_domain,
                # Legacy internal B1.2b result: exact replay is duplicate.
                "store_result": "duplicate",
                "observation_key": cached_observation,
            }

        if processing_state == "domain_rejected":
            cached_domain = receipt.get(
                "domain_store_result"
            )
            cached_error = str(
                receipt.get("last_error_code", "")
                or "not_persisted"
            )

            result: dict[str, object] = {
                "persisted": False,
                "bridge_result": cached_error,
                "receipt_store_result": receipt_store_result,
            }

            if isinstance(cached_domain, str) and cached_domain:
                result["domain_store_result"] = cached_domain
                result["store_result"] = cached_domain

            cached_observation = receipt.get(
                "observation_key"
            )
            if isinstance(cached_observation, str) and cached_observation:
                result["observation_key"] = cached_observation

            return result

        if processing_state != "received":
            return {
                "persisted": False,
                "bridge_result": "receipt_state_error",
                "receipt_store_result": receipt_store_result,
            }

        try:
            packet = parse_tnc2_line(
                raw_tnc2,
                source_type="local_rf",
                transport="vhf_ax25",
                source_gateway="",
                received_at=received_at,
            )
        except (AprsParseError, TypeError, ValueError):
            try:
                store.finalize_a2_receipt(
                    receipt_key,
                    processing_state="domain_rejected",
                    observation_key=None,
                    domain_store_result=None,
                    last_error_code="parse_error",
                )
            except Exception:
                return {
                    "persisted": False,
                    "bridge_result": "receipt_finalize_error",
                    "receipt_store_result": receipt_store_result,
                }

            return {
                "persisted": False,
                "bridge_result": "parse_error",
                "receipt_store_result": receipt_store_result,
            }

        try:
            store_result = store.store_packet(packet)
        except Exception:
            # Receipt remains durable in "received" and is retryable.
            return {
                "persisted": False,
                "bridge_result": "store_error",
                "receipt_store_result": receipt_store_result,
                "observation_key": packet.observation_key,
            }

        persisted = store_result in {
            "created",
            "updated",
            "duplicate",
            "older",
        }

        if not persisted:
            try:
                store.finalize_a2_receipt(
                    receipt_key,
                    processing_state="domain_rejected",
                    observation_key=packet.observation_key,
                    domain_store_result=store_result,
                    last_error_code="not_persisted",
                )
            except Exception:
                return {
                    "persisted": False,
                    "bridge_result": "receipt_finalize_error",
                    "receipt_store_result": receipt_store_result,
                    "store_result": store_result,
                    "domain_store_result": store_result,
                    "observation_key": packet.observation_key,
                }

            return {
                "persisted": False,
                "bridge_result": "not_persisted",
                "receipt_store_result": receipt_store_result,
                "store_result": store_result,
                "domain_store_result": store_result,
                "observation_key": packet.observation_key,
            }

        try:
            store.finalize_a2_receipt(
                receipt_key,
                processing_state="domain_persisted",
                observation_key=packet.observation_key,
                domain_store_result=store_result,
                last_error_code="",
            )
        except Exception:
            # Domain write may already be durable.  Replay is safe because
            # store_packet() is idempotent on observation_key.
            return {
                "persisted": False,
                "bridge_result": "receipt_finalize_error",
                "receipt_store_result": receipt_store_result,
                "store_result": store_result,
                "domain_store_result": store_result,
                "observation_key": packet.observation_key,
            }

        return {
            "persisted": True,
            "bridge_result": "persisted",
            "receipt_store_result": receipt_store_result,
            "store_result": store_result,
            "domain_store_result": store_result,
            "observation_key": packet.observation_key,
        }

    def _service_a2_bridge(self, store: AprsStore) -> bool:
        return self._a2_bridge.service_one(
            lambda event, receiver_id: self._persist_a2_event(
                store,
                event,
                receiver_id,
            )
        )

    def _worker_stop_requested(self, store: AprsStore) -> bool:
        self._service_a2_bridge(store)
        return self._stop_event.is_set()

    def _merge_session_stats(self, session: AprsIsIngestStats) -> None:
        safe = _diagnostic_stats(session)
        with self._lock:
            for name in _STATS_COUNTER_FIELDS:
                self._stats[name] = int(self._stats.get(name, 0)) + int(safe[name])
            self._stats["packet_limit_reached"] = bool(safe["packet_limit_reached"])
            self._stats["time_limit_reached"] = bool(safe["time_limit_reached"])
            self._stats["peer_eof"] = bool(safe["peer_eof"])
            self._stats["stop_requested"] = bool(safe["stop_requested"])
            self._stats["elapsed_seconds"] = float(
                self._stats.get("elapsed_seconds", 0.0)
            ) + float(safe["elapsed_seconds"])
            self._stats["server_identification_seen"] = bool(
                self._stats.get("server_identification_seen", False)
                or safe["server_identification_seen"]
            )
            self._stats["login_acknowledged"] = bool(
                self._stats.get("login_acknowledged", False)
                or safe["login_acknowledged"]
            )

    def _wait_for_reconnect(
        self,
        seconds: float,
        *,
        failure: bool,
        worker_poll: Callable[[], None] | None = None,
    ) -> bool:
        delay = max(0.0, float(seconds))
        with self._lock:
            self._state = "backoff" if failure else "reconnect_wait"
            self._current_backoff_seconds = delay
        LOGGER.info(
            "event=%s delay_seconds=%.3f",
            "reconnect_backoff" if failure else "session_rotate_wait",
            delay,
        )

        if worker_poll is None:
            stopped = self._stop_event.wait(delay)
        else:
            deadline = time.monotonic() + delay
            stopped = False
            while not self._stop_event.is_set():
                worker_poll()
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    break
                if self._stop_event.wait(min(0.05, remaining)):
                    stopped = True
                    break
            if self._stop_event.is_set():
                stopped = True

        with self._lock:
            self._current_backoff_seconds = 0.0
        return stopped

    def _release_ownership(self) -> None:
        ownership = self._ownership
        self._ownership = None
        if ownership is not None:
            ownership.release()

    def _worker(self) -> None:
        try:
            self._worker_main()
        finally:
            self._a2_bridge.cancel_pending()
            self._release_ownership()

    def _worker_main(self) -> None:
        try:
            store = AprsStore(self.config.database_path)
        except Exception as exc:
            with self._lock:
                self._state = "error"
                self._error = _safe_error_code(exc)
            LOGGER.warning("event=storage_init_failure code=%s", _safe_error_code(exc))
            return

        failure_backoff = self.config.reconnect_initial_seconds

        if not self.config.aprs_is_receive_enabled:
            with self._lock:
                self._state = "running_local_rf_only"
                self._error = ""
                self._current_backoff_seconds = 0.0
            LOGGER.info("event=aprs_is_receive_disabled_local_rf_only")
            while not self._stop_event.wait(0.05):
                self._service_a2_bridge(store)
            # Drain at most one already-queued A2 item before clean shutdown.
            self._service_a2_bridge(store)
            with self._lock:
                self._state = "stopped"
                self._error = ""
                self._stats["stop_requested"] = True
            return

        while not self._stop_event.is_set():
            with self._lock:
                self._session_count += 1
                self._state = "connecting"
                self._current_backoff_seconds = 0.0
            LOGGER.info("event=session_connect_attempt")

            try:
                client_kwargs: dict[str, object] = {}
                if self._connector is not None:
                    client_kwargs["connector"] = self._connector
                client = AprsIsClient(
                    self.config.aprs_is_config(),
                    store,
                    **client_kwargs,
                )
                with self._lock:
                    self._state = "running"
                session = client.run_bounded(
                    max_packets=self.config.max_packets,
                    max_seconds=self.config.max_seconds,
                    on_packet=self._on_packet,
                    stop_requested=lambda: self._worker_stop_requested(store),
                )
            except Exception as exc:
                code = _safe_error_code(exc)
                with self._lock:
                    self._session_failures += 1
                    if isinstance(exc, OSError):
                        self._connection_failures += 1
                    self._consecutive_failures += 1
                    self._error = code
                LOGGER.warning("event=session_failure code=%s", code)

                if not self.config.continuous or self._stop_event.is_set():
                    with self._lock:
                        self._state = "stopped" if self._stop_event.is_set() else "error"
                    return

                with self._lock:
                    self._reconnect_count += 1
                if self._wait_for_reconnect(
                    failure_backoff,
                    failure=True,
                    worker_poll=lambda: self._service_a2_bridge(store),
                ):
                    break
                failure_backoff = min(
                    self.config.reconnect_max_seconds,
                    max(
                        self.config.reconnect_initial_seconds,
                        failure_backoff * 2.0,
                    ),
                )
                continue

            self._merge_session_stats(session)
            if session.stop_requested or self._stop_event.is_set():
                with self._lock:
                    self._state = "stopped"
                    self._error = ""
                break

            with self._lock:
                self._last_success_epoch = float(self._clock())
                # Any completed, acknowledged session is evidence that the
                # network path is viable. Reset exponential failure state.
                self._consecutive_failures = 0
                self._error = ""
            failure_backoff = self.config.reconnect_initial_seconds

            if not self.config.continuous:
                with self._lock:
                    self._state = "complete"
                return

            with self._lock:
                self._reconnect_count += 1

            # An immediate peer EOF with no data is treated more cautiously than
            # a normal bounded rotation, while still remaining isolated from the
            # rest of GuToChat.
            peer_eof_without_packets = bool(
                getattr(session, "peer_eof", False)
                and session.packets_received == 0
            )
            delay = (
                self.config.reconnect_initial_seconds
                if peer_eof_without_packets
                else self.config.successful_reconnect_delay_seconds
            )
            if peer_eof_without_packets:
                with self._lock:
                    self._consecutive_failures = 1
            if self._wait_for_reconnect(
                delay,
                failure=peer_eof_without_packets,
                worker_poll=lambda: self._service_a2_bridge(store),
            ):
                break

        with self._lock:
            self._state = "stopped"
            self._error = ""
            self._stats["stop_requested"] = True


def build_aprs_live_runtime_from_config(
    config: dict[str, object],
    *,
    product_database_path: Path,
    aprs_database_path: Path,
    connector: Connector | None = None,
    owner_role: str = "gui",
) -> AprsLiveRuntime | None:
    """Build optional APRS runtime, fail-closed on unsafe APRS configuration.

    The default is OFF.  When enabled, an explicit APRS database is mandatory
    and it must not resolve to the product database (including hard-link alias
    detection when both paths already exist).
    """
    if not bool(config.get("map_aprs_live_enabled", False)):
        return None

    if "map_aprs_database" not in config:
        raise ValueError("APRS live ingest requires explicit map_aprs_database")

    product_db = Path(product_database_path).expanduser().resolve()
    aprs_db = Path(aprs_database_path).expanduser().resolve()
    if _same_file_or_path(aprs_db, product_db):
        raise ValueError(
            "APRS live ingest requires map_aprs_database separate from product database"
        )
    if aprs_db.exists() and not aprs_db.is_file():
        raise ValueError("APRS live database path must name a file")

    runtime_config = AprsLiveRuntimeConfig(
        database_path=aprs_db,
        login=str(config.get("map_aprs_live_login", "")),
        latitude=float(config.get("map_aprs_live_latitude", 0.0)),
        longitude=float(config.get("map_aprs_live_longitude", 0.0)),
        radius_km=float(config.get("map_aprs_live_radius_km", 200.0)),
        host=str(config.get("map_aprs_live_host", "euro.aprs2.net")),
        port=int(config.get("map_aprs_live_port", 14580)),
        max_packets=int(config.get("map_aprs_live_max_packets", 100)),
        max_seconds=float(config.get("map_aprs_live_max_seconds", 120.0)),
        continuous=bool(config.get("map_aprs_live_continuous", False)),
        reconnect_initial_seconds=float(
            config.get("map_aprs_live_reconnect_initial_seconds", 1.0)
        ),
        reconnect_max_seconds=float(
            config.get("map_aprs_live_reconnect_max_seconds", 60.0)
        ),
        successful_reconnect_delay_seconds=float(
            config.get("map_aprs_live_reconnect_success_seconds", 1.0)
        ),
        connect_timeout_seconds=float(
            config.get("map_aprs_live_connect_timeout_seconds", 3.0)
        ),
        read_timeout_seconds=float(
            config.get("map_aprs_live_read_timeout_seconds", 1.0)
        ),
        shutdown_timeout_seconds=float(
            config.get("map_aprs_live_shutdown_timeout_seconds", 5.0)
        ),
        ownership_lock_path=(
            Path(str(config["map_aprs_ingest_lock_file"])).expanduser()
            if str(config.get("map_aprs_ingest_lock_file", "")).strip()
            else default_ingest_lock_path(aprs_db)
        ),
        owner_role=owner_role,
        aprs_is_receive_enabled=bool(config.get("map_aprs_is_receive_enabled", True)),
    )
    # Validate login/filter/host contract synchronously before a thread starts.
    runtime_config.aprs_is_config()
    return AprsLiveRuntime(runtime_config, connector=connector)
