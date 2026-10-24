#!/usr/bin/env python3

from __future__ import annotations



import argparse

import json

import logging

import signal

import socketserver

import threading

import time

import uuid

from datetime import datetime

from pathlib import Path

from typing import Any



from api_security import is_loopback_client

from capabilities import capability_enabled, runtime_capability_view



from module_selection import private_radio_enabled





LOG = logging.getLogger("lorad")

PROTOCOL = "LC2"

APP_VERSION = "2.5.0-beta5"





def now_iso() -> str:

    return datetime.now().astimezone().isoformat(timespec="seconds")





from integrity_status_record import load_integrity_record, save_integrity_record
from message_store import MessageStore

from sqlite_resilience import sqlite_locked_retry

from node_catalog import NodeCatalog

from protocol import control_transport_policy, is_control





class RadioService:

    def __init__(self, config: dict[str, Any]) -> None:

        self.config = config

        self.capability_view = runtime_capability_view(config)

        self.private_radio_enabled = private_radio_enabled(config)
        if self.private_radio_enabled:
            if self.capability_view["enforced"] and not capability_enabled(config, "private_lora"):
    
                raise ValueError("Hardware profile does not enable private_lora for lorad")

        self.local_name = str(config["node_name"])

        self.local_addr = int(config["address"])

        self.freq = int(config.get("frequency", 868))

        self.power = int(config.get("power", 13))

        self.air_speed = int(config.get("air_speed", 2400))

        self.serial_port = str(config.get("serial_port", "/dev/ttyS0"))

        self.api_host = str(config.get("api_host", "127.0.0.1"))

        self.api_port = int(config.get("api_port", 8765))

        self.max_text_bytes = int(config.get("max_text_bytes", 190))

        self.min_tx_interval = float(config.get("min_tx_interval_seconds", 1.0))

        self.ack_timeout = float(config.get("ack_timeout_seconds", 5.0))

        self.max_retries = int(config.get("max_retries", 2))

        self.ack_delay = float(config.get("ack_delay_seconds", 0.25))

        self.outbox_retry_seconds = float(config.get("outbox_retry_seconds", 60.0))

        self.outbox_retry_max_seconds = max(

            self.outbox_retry_seconds,

            float(config.get("outbox_retry_max_seconds", 3600.0)),

        )

        self.radio_retry_seconds = float(config.get("radio_retry_seconds", 10.0))

        self.outbox_ttl_hours = float(config.get("outbox_ttl_hours", 24.0))

        self.outbox_max_pending = max(10, int(config.get("outbox_max_pending", 1000)))

        self.control_outbox_ttl_seconds = max(

            30.0, float(config.get("control_outbox_ttl_seconds", 180.0))

        )

        self.control_outbox_max_attempts = max(

            1, int(config.get("control_outbox_max_attempts", 3))

        )

        # Separate fast serial polling from the much more expensive SQLite

        # outbox lookup. beta3 performed both about 33 times per second.

        self.radio_poll_interval = max(0.05, float(config.get("radio_poll_interval_seconds", 0.10)))

        self.outbox_poll_interval = max(0.20, float(config.get("outbox_poll_interval_seconds", 0.50)))

        self.pending_check_interval = max(0.10, float(config.get("pending_check_interval_seconds", 0.25)))

        self.maintenance_interval = max(60.0, float(config.get("database_maintenance_interval_seconds", 300.0)))

        self.seen_packet_retention_days = max(1.0, float(config.get("seen_packet_retention_days", 30.0)))

        self.fragment_ttl_seconds = max(60.0, float(config.get("control_fragment_ttl_seconds", 900.0)))

        db_path = Path(config["database"])

        self.store = sqlite_locked_retry(

            lambda: MessageStore(db_path),

            label="lorad MessageStore-oppstart",

            logger=LOG,

        )

        self.catalog = sqlite_locked_retry(

            lambda: NodeCatalog(db_path),

            label="lorad NodeCatalog-oppstart",

            logger=LOG,

        )

        self.last_maintenance = sqlite_locked_retry(

            lambda: self.store.maintenance(

                seen_packet_days=self.seen_packet_retention_days,

                fragment_ttl_seconds=self.fragment_ttl_seconds,

                include_integrity=False,

            ),

            label="lorad første databasevedlikehold",

            logger=LOG,

        )

        recovered = (sqlite_locked_retry(

            self.store.recover_outbox,

            label="lorad utboks-gjenoppretting",

            logger=LOG,

        )) if self.private_radio_enabled else 0

        if recovered:

            LOG.info("Gjenopptar %s melding(er) fra varig utboks", recovered)

        self.pending: dict[str, dict[str, Any]] = {}

        self.stop_event = threading.Event()

        self.wake_event = threading.Event()

        self.node: Any = None

        self.radio_online = False

        self.last_error = ""

        self.last_rx = ""

        self.last_tx = ""

        self._last_wire_tx = 0.0

        self._tx_lock = threading.Lock()

        # R2-A: database maintenance must never execute inside the critical

        # radio/outbox loop.  Serialize maintenance work on its own worker so

        # manual maintenance and the periodic task cannot overlap.

        self._maintenance_lock = threading.Lock()

        self._integrity_database = db_path
        self._last_integrity_check = load_integrity_record(db_path)
        self._integrity_current_session = False

        self._maintenance_job_lock = threading.Lock()

        self._maintenance_job: dict[str, Any] = {}

        # Resource-hotfix B: bound expensive history reads server-side.  A client

        # timeout must not allow unbounded ThreadingTCPServer workers to pile up

        # while an older SQLite history scan is still running.

        self.history_query_max_concurrent = max(

            1, min(int(config.get("api_history_max_concurrent", 1)), 4)

        )

        self._history_query_slots = threading.BoundedSemaphore(

            self.history_query_max_concurrent

        )



        # P4-A4-A4-H2: privileged remote-control traffic owns a short,

        # bounded local transmit quiet lease.  RX and transport ACK handling

        # remain active; ordinary user/sync outbox rows are preserved and

        # resume automatically after the lease expires.

        self.privileged_transport_quiet_seconds = max(

            5.0,

            float(

                config.get(

                    "privileged_transport_quiet_seconds",

                    20.0,

                )

            ),

        )

        self._privileged_transport_quiet_until = 0.0



    def start(self) -> None:

        if self.private_radio_enabled:
            threading.Thread(target=self._radio_loop, name="radio", daemon=True).start()

        threading.Thread(

            target=self._maintenance_loop,

            name="database-maintenance",

            daemon=True,

        ).start()



    def start_maintenance_job(self) -> dict[str, Any]:

        with self._maintenance_job_lock:

            if self._maintenance_job.get("state") == "running":

                return dict(self._maintenance_job)

            job_id = uuid.uuid4().hex

            self._maintenance_job = {"job_id": job_id, "state": "running", "started_at": now_iso()}

            try:

                threading.Thread(target=self._maintenance_job_worker, args=(job_id,), daemon=True).start()

            except BaseException:

                self._maintenance_job = {"job_id": job_id, "state": "failed", "error": "Worker could not start"}

                raise

            return dict(self._maintenance_job)



    def maintenance_job_status(self, job_id: str) -> dict[str, Any]:

        with self._maintenance_job_lock:

            if self._maintenance_job.get("job_id") != job_id:

                return {"job_id": job_id, "state": "unknown"}

            return dict(self._maintenance_job)



    def _maintenance_job_worker(self, job_id: str) -> None:

        try:

            result = self.run_maintenance(include_integrity=True)

            self.wake_event.set()

            update = {"state": "done", "result": result, "completed_at": now_iso()}

        except Exception:

            LOG.exception("Database maintenance job failed")

            update = {"state": "failed", "error": "Database maintenance failed", "completed_at": now_iso()}

        with self._maintenance_job_lock:

            if self._maintenance_job.get("job_id") == job_id:

                self._maintenance_job = {**self._maintenance_job, **update}



    def run_maintenance(self, *, include_integrity: bool = False) -> dict[str, Any]:

        with self._maintenance_lock:

            result = self.store.maintenance(

                seen_packet_days=self.seen_packet_retention_days,

                fragment_ttl_seconds=self.fragment_ttl_seconds,

                include_integrity=include_integrity,

            )

            if include_integrity:

                self._last_integrity_check = {"integrity": result.get("integrity", "ukjent"), "completed_at": now_iso()}
                self._integrity_current_session = True
                if not save_integrity_record(self._integrity_database, self._last_integrity_check):
                    LOG.warning("Could not persist completed database integrity result")

            self.last_maintenance = result

        LOG.info("Databasevedlikehold: %s", result)

        return dict(result)



    def try_begin_history_query(self) -> bool:

        """Acquire one bounded server-side slot for expensive history reads."""

        return bool(self._history_query_slots.acquire(blocking=False))



    def end_history_query(self) -> None:

        """Release one history-query slot acquired by try_begin_history_query."""

        self._history_query_slots.release()



    def _maintenance_loop(self) -> None:

        """Run periodic SQLite housekeeping outside the radio critical path."""

        interval = float(getattr(self, "maintenance_interval", 300.0))

        while not self.stop_event.wait(interval):

            try:

                self.run_maintenance()

            except Exception:

                LOG.exception("Databasevedlikehold mislyktes")



    def stop(self) -> None:

        self.stop_event.set()

        self.wake_event.set()

        try:

            if self.node is not None:

                close_node = getattr(self.node, "close", None)

                if callable(close_node):

                    close_node()

                else:

                    serial_port = getattr(self.node, "ser", None)

                    close_serial = getattr(serial_port, "close", None)

                    if callable(close_serial):

                        close_serial()

        except Exception:

            LOG.exception("Kunne ikke lukke serieporten")



    def enqueue_send(

        self,

        destination: int,

        text: str,

        *,

        transport_policy: dict[str, Any] | None = None,

    ) -> str:

        if not self.private_radio_enabled:
            raise RuntimeError("PRIVATE_RADIO_NOT_CONFIGURED")

        if not 0 <= destination <= 65535:

            raise ValueError("Mottakeradressen må være mellom 0 og 65535")

        text = text.strip()

        if not text:

            raise ValueError("Meldingen er tom")

        if len(text.encode("utf-8")) > self.max_text_bytes:

            raise ValueError(

                f"Meldingen er for lang. Maks {self.max_text_bytes} UTF-8-byte."

            )

        message_uid = uuid.uuid4().hex[:12]

        policy = dict(transport_policy or control_transport_policy(text, destination))

        traffic_class = str(policy.get("traffic_class", "user"))

        if traffic_class == "sync":

            policy["max_attempts"] = min(

                int(policy.get("max_attempts", self.control_outbox_max_attempts)),

                self.control_outbox_max_attempts,

            )

            policy["ttl_seconds"] = min(

                float(policy.get("ttl_seconds", self.control_outbox_ttl_seconds)),

                self.control_outbox_ttl_seconds,

            )

            policy.setdefault("priority", 20)

        elif traffic_class == "privileged_control":

            # Privileged control must outrank ordinary traffic locally.

            # This does not discard, pause, or rewrite ordinary outbox rows.

            policy.setdefault("priority", 1000)

        else:

            policy.setdefault("priority", 100)

        allowed = {

            "traffic_class",

            "control_command",

            "control_route",

            "control_request_id",

            "control_group",

            "max_attempts",

            "ttl_seconds",

            "replace_other_requests",

            "priority",

        }

        policy = {key: value for key, value in policy.items() if key in allowed}

        self.store.enqueue_outbox(

            message_uid=message_uid,

            source=self.local_addr,

            destination=destination,

            text=text,

            ttl_hours=self.outbox_ttl_hours,

            max_pending=self.outbox_max_pending,

            **policy,

        )

        if traffic_class == "privileged_control":

            self._activate_privileged_transport_quiet()

        self.wake_event.set()

        return message_uid



    def status(self) -> dict[str, Any]:

        outbox_count, sync_outbox_count = self.store.outbox_counts()

        return {

            "radio_online": self.radio_online,
            "private_radio_configured": self.private_radio_enabled,
            "private_radio_state": ("ONLINE" if self.radio_online else "OFFLINE") if self.private_radio_enabled else "NOT_CONFIGURED",

            "last_error": self.last_error,

            "node_name": self.local_name,

            "address": self.local_addr,

            "frequency_mhz": self.freq + 0.125,

            "power_dbm": self.power,

            "air_speed": self.air_speed,

            "serial_port": self.serial_port,

            "last_rx": self.last_rx,

            "last_tx": self.last_tx,

            "queue_size": outbox_count,

            "outbox_pending": outbox_count,

            "pending_acks": len(self.pending),

            "ack_timeout_seconds": self.ack_timeout,

            "max_retries": self.max_retries,

            "outbox_retry_seconds": self.outbox_retry_seconds,

            "outbox_retry_max_seconds": self.outbox_retry_max_seconds,

            "outbox_ttl_hours": self.outbox_ttl_hours,

            "outbox_max_pending": self.outbox_max_pending,

            "control_outbox_ttl_seconds": self.control_outbox_ttl_seconds,

            "control_outbox_max_attempts": self.control_outbox_max_attempts,

            "sync_outbox_pending": sync_outbox_count,

            "min_tx_interval_seconds": self.min_tx_interval,

            "radio_poll_interval_seconds": self.radio_poll_interval,

            "outbox_poll_interval_seconds": self.outbox_poll_interval,

            "pending_check_interval_seconds": self.pending_check_interval,

            "database_maintenance_interval_seconds": self.maintenance_interval,

            "database_integrity": self._last_integrity_check.get("integrity", "not_run"),

            "database_integrity_checked_at": self._last_integrity_check.get("completed_at", ""),
            "database_integrity_current_session": self._integrity_current_session,

            "last_maintenance": self.last_maintenance.get("completed_at", ""),

            "last_maintenance_result": dict(self.last_maintenance),

            "service_version": APP_VERSION,

            "protocol": PROTOCOL,

            "capability_policy": dict(self.capability_view),

        }



    def _radio_loop(self) -> None:

        if not self.private_radio_enabled:
            return
        import sx126x

        while not self.stop_event.is_set():

            try:

                LOG.info(

                    "Initialiserer radio: adresse=%s frekvens=%s effekt=%s ACK-timeout=%ss retries=%s",

                    self.local_addr,

                    self.freq,

                    self.power,

                    self.ack_timeout,

                    self.max_retries,

                )

                self.node = sx126x.sx126x(

                    serial_num=self.serial_port,

                    freq=self.freq,

                    addr=self.local_addr,

                    power=self.power,

                    rssi=True,

                    air_speed=self.air_speed,

                    relay=False,

                )

                self.radio_online = bool(getattr(self.node.ser, "is_open", True))

                self.last_error = ""

                self._active_radio_loop()

            except Exception as exc:

                self.radio_online = False

                self.last_error = f"{type(exc).__name__}: {exc}"

                LOG.exception("Radiofeil; prøver igjen om 5 sekunder")

                self.stop_event.wait(5)



    def _active_radio_loop(self) -> None:

        next_outbox_check = 0.0

        next_pending_check = 0.0

        while not self.stop_event.is_set():

            now = time.monotonic()

            if now >= next_outbox_check:

                self._process_outbox()

                next_outbox_check = time.monotonic() + self.outbox_poll_interval



            # Keep receive latency low without opening SQLite on every pass.

            self._receive_one()



            now = time.monotonic()

            if now >= next_pending_check:

                self._check_pending()

                next_pending_check = time.monotonic() + self.pending_check_interval



            now = time.monotonic()

            timeout = min(

                self.radio_poll_interval,

                max(0.0, next_outbox_check - now),

                max(0.0, next_pending_check - now),

            )

            signalled = self.wake_event.wait(max(0.01, timeout))

            if signalled:

                self.wake_event.clear()

                # New API traffic or an immediate retry should inspect the

                # persistent outbox without waiting for the periodic poll.

                next_outbox_check = 0.0



    def _build_packet(self, destination: int, envelope: bytes) -> bytes:

        if len(envelope) > 225:

            raise ValueError("Meldingen med protokollhode er for lang")

        offset_frequency = self.freq - (850 if self.freq > 850 else 410)

        return (

            bytes([destination >> 8, destination & 0xFF, offset_frequency])

            + bytes(

                [

                    self.local_addr >> 8,

                    self.local_addr & 0xFF,

                    int(self.node.offset_freq),

                ]

            )

            + envelope

        )



    def _wire_send(self, destination: int, envelope: bytes) -> bytes:

        if not self.private_radio_enabled:
            raise RuntimeError("PRIVATE_RADIO_NOT_CONFIGURED")

        with self._tx_lock:

            wait = self.min_tx_interval - (time.monotonic() - self._last_wire_tx)

            if wait > 0:

                time.sleep(wait)

            data = self._build_packet(destination, envelope)

            self.node.send(data)

            self._last_wire_tx = time.monotonic()

            self.last_tx = now_iso()

            return data



    def _message_envelope(self, uid: str, destination: int, text: str) -> bytes:

        return (

            f"{PROTOCOL}|{uid}|{self.local_addr}|{destination}|MSG|{text}"

        ).encode("utf-8")



    def _ack_envelope(self, uid: str, destination: int) -> bytes:

        return (

            f"{PROTOCOL}|{uid}|{self.local_addr}|{destination}|ACK|"

        ).encode("utf-8")



    def _activate_privileged_transport_quiet(self) -> None:

        """Extend the bounded local quiet lease for privileged transport."""

        current = time.monotonic()

        quiet_seconds = max(

            5.0,

            float(

                getattr(

                    self,

                    "privileged_transport_quiet_seconds",

                    20.0,

                )

            ),

        )

        self._privileged_transport_quiet_until = max(

            float(

                getattr(

                    self,

                    "_privileged_transport_quiet_until",

                    0.0,

                )

            ),

            current + quiet_seconds,

        )



    def _privileged_transport_quiet_active(self) -> bool:

        """Return whether ordinary local TX must remain quiescent."""

        until = float(

            getattr(

                self,

                "_privileged_transport_quiet_until",

                0.0,

            )

        )

        if until <= 0.0:

            return False

        if time.monotonic() >= until:

            self._privileged_transport_quiet_until = 0.0

            return False

        return True



    def _activate_ordinary_tx_receive_guard(self) -> None:

        """Open a bounded RX window before the next ordinary local TX."""

        current = time.monotonic()

        guard_seconds = min(

            10.0,

            max(

                1.0,

                float(

                    getattr(

                        self,

                        "ordinary_tx_receive_guard_seconds",

                        6.0,

                    )

                ),

            ),

        )

        self._ordinary_tx_receive_guard_until = max(

            float(

                getattr(

                    self,

                    "_ordinary_tx_receive_guard_until",

                    0.0,

                )

            ),

            current + guard_seconds,

        )



    def _ordinary_tx_receive_guard_active(self) -> bool:

        """Return whether ordinary TX must yield to the RX acquisition window."""

        until = float(

            getattr(

                self,

                "_ordinary_tx_receive_guard_until",

                0.0,

            )

        )

        if until <= 0.0:

            return False

        if time.monotonic() >= until:

            self._ordinary_tx_receive_guard_until = 0.0

            return False

        return True



    def _process_outbox(self) -> None:

        # Keep the private Waveshare link strictly stop-and-wait for unicast.

        # The radio is half-duplex, and sending a second queued frame before

        # the first one has received its transport ACK can make the peer's ACK

        # collide with the next frame.  This was especially visible during the

        # six-frame Mobile sync burst (IREQ/NREQ/MREQ for 868 and 433), where

        # INFO, GWIDENT and NODE responses repeatedly expired while the final

        # NDONE/MDONE happened to get through.

        if self.pending:

            return

        item = self.store.next_outbox_due()

        if item is None:

            return



        traffic_class = str(

            item.get("traffic_class", "user")

        )



        # During a privileged transaction, preserve ordinary queued traffic

        # but do not place it on the half-duplex radio.  Privileged rows have

        # priority 1000, so any due privileged row is selected ahead of

        # ordinary user/sync rows by MessageStore.next_outbox_due().

        if (

            self._privileged_transport_quiet_active()

            and traffic_class != "privileged_control"

        ):

            return



        # After an ordinary unicast attempt releases stop-and-wait, keep a

        # bounded receive window before sending another ordinary frame.

        # Privileged control bypasses this guard so the first authenticated

        # request/response can acquire the half-duplex transport.

        if (

            self._ordinary_tx_receive_guard_active()

            and traffic_class != "privileged_control"

        ):

            return



        if traffic_class == "privileged_control":

            self._activate_privileged_transport_quiet()



        uid = str(item["message_uid"])

        destination = int(item["destination"])

        text = str(item["text"])

        attempts = int(item.get("attempts", 0)) + 1

        try:

            data = self._wire_send(

                destination, self._message_envelope(uid, destination, text)

            )

            sync_group = str(item.get("control_group", ""))

            lease_group_prefix = next(

                (

                    prefix

                    for prefix in (

                        "response:POSITION_HISTORY:",

                        "response:APRS:",

                        "response:MESSAGES:",

                    )

                    if sync_group.startswith(prefix)

                ),

                "",

            )

            if traffic_class == "sync" and lease_group_prefix:

                try:

                    renewed = self.store.refresh_sync_group_expiry(

                        uid,

                        ttl_seconds=self.control_outbox_ttl_seconds,

                        control_group_prefix=lease_group_prefix,

                    )

                    if renewed:

                        LOG.debug(

                            "Fornyet sync-responslease for %s køpost(er) etter wire-aktivitet (%s)",

                            renewed,

                            lease_group_prefix,

                        )

                except Exception:

                    # The radio frame is already on the wire.  A lease-refresh

                    # bookkeeping error must never turn that successful send

                    # into a synthetic radio failure or duplicate retry.

                    LOG.exception(

                        "Kunne ikke fornye sync-responslease etter wire-aktivitet (%s)",

                        lease_group_prefix,

                    )

            if destination == 65535:

                self.store.mark_wire_sent(

                    uid,

                    attempts=attempts,

                    raw_hex=data.hex(),

                    waiting_ack=False,

                    status="Sendt (broadcast)",

                )

            else:

                self.pending[uid] = {

                    "attempts": attempts,

                    "last_send": time.monotonic(),

                    "traffic_class": traffic_class,

                }

                self.store.mark_wire_sent(

                    uid,

                    attempts=attempts,

                    raw_hex=data.hex(),

                    waiting_ack=True,

                    status="Venter på ACK",

                )

            LOG.info(

                "Sendt UID=%s til %s (forsøk %s, %s UTF-8-byte)",

                uid, destination, attempts, len(text.encode("utf-8")),

            )

        except Exception as exc:

            self.radio_online = False

            self.last_error = f"Sendefeil: {type(exc).__name__}: {exc}"

            self.store.schedule_retry(

                uid,

                attempts=int(item.get("attempts", 0)),

                delay_seconds=self.radio_retry_seconds,

                status="Venter på radioforbindelse",

                error=self.last_error,

            )

            LOG.exception("Kunne ikke sende UID=%s; beholdes i utboks", uid)

            raise



    def _check_pending(self) -> None:

        current = time.monotonic()

        round_size = max(1, self.max_retries + 1)

        for uid, pending in list(self.pending.items()):

            if current - float(pending["last_send"]) < self.ack_timeout:

                continue

            attempts = int(pending["attempts"])

            traffic_class = str(

                pending.get("traffic_class", "user")

            )

            round_position = ((attempts - 1) % round_size) + 1

            if round_position < round_size:

                delay = 0.0

                next_position = round_position + 1

                status = f"Prøver igjen ({next_position}/{round_size})"

            else:

                delay = self._long_retry_delay(attempts)

                status = "Ingen ACK – venter på forbindelse"

            retained = self.store.schedule_retry(

                uid,

                attempts=attempts,

                delay_seconds=delay,

                status=status,

            )

            self.pending.pop(uid, None)

            if traffic_class != "privileged_control":

                self._activate_ordinary_tx_receive_guard()

            if retained:

                self.wake_event.set()

                LOG.warning("Ingen ACK for UID=%s; %s", uid, status)

            else:

                LOG.warning(

                    "Ingen ACK for UID=%s; transient kontrollmelding er utløpt",

                    uid,

                )



    def _long_retry_delay(self, attempts: int) -> float:

        """Back off complete delivery rounds during prolonged no-coverage periods."""

        round_size = max(1, self.max_retries + 1)

        completed_rounds = max(1, int(attempts) // round_size)

        exponent = min(completed_rounds - 1, 8)

        return min(

            self.outbox_retry_seconds * (2 ** exponent),

            self.outbox_retry_max_seconds,

        )



    @staticmethod

    def _parse_envelope(

        payload: bytes, fallback_source: int

    ) -> tuple[str, int, int, str, str]:

        decoded = payload.decode("utf-8", errors="replace")

        try:

            parts = decoded.split("|", 5)

            if len(parts) == 6 and parts[0] in {"LC1", "LC2"}:

                uid = parts[1]

                source = int(parts[2])

                destination = int(parts[3])

                kind = parts[4]

                text = parts[5]

                if kind in {"MSG", "ACK"}:

                    return uid, source, destination, kind, text

        except Exception:

            pass

        return uuid.uuid4().hex[:12], fallback_source, 0, "MSG", decoded



    def _send_ack(self, uid: str, destination: int) -> None:

        time.sleep(self.ack_delay)

        self._wire_send(destination, self._ack_envelope(uid, destination))

        LOG.info("ACK sendt for UID=%s til %s", uid, destination)



    def _receive_one(self) -> None:

        if self.node is None or self.node.ser.inWaiting() <= 0:

            return

        time.sleep(0.35)

        raw = self.node.ser.read(self.node.ser.inWaiting())

        if len(raw) < 4:

            LOG.warning("For kort mottakspakke: %s", raw.hex())

            return



        source_from_radio = (raw[0] << 8) + raw[1]

        frequency_mhz = raw[2] + int(self.node.start_freq)

        packet_rssi = -(256 - raw[-1])

        payload = raw[3:-1]

        uid, source, destination, kind, text = self._parse_envelope(

            payload, source_from_radio

        )

        if destination == 0:

            destination = self.local_addr

        self.last_rx = now_iso()

        self.radio_online = True



        if kind == "ACK":

            if destination != self.local_addr:

                return

            updated = self.store.complete_outbox(

                uid, status="Bekreftet", ack_rssi=packet_rssi

            )

            completed_pending = self.pending.pop(uid, None)

            if (

                completed_pending is not None

                and str(

                    completed_pending.get("traffic_class", "user")

                ) != "privileged_control"

            ):

                self._activate_ordinary_tx_receive_guard()

            if updated:

                LOG.info("ACK mottatt for UID=%s fra %s, RSSI %s dBm", uid, source, packet_rssi)

            else:

                LOG.warning("ACK for ukjent eller ferdig UID=%s fra %s", uid, source)

            return



        if destination not in {self.local_addr, 65535}:

            LOG.debug("Ignorerer pakke til adresse %s", destination)

            return



        duplicate = self.store.receive_once(

            message_uid=uid, source=source, destination=destination,

            text=text, packet_rssi=packet_rssi, raw_hex=raw.hex(),

        )

        if not duplicate:

            LOG.info(

                "Mottatt UID=%s fra %s til %s på %s.125 MHz, RSSI %s dBm (%s UTF-8-byte)",

                uid,

                source,

                destination,

                frequency_mhz,

                packet_rssi,

                len(text.encode("utf-8")),

            )

        else:

            LOG.info("Duplikat UID=%s fra %s; lagres ikke på nytt", uid, source)



        if destination == self.local_addr:

            try:

                self._send_ack(uid, source)

            except Exception as exc:

                self.last_error = f"ACK-feil: {type(exc).__name__}: {exc}"

                LOG.exception("Kunne ikke sende ACK for UID=%s", uid)





class ApiHandler(socketserver.StreamRequestHandler):

    def handle(self) -> None:

        service: RadioService = self.server.service  # type: ignore[attr-defined]

        try:

            line = self.rfile.readline(1024 * 1024)

            request = json.loads(line.decode("utf-8"))

            command = request.get("command")

            if command == "status":

                response = {"ok": True, "status": service.status()}

            elif command == "list":

                limit = max(1, min(int(request.get("limit", 500)), 2000))

                messages = service.store.list_recent(limit)

                if bool(request.get("hide_control", False)):

                    messages = [

                        item

                        for item in messages

                        if not is_control(str(item.get("text", "")))

                    ]

                response = {"ok": True, "messages": messages}

            elif command == "list_controls":

                limit = max(1, min(int(request.get("limit", 500)), 2000))

                response = {

                    "ok": True,

                    "messages": service.store.list_recent_controls(limit),

                }

            elif command == "list_display":

                if not service.try_begin_history_query():

                    response = {

                        "ok": False,

                        "error": "HistoryBusyError: visible-history query already running",

                    }

                else:

                    try:

                        limit = max(1, min(int(request.get("limit", 250)), 1000))

                        before_value = request.get("before_id")

                        before_id = (

                            int(before_value)

                            if before_value not in (None, "")

                            else None

                        )

                        response = {

                            "ok": True,

                            "messages": service.store.list_recent_display_carriers(

                                limit, before_id=before_id

                            ),

                        }

                    finally:

                        service.end_history_query()

            elif command == "outbox":

                response = {"ok": True, "outbox": service.store.outbox_rows()}

            elif command == "outbox_history":

                response = {

                    "ok": True,

                    "history": service.store.queue_history(

                        str(request["message_uid"]),

                        int(request.get("limit", 50)),

                    ),

                }

            elif command == "maintenance_start":

                response = {"ok": True, "maintenance_job": service.start_maintenance_job()}

            elif command == "maintenance_status":

                response = {"ok": True, "maintenance_job": service.maintenance_job_status(str(request.get("job_id", "")))}

            elif command == "maintenance":

                # Explicit operator maintenance retains the full integrity check.

                response = {

                    "ok": True,

                    "maintenance": service.run_maintenance(include_integrity=True),

                }

                service.wake_event.set()

            elif command == "cleanup_controls":

                response = {"ok": True, "maintenance": service.run_maintenance()}

                service.wake_event.set()

            elif command == "cancel":

                response = {

                    "ok": service.store.cancel_outbox(str(request["message_uid"])),

                    "error": "Fant ikke meldingen i utboksen",

                }

            elif command == "pause":

                response = {

                    "ok": service.store.pause_outbox(str(request["message_uid"])),

                    "error": "Meldingen kunne ikke pauses (den kan være aktiv eller ferdig)",

                }

            elif command == "resume":

                ok = service.store.resume_outbox(str(request["message_uid"]))

                if ok:

                    service.wake_event.set()

                response = {

                    "ok": ok,

                    "error": "Fant ikke en pauset melding i utboksen",

                }

            elif command == "renew":

                ok = service.store.renew_outbox(

                    str(request["message_uid"]),

                    ttl_hours=float(request.get("ttl_hours", service.outbox_ttl_hours)),

                )

                if ok:

                    service.wake_event.set()

                response = {

                    "ok": ok,

                    "error": "Fant ikke en utløpt, beholdt melding i utboksen",

                }

            elif command == "retry":

                ok = service.store.retry_now(str(request["message_uid"]))

                if ok:

                    service.wake_event.set()

                response = {"ok": ok, "error": "Fant ikke meldingen i utboksen"}

            elif command == "version":

                response = {"ok": True, "version": APP_VERSION, "protocol": PROTOCOL}

            elif command == "send":

                policy = {

                    key: request[key]

                    for key in (

                        "traffic_class",

                        "control_command",

                        "control_route",

                        "control_request_id",

                        "control_group",

                        "max_attempts",

                        "ttl_seconds",

                        "replace_other_requests",

                        "priority",

                    )

                    if key in request

                }

                uid = service.enqueue_send(

                    int(request["destination"]),

                    str(request["text"]),

                    transport_policy=policy or None,

                )

                response = {"ok": True, "message_uid": uid, "queued": True}

            else:

                response = {"ok": False, "error": "Ukjent kommando"}

        except Exception as exc:

            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

        self.wfile.write((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))





class ApiServer(socketserver.ThreadingTCPServer):

    allow_reuse_address = True

    daemon_threads = True



    def verify_request(self, request: Any, client_address: Any) -> bool:

        # Defense in depth: hardware profiles already require 127.0.0.1, but

        # reject non-loopback peers even if a legacy/custom config binds wider.

        return is_loopback_client(client_address)





def load_config(path: Path) -> dict[str, Any]:

    from hardware_profile_runtime import load_runtime_config



    return load_runtime_config(path)





def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument("--config", required=True)

    args = parser.parse_args()

    logging.basicConfig(

        level=logging.INFO,

        format="%(asctime)s %(levelname)s %(name)s: %(message)s",

    )

    service = RadioService(load_config(Path(args.config)))

    service.start()

    server = ApiServer((service.api_host, service.api_port), ApiHandler)

    server.service = service  # type: ignore[attr-defined]



    def request_stop(signum: int, frame: Any) -> None:

        LOG.info("Stoppsignal mottatt")

        service.stop()

        threading.Thread(target=server.shutdown, daemon=True).start()



    signal.signal(signal.SIGTERM, request_stop)

    signal.signal(signal.SIGINT, request_stop)

    LOG.info("API lytter på %s:%s", service.api_host, service.api_port)

    try:

        server.serve_forever(poll_interval=0.5)

    finally:

        service.stop()

        server.server_close()

    return 0





if __name__ == "__main__":

    raise SystemExit(main())

