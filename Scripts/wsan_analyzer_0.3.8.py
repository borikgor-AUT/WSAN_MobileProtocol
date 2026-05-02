#!/usr/bin/env python3
"""
WSAN Analyzer GUI
=================
Unified version:
- Open Log File (Mote_Communication.txt)
- Streaming parser + progress bar + watchdog
- Message table + search/filter
- Graphs (PDR, throughput, latency CDF, hop, load, per-mobile)
- Distribution Tree via Qt GraphicsView (right-click)

Author: Boris Gor (spec), implementation via Copilot
"""

from __future__ import annotations

import sys
import time
import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Tuple, List, Set

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("QtAgg")
import matplotlib.pyplot as plt

from PySide6.QtCore import Qt, QObject, Signal, Slot, QPointF, QRectF, QSizeF, QEvent
from PySide6.QtGui import (QPen, QBrush, QAction, QPainter, QPainterPath,
                            QColor, QFont, QFontMetrics, QPolygonF)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog,
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QLineEdit, QMessageBox, QCheckBox, QSlider,
    QTabWidget, QGroupBox, QGridLayout,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QTabWidget, QMenu, QScrollArea
)

# ==========================================================
# WSAN constants (from your headers)
# ==========================================================

WSAN_SIG = "5753414E"      # "WSAN"
MARK_MBL = "Mbl"
MARK_RSU = "RSU"

WSAN_MSG_QUERY = 0
WSAN_MSG_ACK = 1
WSAN_MSG_DATA = 2
WSAN_MSG_EMERGENCY = 4

TTL_DEFAULT = 3
FRIEND_EMPTY = 0xFFFFFFFF
MAX_NODE_ID = 255  # Sky node_id8 range; used to reject malformed WSAN parses

# ==========================================================
# Data structures
# ==========================================================

@dataclass
class MsgRow:
    time_created_ms: int
    time_delivered_ms: Optional[int]
    latency_ms: Optional[int]
    origin_id: int
    msg_id: int
    msg_type: str
    delivered: bool
    hop_count: Optional[int]
    tx_count: int
    duplicate_count: int
    hex_norm: str

# ==========================================================
# Worker signals
# ==========================================================

class WorkerSignals(QObject):
    progress = Signal(float)
    finished = Signal(object)
    error = Signal(str)
    watchdog = Signal(object)

class WatchdogTicket:
    def __init__(self):
        self.allow = True
        self.dont_ask_again = False
        self._event = threading.Event()

    def wait(self):
        self._event.wait()

    def release(self):
        self._event.set()

# ==========================================================
# WSAN frame parsing helpers
# ==========================================================

def hex_to_bytes(h: str) -> bytes:
    # Normalize: remove spaces and optional 0x prefixes.
    h = h.replace("0x", "").replace("0X", "")
    h = h.replace(" ", "").upper()
    h = h.replace("\t", "").upper()
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""

def extract_wsan_frame(hexline: str) -> Optional[bytes]:
    # Normalize to reliably find WSAN signature even if split by spaces.
    hx = hexline.replace("0x", "").replace("0X", "")
    hx = hx.replace(" ", "").upper()
    hx = hx.replace("\t", "").upper()
    idx = hx.find(WSAN_SIG)
    if idx < 0:
        return None
    raw = hex_to_bytes(hx[idx:])
    if len(raw) < 7:
        return None
    body_len = (raw[5] << 8) | raw[6]
    total = 7 + body_len
    if len(raw) < total:
        return None
    frame = raw[:total]
#    cs_calc = sum(frame[:-1]) & 0xFF
#    if cs_calc != frame[-1]:
#        return None
    return frame

def parse_wsan(frame: bytes) -> Optional[dict]:
    try:
        marker = frame[7:10].decode()
        sender = int.from_bytes(frame[10:14], "big")
        msg_type = frame[14]
        msg_id = int.from_bytes(frame[15:19], "big")
        target = int.from_bytes(frame[19:23], "big")
        origin = int.from_bytes(frame[23:27], "big")
        body_len = (frame[5] << 8) | frame[6]
        pay_len = body_len - 25
        payload = frame[27:27+pay_len]
        ts_ms = int.from_bytes(frame[27+pay_len:27+pay_len+4], "big")
        return dict(
            marker=marker,
            sender=sender,
            msg_type=msg_type,
            msg_id=msg_id,
            target=target,
            origin=origin,
            payload=payload,
            ts_ms=ts_ms
        )
    except Exception:
        return None

def is_valid_id(x: int) -> bool:
    return 0 <= x <= MAX_NODE_ID

def parse_ack(payload: bytes) -> Optional[Tuple[int,int,int]]:
    if payload is None or len(payload) < 9:
        return None
    return payload[0], int.from_bytes(payload[1:5],"big"), int.from_bytes(payload[5:9],"big")

def parse_ttl(payload: bytes) -> Optional[int]:
    if payload is None or len(payload) < 17:
        return None
    return payload[16]

def parse_friends(payload: bytes) -> Optional[Tuple[int, int]]:
    """
    Return (friend1, friend2) from DATA payload.
    Layout per wsan_data_payload_t: friend1 at offset 8, friend2 at 12.
    """
    if payload is None or len(payload) < 17:
        return None
    f1 = int.from_bytes(payload[8:12], "big")
    f2 = int.from_bytes(payload[12:16], "big")
    return f1, f2

class ParserThread(threading.Thread):
    def __init__(self, path: Path, signals: WorkerSignals):
        super().__init__(daemon=True)
        self.path = path
        self.signals = signals
        self.stop = False
        self.ask = True
        self.last_watchdog = time.time()

    def run(self):
        try:
            result = self.parse()
            self.signals.finished.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))

    def parse(self):
        size = self.path.stat().st_size
        read = 0

        created = {}
        created_hex = {}
        delivered = {}
        tx_count = {}
        ttl_rsu = {}
        per_mobile_created = {}
        per_mobile_delivered = {}

        load_frames = {}
        load_bytes = {}

        total_lines = 0
        wsan_lines = 0
        wsan_ts_first = None
        wsan_ts_last = None
        extracted_frames = 0
        by_marker = {}
        by_type = {}

        with self.path.open("r", errors="replace") as f:
            for line in f:
                total_lines += 1
                if self.stop:
                    break

                read += len(line)
                self.signals.progress.emit(read/size)

                if self.ask and time.time() - self.last_watchdog > 60:
                    ticket = WatchdogTicket()
                    self.signals.watchdog.emit(ticket)
                    ticket.wait()
                    if ticket.dont_ask_again:
                        self.ask = False
                    self.last_watchdog = time.time()
                    if not ticket.allow:
                        break

                parts = line.strip().split("\t")
                # Mote_Communication format in this file:
                # time \t src \t receivers \t "LEN: 0xHEX..."
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 4:
                    continue

                try:
                    sim_ms = int(parts[0])
                except ValueError:
                    continue

                if wsan_ts_first is None:

                    wsan_ts_first = sim_ms

                wsan_ts_last = sim_ms

                recv = parts[2].strip()

                # Extract hex dump from the 4th column after ':'
                rest = parts[3]
                if ":" not in rest:
                    continue
                hex_dump = rest.split(":", 1)[1]

                frame = extract_wsan_frame(hex_dump)
                    
                if frame is None:
                    continue
                wsan_lines += 1
                extracted_frames += 1
                ws = parse_wsan(frame)
                if ws is None:
                    continue

                # Reject malformed parses: origin/sender should be in mote ID range.
                # This removes false positives where 'WSAN' appears inside payload.
                if not is_valid_id(ws["sender"]) or not is_valid_id(ws["origin"]):
                    continue

                by_marker[ws["marker"]] = by_marker.get(ws["marker"], 0) + 1
                by_type[ws["msg_type"]] = by_type.get(ws["msg_type"], 0) + 1

                sec = sim_ms//1000
                load_frames[sec] = load_frames.get(sec,0)+1
                load_bytes[sec] = load_bytes.get(sec,0)+len(frame)

                key = (ws["origin"], ws["msg_id"])

                if ws["msg_type"] in (WSAN_MSG_DATA, WSAN_MSG_EMERGENCY):
                    tx_count[key] = tx_count.get(key,0)+1
                    if ws["sender"] == ws["origin"] and key not in created:
                        created[key] = sim_ms
                        created_hex[key] = frame.hex().upper()
                        per_mobile_created[ws["origin"]] = per_mobile_created.get(ws["origin"],0)+1

                if ws["marker"] == MARK_RSU and ws["msg_type"] == WSAN_MSG_ACK:
                    ack = parse_ack(ws["payload"])
                    if ack:
                        at, ao, am = ack
                        akey = (ao, am)
                        if at in (WSAN_MSG_DATA, WSAN_MSG_EMERGENCY) and akey not in delivered:
                            delivered[akey] = sim_ms
                            per_mobile_delivered[ao] = per_mobile_delivered.get(ao,0)+1

                if ws["msg_type"] == WSAN_MSG_DATA and recv != "-" and key not in ttl_rsu:
                    ttl = parse_ttl(ws["payload"])
                    if ttl is not None:
                        ttl_rsu[key] = ttl


        # Build message table strictly from created messages only (sender==origin seen).
        rows = []
        for (o,m), tc in created.items():
            d = delivered.get((o,m))
            rows.append(MsgRow(
                time_created_ms=tc,
                time_delivered_ms=d,
                latency_ms=(d-tc) if d else None,
                origin_id=o,
                msg_id=m,
                msg_type="DATA",
                delivered=d is not None,
                hop_count=(TTL_DEFAULT-ttl_rsu[(o,m)]) if (o,m) in ttl_rsu and d else None,
                tx_count=tx_count.get((o,m),0),
                duplicate_count=max(0,tx_count.get((o,m),0)-1),
                hex_norm=created_hex.get((o,m), "")
            ))

        if rows:
            msg_df = pd.DataFrame([r.__dict__ for r in rows])
            msg_df = msg_df.sort_values("time_created_ms")
        else:
            # Ensure stable schema even if nothing was parsed as 'created'
            msg_df = pd.DataFrame(columns=[
                "time_created_ms", "time_delivered_ms", "latency_ms",
                "origin_id", "msg_id", "msg_type", "delivered",
                "hop_count", "tx_count", "duplicate_count"
            ])

        per_mobile_df = pd.DataFrame({
            "mobile_id": list(set(per_mobile_created)|set(per_mobile_delivered))
        })
        per_mobile_df["created"] = per_mobile_df["mobile_id"].map(lambda x: per_mobile_created.get(x,0))
        per_mobile_df["delivered"] = per_mobile_df["mobile_id"].map(lambda x: per_mobile_delivered.get(x,0))

        load_df = pd.DataFrame({
            "sec": list(load_frames),
            "frames": [load_frames[k] for k in load_frames],
            "bytes": [load_bytes[k] for k in load_frames]
        }).sort_values("sec")
        # --------------------------------------------------------------
        # High-level statistics (for Log Stats tab)
        # --------------------------------------------------------------
        def _fmt_pct(x):
            try:
                return f"{100.0*float(x):.2f}%"
            except Exception:
                return "-"

        stats_rows = []  # list of (metric, value)

        def _sec(title: str) -> None:
            stats_rows.append((f"== {title} ==", ""))

        def _add(k: str, v) -> None:
            stats_rows.append((k, v))

        _sec("Log overview")
        _add("Total lines", total_lines)
        _add("WSAN frames (lines containing WSAN)", wsan_lines)
        _add("WSAN frames extracted", extracted_frames)
        _add("Marker Mbl", by_marker.get("Mbl", 0))
        _add("Marker RSU", by_marker.get("RSU", 0))
        _add("Type QUERY (0)", by_type.get(0, 0))
        _add("Type ACK (1)", by_type.get(1, 0))
        _add("Type DATA (2)", by_type.get(2, 0))
        _add("Type EMERG (4)", by_type.get(4, 0))

        _sec("Time")
        if wsan_ts_first is None or wsan_ts_last is None:
            _add("First timestamp (ms)", "-")
            _add("Last timestamp (ms)", "-")
            _add("Duration (s)", "-")
        else:
            _add("First timestamp (ms)", wsan_ts_first)
            _add("Last timestamp (ms)", wsan_ts_last)
            _add("Duration (s)", f"{(wsan_ts_last-wsan_ts_first)/1000.0:.3f}")

        _sec("Message outcomes (originated DATA only)")
        n_created = len(created)
        n_delivered = len(delivered)
        _add("Unique created messages (sender==origin)", n_created)
        _add("Delivered (RSU ACK)", n_delivered)
        _add("Delivery ratio (PDR)", _fmt_pct((n_delivered / n_created) if n_created else 0.0))

        _sec("Latency (delivered only)")
        if msg_df is not None and not msg_df.empty:
            lat = msg_df["latency_ms"].dropna()
            _add("Latency samples", int(len(lat)))
            if len(lat):
                _add("Latency mean (ms)", f"{lat.mean():.2f}")
                _add("Latency median (ms)", f"{lat.median():.2f}")
                _add("Latency p90 (ms)", f"{lat.quantile(0.90):.2f}")
                _add("Latency p95 (ms)", f"{lat.quantile(0.95):.2f}")
                _add("Latency max (ms)", f"{lat.max():.2f}")
        else:
            _add("Latency samples", 0)

        _sec("Hop / TTL (delivered only)")
        if msg_df is not None and not msg_df.empty and "hop_count" in msg_df.columns:
            hops = msg_df["hop_count"].dropna()
            _add("Hop samples", int(len(hops)))
            if len(hops):
                _add("Hop mean", f"{hops.mean():.2f}")
                _add("Hop median", f"{hops.median():.2f}")
                _add("Hop max", int(hops.max()))
        else:
            _add("Hop samples", 0)

        _sec("Overhead / redundancy")
        if msg_df is not None and not msg_df.empty:
            total_tx = int(msg_df["tx_count"].fillna(0).sum())
            total_dup = int(msg_df["duplicate_count"].fillna(0).sum())
            _add("Total DATA transmissions (seen)", total_tx)
            _add("Total duplicate transmissions (seen)", total_dup)
            _add("Avg TX per message", f"{(total_tx / n_created):.2f}" if n_created else "-")
            _add("TX per delivered message", f"{(total_tx / n_delivered):.2f}" if n_delivered else "-")
        else:
            _add("Total DATA transmissions (seen)", 0)
            _add("Total duplicate transmissions (seen)", 0)

        _sec("Channel load (from log timestamps)")
        if load_df is not None and not load_df.empty:
            fsec = load_df["frames"].astype(float)
            bsec = load_df["bytes"].astype(float)
            _add("Avg frames/sec", f"{fsec.mean():.2f}")
            _add("Peak frames/sec", int(fsec.max()))
            _add("p95 frames/sec", f"{fsec.quantile(0.95):.2f}")
            _add("Avg bytes/sec", f"{bsec.mean():.2f}")
            _add("Peak bytes/sec", int(bsec.max()))
            _add("p95 bytes/sec", f"{bsec.quantile(0.95):.2f}")

        _sec("Per-node (top origins)")
        if per_mobile_df is not None and not per_mobile_df.empty:
            origin_col = next((c for c in ["origin_id", "OriginID", "origin", "Origin"] if c in per_mobile_df.columns), None)
            created_col = next((c for c in ["created", "Created"] if c in per_mobile_df.columns), None)
            delivered_col = next((c for c in ["delivered", "Delivered"] if c in per_mobile_df.columns), None)

            if origin_col and created_col:
                topc = per_mobile_df.sort_values(created_col, ascending=False).head(5)
                _add(
                    "Top-5 origins by created",
                    ", ".join([f"{int(row[origin_col])}({int(row[created_col])})" for _, row in topc.iterrows()])
                )

            if origin_col and delivered_col:
                topd = per_mobile_df.sort_values(delivered_col, ascending=False).head(5)
                _add(
                    "Top-5 origins by delivered",
                    ", ".join([f"{int(row[origin_col])}({int(row[delivered_col])})" for _, row in topd.iterrows()])
                )

        return dict(messages=msg_df, per_mobile=per_mobile_df,
                    load=load_df, stats=stats_rows)

# ==========================================================
# Propagation path builder
# ==========================================================

def build_propagation_paths(
    log_path: str,
    origin_id: int,
    msg_id: int,
) -> dict:
    """Build a TTL-layered propagation layout for one (origin_id, msg_id).

    The log format is assumed to be Contiki/Cooja Mote_Communication.txt:
        time_ms 	 src 	 receivers 	 "LEN: 0x..."

    Output layout keys
    ------------------
    - origin_id: int
    - msg_id: int
    - ttl_start: int
    - rsu_id: int | None
    - rsu_ack_time: int | None
    - delivered: bool
    - delivered_by_origin: bool
    - rsu_deliverer: int | None
    - node_level: dict[int, int]          (origin is level 0)
    - parent: dict[int, int]              (best-effort parent for layout)
    - edges: list[tuple[int, int]]        (sender -> receiver)
    - ack_nodes: set[int]                (mobiles that sent ACK for this msg)
    - senders_seen: set[int]             (nodes that sent DATA for this msg)

    Notes
    -----
    - Levels come from TTL in wsan_data_payload_t: ttl8 = payload[16].
      If origin sent with ttl_start, then a sender with ttl_sent is:
          level(sender) = ttl_start - ttl_sent
      and every receiver observed in that transmission is placed at:
          level(receiver) = level(sender) + 1

    - RSU id is learned from RSU ACK frames that refer to (origin_id, msg_id).

    - receivers column is used as evidence of *who got the frame*.
      (This matches your log semantics.)

    - Mobile ACKs are collected and shown as nodes.
    """
    import re

    def _norm_hex(col: str) -> str:
        """Normalize the HEX column: strip prefix, spaces, 0x, uppercase."""
        if ":" in col:
            col = col.split(":", 1)[1]
        col = col.replace("0x", "").replace("0X", "")
        col = re.sub(r"\s+", "", col)
        return col.upper()

    def _recv_ids(recv: str) -> list[int]:
        """Parse numeric IDs from the receivers column."""
        if not recv:
            return []
        r = recv.strip()
        if r == "-":
            return []
        return [int(x) for x in re.findall(r"\d+", r)]

    data_events = []  # (t, sender, ttl, recv_ids)
    origin_ttls: list[int] = []
    ack_nodes: set[int] = set()

    rsu_id: int | None = None
    rsu_ack_time: int | None = None

    with open(log_path, "r", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            try:
                t = int(parts[0])
            except ValueError:
                continue

            recv_field = parts[2].strip()
            hx = _norm_hex(parts[3])
            if WSAN_SIG not in hx:
                continue

            frame = extract_wsan_frame(hx)
            if frame is None:
                continue

            ws = parse_wsan(frame)
            if ws is None:
                continue

            if not is_valid_id(ws["sender"]) or not is_valid_id(ws["origin"]):
                continue

            # RSU ACK => delivery & RSU id
            if ws["marker"] == MARK_RSU and ws["msg_type"] == WSAN_MSG_ACK:
                a = parse_ack(ws["payload"])
                if a:
                    acked_type, ao, am = a
                    if acked_type == WSAN_MSG_DATA and ao == origin_id and am == msg_id:
                        if rsu_ack_time is None or t < rsu_ack_time:
                            rsu_ack_time = t
                            rsu_id = ws["sender"]
                continue

            # Mobile ACK => collect ACK senders
            if ws["marker"] == MARK_MBL and ws["msg_type"] == WSAN_MSG_ACK:
                a = parse_ack(ws["payload"])
                if a:
                    acked_type, ao, am = a
                    if acked_type == WSAN_MSG_DATA and ao == origin_id and am == msg_id:
                        ack_nodes.add(int(ws["sender"]))
                continue

            # DATA only for this message
            if ws["msg_type"] != WSAN_MSG_DATA:
                continue
            if ws["origin"] != origin_id or ws["msg_id"] != msg_id:
                continue

            ttl = parse_ttl(ws["payload"])
            if ttl is None:
                continue

            sender = int(ws["sender"])
            recvs = _recv_ids(recv_field)

            data_events.append((t, sender, int(ttl), recvs))
            if sender == origin_id:
                origin_ttls.append(int(ttl))

    ttl_start = max(origin_ttls) if origin_ttls else TTL_DEFAULT

    node_level: dict[int, int] = {origin_id: 0}
    parent: dict[int, int] = {origin_id: origin_id}
    edges_set: set[tuple[int, int]] = set()
    senders_seen: set[int] = set()

    for (t, sender, ttl, recvs) in sorted(data_events, key=lambda x: x[0]):
        senders_seen.add(sender)
        s_level = max(0, ttl_start - ttl)
        if sender not in node_level or s_level < node_level[sender]:
            node_level[sender] = s_level

        for r in recvs:
            if not is_valid_id(r) or r == sender:
                continue
            r_level = s_level + 1
            if r not in node_level or r_level < node_level[r]:
                node_level[r] = r_level
            edges_set.add((sender, r))
            if r not in parent:
                parent[r] = sender

    # Add ACK-only nodes if not already present
    for a in sorted(ack_nodes):
        if a not in node_level:
            node_level[a] = 1
            parent[a] = origin_id
            edges_set.add((origin_id, a))

    edges = sorted(edges_set)

    delivered = rsu_id is not None
    delivered_by_origin = False
    rsu_deliverer: int | None = None

    if delivered and rsu_id is not None:
        best = None  # (t, sender)
        for (t, sender, _ttl, recvs) in data_events:
            if rsu_ack_time is not None and t > rsu_ack_time + 5000:
                continue
            if rsu_id in recvs:
                if best is None or t > best[0]:
                    best = (t, sender)
        if best is not None:
            rsu_deliverer = best[1]
            delivered_by_origin = (rsu_deliverer == origin_id)
    # Dead-end nodes: receivers of this message that never forwarded.
    dead_nodes = {nid for nid in node_level if nid not in senders_seen and nid not in (origin_id, rsu_id)}

    return dict(
        origin_id=origin_id,
        msg_id=msg_id,
        ttl_start=ttl_start,
        rsu_id=rsu_id,
        rsu_ack_time=rsu_ack_time,
        delivered=delivered,
        delivered_by_origin=delivered_by_origin,
        rsu_deliverer=rsu_deliverer,
        node_level=node_level,
        parent=parent,
        edges=edges,
        ack_nodes=set(ack_nodes),
        senders_seen=set(senders_seen),
        dead_nodes=set(dead_nodes),
    )


class PropagationWidget(QWidget):
    """Fan-out propagation view.

    Confirmed rules:
        - Draw ALL RSU reception paths that appear in edges (a -> RSU).
        - Dead-end paths (origin -> dead node) are DASHED.
        - All circles are CLOSED and FILLED.
        - Arrow heads end at the BORDER of the destination node.
        - If a receiver is reached from multiple senders, draw it multiple times.
    """

    _C_ORIGIN = QColor(186, 117, 20)     # amber
    _C_RSU    = QColor(83, 74, 183)      # purple
    _C_NODE   = QColor(29, 158, 117)     # teal
    _C_ACK    = QColor(80, 160, 255)     # blue
    _C_EDGE   = QColor(235, 235, 235)   # near-white

    _NODE_R = 18
    _HOP_R  = 14
    _ACK_R  = 12

    _MARGIN_X  = 90
    _LIMIT_DEG = 45.0

    def __init__(self, origin_id: int, msg_id: int, layout: dict, parent=None):
        super().__init__(parent)
        self.origin_id = origin_id
        self.msg_id = msg_id
        self.layout = layout or {}
        self.setMinimumSize(900, 500)
        self._font = QFont("Arial", 9)
        self._font_small = QFont("Arial", 8)

    def _spread_angles_excluding_zero(self, n: int, limit_deg: float) -> list[float]:
        if n <= 0:
            return []
        if n == 1:
            return [limit_deg if limit_deg else 15.0]
        raw = [(-limit_deg + 2 * limit_deg * i / n) for i in range(n + 1)]
        raw.sort(key=abs)
        raw = raw[1:]
        raw.sort(reverse=True)
        return raw[:n]

    def _pos_from_angle(self, ox: float, oy: float, r: float, ang_deg: float) -> QPointF:
        ang = math.radians(ang_deg)
        return QPointF(ox + r * math.cos(ang), oy - r * math.sin(ang))

    def _trim_segment(self, a: QPointF, b: QPointF, ra: float, rb: float) -> tuple[QPointF, QPointF] | None:
        dx = b.x() - a.x()
        dy = b.y() - a.y()
        ln = math.hypot(dx, dy)
        if ln < 1e-6:
            return None
        ux = dx / ln
        uy = dy / ln
        a2 = QPointF(a.x() + ux * ra, a.y() + uy * ra)
        b2 = QPointF(b.x() - ux * rb, b.y() - uy * rb)
        return a2, b2

    def _draw_arrow(self, p: QPainter, a: QPointF, b: QPointF,
                    ra: float, rb: float, pen: QPen) -> None:
        seg = self._trim_segment(a, b, ra, rb)
        if seg is None:
            return
        a2, b2 = seg

        p.setPen(pen)
        p.drawLine(a2, b2)

        # Arrow head at b2
        dx = b2.x() - a2.x()
        dy = b2.y() - a2.y()
        ln = math.hypot(dx, dy)
        if ln < 1e-6:
            return
        ux = dx / ln
        uy = dy / ln
        px = -uy
        py = ux

        head_len = 10.0
        head_w = 6.0

        tip = b2
        left = QPointF(b2.x() - ux * head_len + px * head_w,
                       b2.y() - uy * head_len + py * head_w)
        right = QPointF(b2.x() - ux * head_len - px * head_w,
                        b2.y() - uy * head_len - py * head_w)

        p.setBrush(QBrush(pen.color()))
        p.drawPolygon(QPolygonF([tip, left, right]))
        p.setBrush(Qt.NoBrush)

    def paintEvent(self, _event):
        W, H = self.width(), self.height()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(0, 0, W, H, QColor(0, 0, 0, 0))

        node_level: dict[int, int] = dict(self.layout.get("node_level", {}) or {})
        edges_raw: list[tuple[int, int]] = self.layout.get("edges", [])
        ack_nodes: set[int] = set(self.layout.get("ack_nodes", set()))
        dead_nodes: set[int] = set(self.layout.get("dead_nodes", set()))

        rsu_id = self.layout.get("rsu_id", None)
        delivered = bool(self.layout.get("delivered", False))

        # Collect nodes from edges, to keep relays visible
        all_nodes = set(node_level.keys())
        for a, b in edges_raw:
            all_nodes.add(int(a))
            all_nodes.add(int(b))
        all_nodes.add(int(self.origin_id))
        if rsu_id is not None:
            all_nodes.add(int(rsu_id))

        # Reserve level 0 for origin only
        for nid in list(all_nodes):
            if nid == self.origin_id:
                node_level[nid] = 0
            elif node_level.get(nid, 1) == 0:
                node_level[nid] = 1

        for nid in all_nodes:
            if nid not in node_level and nid not in (self.origin_id, rsu_id):
                node_level[nid] = 1

        ox = float(self._MARGIN_X)
        oy = H / 2.0
        max_lv = max(node_level.values()) if node_level else 0
        x_step = max(150.0, (W - 2 * self._MARGIN_X) / max(3.0, (max_lv + 1)))

        # Build incoming map (ignore dead senders)
        incoming: dict[int, list[int]] = {}
        for a, b in edges_raw:
            a = int(a); b = int(b)
            if a in dead_nodes:
                continue
            if b == self.origin_id:
                continue
            incoming.setdefault(b, []).append(a)
        for nid in incoming:
            incoming[nid] = sorted(set(incoming[nid]))

        # Instances (node, parent)
        origin_key = (self.origin_id, None)
        instances: dict[tuple[int, int | None], None] = {origin_key: None}

        for nid in sorted(all_nodes):
            if nid in (self.origin_id, rsu_id):
                continue
            if nid in dead_nodes:
                instances[(nid, self.origin_id)] = None
                continue
            parents = incoming.get(nid, []) or [self.origin_id]
            for par in parents:
                instances[(nid, par)] = None

        # Primary instance
        primary: dict[int, tuple[int, int | None]] = {self.origin_id: origin_key}
        for (nid, par) in instances:
            if nid == self.origin_id:
                continue
            cur = primary.get(nid)
            if cur is None:
                primary[nid] = (nid, par)
            else:
                if par == self.origin_id and cur[1] != self.origin_id:
                    primary[nid] = (nid, par)
                elif cur[1] not in (None, self.origin_id) and par not in (None, self.origin_id) and par < cur[1]:
                    primary[nid] = (nid, par)

        # Bucket instances by level
        level_keys: dict[int, list[tuple[int, int | None]]] = {}
        for (nid, par) in instances:
            lv = node_level.get(nid, 1)
            level_keys.setdefault(lv, []).append((nid, par))
        for lv in level_keys:
            level_keys[lv].sort(key=lambda k: (k[0], -1 if k[1] is None else k[1]))

        pos: dict[tuple[int, int | None], QPointF] = {origin_key: QPointF(ox, oy)}
        angs: dict[tuple[int, int | None], float] = {origin_key: 0.0}

        # Level 1 spread
        lvl1 = level_keys.get(1, [])
        a1 = self._spread_angles_excluding_zero(len(lvl1), self._LIMIT_DEG)
        for key, ang in zip(lvl1, a1):
            angs[key] = ang
            pos[key] = self._pos_from_angle(ox, oy, x_step, ang)

        # Deeper levels
        for lv in range(2, max_lv + 1):
            keys = level_keys.get(lv, [])
            if not keys:
                continue
            buckets: dict[int, list[tuple[int, int | None]]] = {}
            for key in keys:
                par = key[1] if key[1] is not None else self.origin_id
                buckets.setdefault(int(par), []).append(key)
            for par, kids in buckets.items():
                kids.sort(key=lambda k: (k[0], -1 if k[1] is None else k[1]))
                base = angs.get(primary.get(par, origin_key), 0.0)
                spread = max(8.0, self._LIMIT_DEG / (lv + 1))
                offs = [0.0] if len(kids) == 1 else [(-spread + 2 * spread * i / (len(kids) - 1)) for i in range(len(kids))]
                for kid, off in zip(kids, offs):
                    ang = max(-self._LIMIT_DEG, min(self._LIMIT_DEG, base + off))
                    if abs(ang) < 4.0:
                        ang = 4.0 if ang >= 0 else -4.0
                    angs[kid] = ang
                    pos[kid] = self._pos_from_angle(ox, oy, x_step * float(lv), ang)

        # RSU
        rsu_key = None
        if rsu_id is not None:
            rsu_key = (int(rsu_id), None)
        if delivered and rsu_key is not None:
            pos[rsu_key] = QPointF(ox + x_step * float(max_lv + 1), oy)

        # Pens
        pen_solid = QPen(self._C_EDGE, 2.6)
        pen_solid.setCapStyle(Qt.RoundCap)
        pen_solid.setStyle(Qt.SolidLine)

        pen_dead = QPen(self._C_EDGE, 2.0)
        pen_dead.setCapStyle(Qt.RoundCap)
        pen_dead.setStyle(Qt.DashLine)

        # Draw arrows between primary instances (solid)
        drawn = set()
        for a, b in edges_raw:
            a = int(a); b = int(b)
            if b == rsu_id:
                continue  # RSU handled separately below
            if a in dead_nodes or b in dead_nodes:
                continue
            if a not in primary or b not in primary:
                continue
            ka = primary[a]
            kb = primary[b]
            if ka in pos and kb in pos and (ka, kb) not in drawn:
                drawn.add((ka, kb))
                self._draw_arrow(p, pos[ka], pos[kb], self._HOP_R, self._HOP_R, pen_solid)

        # Dead-end arrows: origin -> dead node (dashed)
        for nid in sorted(dead_nodes):
            k = (int(nid), self.origin_id)
            if origin_key in pos and k in pos:
                self._draw_arrow(p, pos[origin_key], pos[k], self._NODE_R, self._HOP_R, pen_dead)

        # ALL RSU reception arrows: a -> RSU (solid)
        if delivered and rsu_key is not None and rsu_key in pos:
            for a, b in edges_raw:
                a = int(a); b = int(b)
                if b != int(rsu_id):
                    continue
                if a in dead_nodes:
                    continue
                if a not in primary:
                    continue
                ka = primary[a]
                if ka in pos:
                    self._draw_arrow(p, pos[ka], pos[rsu_key], self._HOP_R, self._NODE_R * 1.5, pen_solid)

        # Node drawing helper (ALWAYS filled)
        def _draw_node(pt: QPointF, label: str, color: QColor, r: int) -> None:
            p.setPen(QPen(color.darker(140), 2.0))
            p.setBrush(QBrush(color.lighter(150)))
            p.drawEllipse(pt, r, r)
            p.setPen(QPen(color.darker(200), 1))
            p.setFont(self._font)
            fm = QFontMetrics(self._font)
            tw = fm.horizontalAdvance(label)
            p.drawText(int(pt.x() - tw / 2), int(pt.y() + fm.ascent() / 2), label)

        # Origin
        _draw_node(pos[origin_key], str(self.origin_id), self._C_ORIGIN, self._NODE_R)

        # RSU diamond
        if delivered and rsu_key is not None and rsu_key in pos:
            pt = pos[rsu_key]
            d = int(self._NODE_R * 1.5)
            diamond = QPolygonF([
                QPointF(pt.x(), pt.y() - d),
                QPointF(pt.x() + d, pt.y()),
                QPointF(pt.x(), pt.y() + d),
                QPointF(pt.x() - d, pt.y()),
            ])
            p.setPen(QPen(self._C_RSU.darker(140), 2))
            p.setBrush(QBrush(self._C_RSU.lighter(160)))
            p.drawPolygon(diamond)
            p.setPen(QPen(self._C_RSU.darker(200), 1))
            p.setFont(self._font)
            fm = QFontMetrics(self._font)
            p.drawText(int(pt.x() - fm.horizontalAdvance("RSU") / 2),
                       int(pt.y() + fm.ascent() / 2 - 5), "RSU")
            p.drawText(int(pt.x() - fm.horizontalAdvance(str(rsu_id)) / 2),
                       int(pt.y() + fm.ascent() / 2 + 7), str(rsu_id))

        # Other instances
        for key, pt in pos.items():
            nid, par = key
            if nid in (self.origin_id, rsu_id):
                continue
            if nid in ack_nodes:
                _draw_node(pt, str(nid), self._C_ACK, self._ACK_R)
            else:
                _draw_node(pt, str(nid), self._C_NODE, self._HOP_R)

        # Legend
        legend = [
            ("Origin", self._C_ORIGIN),
            ("Relay/Receiver", self._C_NODE),
            ("ACK sender", self._C_ACK),
            ("Dead-end path", self._C_EDGE),
        ]
        box_h = 16
        pad = 8
        box_w = 210
        box_h_total = pad * 2 + box_h * (len(legend) + 2)
        lx = 16
        ly = max(16, H - box_h_total - 16)

        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(QColor(0, 0, 0, 160)))
        p.drawRoundedRect(QRectF(lx, ly, box_w, box_h_total), 6, 6)

        p.setFont(self._font_small)
        fm = QFontMetrics(self._font_small)
        cy = ly + pad

        for txt, col in legend:
            p.setPen(QPen(col.darker(140), 2))
            p.setBrush(QBrush(col.lighter(150)))
            p.drawEllipse(QPointF(lx + pad + 8, cy + 8), 6, 6)
            p.setBrush(Qt.NoBrush)
            p.setPen(QPen(QColor(245, 245, 245)))
            p.drawText(lx + pad + 20, cy + fm.ascent() + 2, txt)
            cy += box_h

        # Line style notes
        p.setPen(QPen(QColor(245, 245, 245)))
        p.drawText(lx + pad + 20, cy + fm.ascent() + 2, "Solid = reception")
        cy += box_h
        p.drawText(lx + pad + 20, cy + fm.ascent() + 2, "Dashed = dead-end")

        p.end()


class PropagationWindow(QMainWindow):
    def __init__(self, origin_id: int, msg_id: int, layout: dict):
        super().__init__()
        delivered = bool(layout.get("delivered", False)) if layout else False
        self.setWindowTitle(
            f"Propagation  {origin_id}:{msg_id:08X}  "
            f"({'delivered' if delivered else 'not delivered'})"
        )
        self.resize(950, 520)
        self.setCentralWidget(PropagationWidget(origin_id, msg_id, layout))


# ==========================================================
# GraphicsView Tree  (legacy hierarchical view)
# ==========================================================

# ==========================================================
# Main GUI
# ==========================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WSAN Analyzer")
        self.resize(1300,800)
        self.messages_df=None
        self.per_mobile_df=None
        self.load_df=None
        self.signals=WorkerSignals()
        self._build_ui()
        self._wire()
        self._tree_windows = []
        self.log_path = None

    def _build_ui(self):
        c=QWidget(); self.setCentralWidget(c)
        v=QVBoxLayout(c)

        top=QHBoxLayout()
        self.btn_open=QPushButton("[Open Log File]")
        self.btn_open.setToolTip("Open Mote_Communication.txt and parse it")
        self.btn_open.clicked.connect(self.open_file)
        top.addWidget(self.btn_open)
        self.progress=QProgressBar(); top.addWidget(self.progress)
        v.addLayout(top)

        self.statusBar().showMessage("Ready.")

        self.tabs = QTabWidget()
        v.addWidget(self.tabs)

        # Messages tab
        tab_msg = QWidget()
        tab_msg_l = QVBoxLayout(tab_msg)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["TimeCreated","TimeDelivered","Latency",
             "OriginID","MsgID","Type","Delivered","HexNorm"]
        )
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)
        tab_msg_l.addWidget(self.table)
        self.tabs.addTab(tab_msg, "Messages")

        # Log Stats tab
        tab_stats = QWidget()
        tab_stats_l = QVBoxLayout(tab_stats)
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        # Enable Excel-like selection and copying (Ctrl+C).
        self.stats_table.setSelectionMode(
            QAbstractItemView.ExtendedSelection
        )
        self.stats_table.setSelectionBehavior(
            QAbstractItemView.SelectItems
        )
        self.stats_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )
        self.stats_table.setFocusPolicy(Qt.StrongFocus)
        self.stats_table.installEventFilter(self)
        self.stats_table.setContextMenuPolicy(
            Qt.CustomContextMenu
        )
        self.stats_table.customContextMenuRequested.connect(
            self._stats_table_menu
        )

        self.stats_table.horizontalHeader().setStretchLastSection(True)
        tab_stats_l.addWidget(self.stats_table)
        self.tabs.addTab(tab_stats, "Log Stats")

    def _wire(self):
        self.signals.progress.connect(lambda p:self.progress.setValue(int(p*100)))
        self.signals.finished.connect(self.on_finished)
        self.signals.error.connect(lambda e:QMessageBox.critical(self,"Error",e))
        self.signals.watchdog.connect(self.on_watchdog)

    def open_file(self):
        path,_=QFileDialog.getOpenFileName(self,"Open Log File","","Text files (*.txt)")
        if not path:
            self.statusBar().showMessage("Open cancelled.")
            return
        self.log_path = path
        self.statusBar().showMessage(f"Parsing {path} ...")
        self.progress.setValue(0)
        self.worker=ParserThread(Path(path),self.signals)
        self.worker.start()

    def on_finished(self,res):
        self.messages_df=res["messages"]
        self.per_mobile_df=res["per_mobile"]
        self.load_df=res["load"]
        self.stats = res.get("stats", {})
        self.populate()
        self.populate_stats()
        if self.messages_df is None or len(self.messages_df) == 0:
            self.statusBar().showMessage(
                "Parsed 0 messages. Check that the log contains WSAN frames "
                "and that created messages exist (sender==origin)."
            )
            QMessageBox.warning(
                self,
                "No messages found",
                "Parsed 0 messages.\n\n"
                "Possible reasons:\n"
                "- The file is not a Mote_Communication log.\n"
                "- WSAN frames are not present or checksum validation dropped them.\n"
                "- No frames matched 'created' rule (sender==origin).\n"
            )
            return
        self.statusBar().showMessage(
            f"Loaded {len(self.messages_df)} messages"
        )
        QMessageBox.information(self,"Done","Log file parsed successfully.")

    def populate(self):
        df=self.messages_df
        self.table.setRowCount(len(df))
        for r,row in enumerate(df.itertuples(index=False)):
            vals=[row.time_created_ms,row.time_delivered_ms,row.latency_ms,
                  row.origin_id,row.msg_id,row.msg_type,row.delivered,
                  getattr(row, "hex_norm", "")]
            for c,v in enumerate(vals):
                self.table.setItem(r,c,QTableWidgetItem("" if v is None else str(v)))
    def populate_stats(self):
        """Populate the Log Stats table from a list of (metric, value) rows."""
        rows = getattr(self, "stats", []) or []
        self.stats_table.setRowCount(len(rows))

        for i, (k, v) in enumerate(rows):
            it_k = QTableWidgetItem(str(k))
            it_v = QTableWidgetItem(str(v))

            if str(k).startswith("==") and str(k).endswith("=="):
                f = it_k.font()
                f.setBold(True)
                it_k.setFont(f)
                it_v.setFont(f)
                it_v.setText("")

            self.stats_table.setItem(i, 0, it_k)
            self.stats_table.setItem(i, 1, it_v)


    def _copy_table_selection(self, table: QTableWidget) -> None:
        # Copy selected cells from a QTableWidget into clipboard as TSV.
        # Paste target: Excel / Google Sheets.
        # Uses: selectedIndexes(), item(), QApplication.clipboard().
        indexes = table.selectedIndexes()
        if not indexes:
            return

        indexes = sorted(indexes, key=lambda i: (i.row(), i.column()))
        all_cols = sorted({i.column() for i in indexes})

        rows: dict[int, dict[int, str]] = {}
        for idx in indexes:
            r = idx.row()
            c = idx.column()
            item = table.item(r, c)
            txt = "" if item is None else item.text()
            rows.setdefault(r, {})[c] = txt

        tsv_lines: list[str] = []
        for r in sorted(rows.keys()):
            tsv_lines.append("\t".join([rows[r].get(c, "")
                                          for c in all_cols]))

        QApplication.clipboard().setText("\n".join(tsv_lines))

    def _stats_table_menu(self, pos) -> None:
        # Context menu for the Metrics/Log Stats table.
        menu = QMenu(self.stats_table)
        act_copy = QAction("Copy", self)
        act_copy.triggered.connect(
            lambda: self._copy_table_selection(self.stats_table)
        )
        menu.addAction(act_copy)
        menu.exec(self.stats_table.viewport().mapToGlobal(pos))

    def eventFilter(self, obj, event):
        # Intercept Ctrl+C on the Metrics table and copy selection as TSV.
        if obj is getattr(self, "stats_table", None):
            if event.type() == QEvent.Type.KeyPress:
                if (event.key() == Qt.Key_C and
                        (event.modifiers() & Qt.ControlModifier)):
                    self._copy_table_selection(self.stats_table)
                    return True
        return super().eventFilter(obj, event)

    def on_watchdog(self,ticket):
        m = QMessageBox(self)
        m.setText("This is taking too long. Continue?")
        m.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        cb = QCheckBox("Don't ask again")
        m.setCheckBox(cb)
        r = m.exec()
        ticket.allow = (r == QMessageBox.Yes)
        ticket.dont_ask_again = cb.isChecked()
        ticket.release()

    def show_propagation(self, origin: int, msg: int):
        """Build and show the left→right propagation path view."""
        if not self.log_path:
            QMessageBox.warning(self, "No log", "No log file loaded.")
            return

        if self.messages_df is not None:
            ok = ((self.messages_df["origin_id"] == origin) &
                  (self.messages_df["msg_id"] == msg)).any()
            if not ok:
                QMessageBox.information(
                    self, "Not created in log",
                    "This message has no creation point in the log "
                    "(sender==origin was never observed)."
                )
                return

        layout = build_propagation_paths(
            self.log_path, origin, msg
        )

        win = PropagationWindow(origin, msg, layout)
        self._tree_windows.append(win)
        win.show()

    def context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        r = idx.row()
        origin    = int(self.table.item(r, 3).text())
        msg       = int(self.table.item(r, 4).text())
        delivered = self.table.item(r, 6).text() == "True"

        menu = QMenu(self)

        act_prop = QAction("Show propagation paths  (L→R view)", self)
        act_prop.triggered.connect(lambda: self.show_propagation(origin, msg))
        menu.addAction(act_prop)

        menu.exec(self.table.viewport().mapToGlobal(pos))

# ==========================================================
# Entry point
# ==========================================================

def main():
    app=QApplication(sys.argv)
    w=MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()