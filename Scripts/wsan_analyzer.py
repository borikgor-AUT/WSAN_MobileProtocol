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
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Tuple, List, Set

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("QtAgg")
import matplotlib.pyplot as plt

from PySide6.QtCore import Qt, QObject, Signal, Slot, QPointF
from PySide6.QtGui import QPen, QBrush, QAction
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog,
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QTableWidget, QTableWidgetItem,
    QLineEdit, QMessageBox, QCheckBox, QSlider,
    QTabWidget, QGroupBox, QGridLayout,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QTabWidget, QMenu
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

def find_all_paths_to_rsu(start_node, edges_list, rsu_target):
    """
    Find all simple paths from start_node to rsu_target.

    This function walks FORWARD along directed edges (parent -> child).
    It may scan edges_list on each step (O(V*E)) which is fine for small
    WSAN trees. It creates:
      - paths: list of node lists, each representing a path
      - visited: set used to prevent cycles
    """
    paths = []

    def dfs(node, path, visited):
        """
        Depth-first traversal that follows parent->child edges.

        Uses:
          - edges_list as an edge source (parent, child, ...)
          - visited to avoid cycles
        """
        if node == rsu_target:
            paths.append(path[:])
            return

        visited.add(node)

        for (parent, child, _) in edges_list:
            if parent == node and child not in visited:
                path.append(child)
                dfs(child, path, visited)
                path.pop()

        visited.remove(node)

    if rsu_target is not None:
        dfs(start_node, [start_node], set())

    return paths

def build_friend_ack_tree_from_log(
    log_path: str,
    origin_id: int,
    msg_id: int,
    ack_window_ms: int = 2000,
) -> tuple[dict[int, int], list[tuple[int, int]], bool, int | None]:
    """
    Build friend-ACK edges for one message (origin_id, msg_id).

    Returns:
        parent_map: child -> parent (first-parent tree)
        all_edges: list of (parent, child) for all valid edges
        delivered: whether RSU ACK exists for this message
        last_hop_to_rsu: mote id that likely delivered DATA to RSU (or None)

    Strategy:
      - Collect DATA transmissions for this key:
          time, sender_id, friend1, friend2, receiver_field
      - Collect ACK events (Mbl ACK only) for this key:
          time, ack_sender
      - Determine RSU delivery:
          time of RSU ACK (strict delivered)
          last_hop_to_rsu = most recent DATA with receiver != '-' before RSU ACK
      - Link ACK sender B to parent A by selecting the latest DATA(A)
        such that B is in {friend1, friend2} and DATA_time <= ACK_time
        and (ACK_time - DATA_time) <= ack_window_ms
    """
    # Local helpers (same logic as your main parser):
    import re

    def _norm_hex(col: str) -> str:
        if ":" in col:
            col = col.split(":", 1)[1]
        col = col.replace("0x", "").replace("0X", "")
        col = re.sub(r"\s+", "", col)
        return col.upper()

    data_events = []  # (t, sender, f1, f2, recv_field)
    ack_events = []   # (t, ack_sender)
    rsu_ack_time = None

    # Scan the file (on-demand)
    with open(log_path, "r", errors="replace") as f:
        for line in f:
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

            # Only care about this message key
            if ws["origin"] != origin_id or ws["msg_id"] != msg_id:
                # Special case: RSU ACK refers to (acked_origin, acked_msg),
                # not its own origin/msg_id. We'll handle below.
                pass

            # 1) RSU ACK delivery detection
            if ws["marker"] == MARK_RSU and ws["msg_type"] == WSAN_MSG_ACK:
                a = parse_ack(ws["payload"])
                if a:
                    acked_type, ao, am = a
                    if ao == origin_id and am == msg_id:
                        if rsu_ack_time is None or t < rsu_ack_time:
                            rsu_ack_time = t
                continue

            # 2) DATA events for this key
            if ws["msg_type"] == WSAN_MSG_DATA:
                if ws["origin"] != origin_id or ws["msg_id"] != msg_id:
                    continue
                fr = parse_friends(ws["payload"])
                if fr is None:
                    continue
                f1, f2 = fr
                data_events.append((t, ws["sender"], f1, f2, recv_field))
                continue

            # 3) Mbl ACK events for this key
            if ws["marker"] == MARK_MBL and ws["msg_type"] == WSAN_MSG_ACK:
                a = parse_ack(ws["payload"])
                if a:
                    acked_type, ao, am = a
                    if acked_type == WSAN_MSG_DATA and ao == origin_id and am == msg_id:
                        ack_events.append((t, ws["sender"]))
                continue

    delivered = rsu_ack_time is not None

    # Find last hop to RSU (only if delivered)
    last_hop_to_rsu = None
    if delivered:
        # latest DATA to RSU before RSU ACK
        cand = [
            (t, sender) for (t, sender, f1, f2, rcv) in data_events
            if rcv != "-" and t <= rsu_ack_time
        ]
        if cand:
            cand.sort()
            last_hop_to_rsu = cand[-1][1]

    # Build edges by linking ACKs to last matching DATA parent
    data_events.sort()   # by time
    ack_events.sort()

    all_edges = []
    parent_map = {}  # child -> parent (first parent)

    # Index DATA by sender (for quick search)
    by_sender = {}
    for ev in data_events:
        by_sender.setdefault(ev[1], []).append(ev)

    def _is_friend(ack_sender: int, f1: int, f2: int) -> bool:
        if ack_sender == FRIEND_EMPTY:
            return False
        return (ack_sender == f1) or (ack_sender == f2)

    # For each ACK, find the closest-in-time parent DATA that listed
    # ack_sender as a friend and was sent within ack_window_ms before
    # the ACK.  We want the LATEST such DATA across all senders (most
    # recent = most likely the trigger).
    for (t_ack, ack_sender) in ack_events:
        best_t = -1
        best_parent = None
        for parent_sender, evs in by_sender.items():
            # evs is sorted ascending by time; walk newest-first.
            for (t_data, s, f1, f2, _rcv) in reversed(evs):
                if t_data > t_ack:
                    # Future event; keep scanning older ones.
                    continue
                if t_ack - t_data > ack_window_ms:
                    # Too old; all remaining events for this sender are older.
                    break
                if _is_friend(ack_sender, f1, f2):
                    if t_data > best_t:
                        best_t = t_data
                        best_parent = parent_sender
                    break   # found the latest qualifying event for this sender

        if best_parent is None:
            continue

        all_edges.append((best_parent, ack_sender))
        if ack_sender not in parent_map:
            # First (earliest ACK) determines the primary parent for BFS layout.
            parent_map[ack_sender] = best_parent
        # all_edges always records every edge so the full propagation
        # graph is available for the "show all paths" view.

    # Ensure origin exists as root (even if it has no children)
    parent_map.setdefault(origin_id, origin_id)

    return parent_map, all_edges, delivered, last_hop_to_rsu
    
# ==========================================================
# Streaming parser thread
# ==========================================================

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

        stats = {
            "Total lines": total_lines,
            "WSAN frames found": wsan_lines,
            "WSAN frames extracted": extracted_frames,
            "Marker Mbl": by_marker.get("Mbl", 0),
            "Marker RSU": by_marker.get("RSU", 0),
            "Type QUERY (0)": by_type.get(0, 0),
            "Type ACK (1)": by_type.get(1, 0),
            "Type DATA (2)": by_type.get(2, 0),
            "Type EMERG (4)": by_type.get(4, 0),
            "Unique created messages (sender==origin)": len(created),
            "Unique DATA messages seen": len(set(tx_count.keys())),
            "Delivered (RSU ACK)": len(delivered),
        }
        return dict(messages=msg_df, per_mobile=per_mobile_df,
                    load=load_df, stats=stats)

# ==========================================================
# GraphicsView Tree
# ==========================================================

class TreeView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self._panning = False
        self._pan_start = QPointF()

    def wheelEvent(self, e):
        self.scale(1.25 if e.angleDelta().y()>0 else 0.8,
                   1.25 if e.angleDelta().y()>0 else 0.8)


    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._panning = True
            self._pan_start = e.position()  # QPointF in Qt6
            self.setCursor(Qt.ClosedHandCursor)
        super().mousePressEvent(e)


    def mouseMoveEvent(self, e):
        if self._panning:
            cur = e.position()
            d = self.mapToScene(cur.toPoint()) - self.mapToScene(
                self._pan_start.toPoint()
            )
            self.translate(-d.x(), -d.y())
            self._pan_start = cur
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self,e):
        self._panning=False
        self.setCursor(Qt.ArrowCursor)
        super().mouseReleaseEvent(e)

class TreeWindow(QMainWindow):

    def __init__(self, title, nodes, edges, rsu=None):
        super().__init__()
        self.setWindowTitle(title)
        self.resize(900, 650)

        self.scene = QGraphicsScene(self)
        self.view = TreeView(self.scene)
        self.setCentralWidget(self.view)

        # Draw edges first (so nodes sit on top)
        for a, b, bold in edges:
            if a not in nodes or b not in nodes:
                continue
            p1 = nodes[a]
            p2 = nodes[b]
            line = QGraphicsLineItem(p1.x(), p1.y(), p2.x(), p2.y())
            pen = QPen(
                Qt.black,
                3 if bold else 1,
                Qt.SolidLine if bold else Qt.DashLine,
            )
            line.setPen(pen)
            self.scene.addItem(line)

        # Draw nodes
        for nid, p in nodes.items():
            r = 16 if (rsu is not None and nid == rsu) else 10
            circ = QGraphicsEllipseItem(p.x() - r, p.y() - r, 2 * r, 2 * r)
            circ.setBrush(QBrush(Qt.white))
            circ.setPen(QPen(Qt.black, 2))
            self.scene.addItem(circ)

            txt = self.scene.addText(str(nid))
            txt.setPos(p.x() + r + 2, p.y() - r)

        # Fit view after all items have been added.
        self.scene.setSceneRect(self.scene.itemsBoundingRect())
        self.view.fitInView(self.scene.sceneRect(), Qt.KeepAspectRatio)

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
        stats = getattr(self, "stats", {}) or {}
        self.stats_table.setRowCount(len(stats))
        for i, (k, v) in enumerate(stats.items()):
            self.stats_table.setItem(i, 0, QTableWidgetItem(str(k)))
            self.stats_table.setItem(i, 1, QTableWidgetItem(str(v)))
    def show_tree(self, origin: int, msg: int, delivered_flag: bool):
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
                    "(sender==origin was never observed), so it is ignored."
                )
                return

        parent_map, all_edges, delivered, last_hop = (
            build_friend_ack_tree_from_log(self.log_path, origin, msg)
        )

        # Use all_edges so every propagation path is visible, including
        # branches that never reached the RSU.
        # Deduplicate edges (same (parent, child) pair may appear multiple
        # times if a node sent several retries that all got ACKed).
        seen_edges: set = set()
        edges_to_draw = []
        children: dict = {}

        for (p, c) in all_edges:
            key = (p, c)
            if key in seen_edges or p == c:
                continue
            seen_edges.add(key)
            # Bold edge = path that leads to or from the RSU delivery hop.
            bold = delivered and last_hop is not None and (
                c == last_hop or p == last_hop
            )
            edges_to_draw.append((p, c, bold))
            children.setdefault(p, []).append(c)

        # Ensure origin appears even when it has no outgoing edges.
        if not edges_to_draw:
            pass  # origin-only tree is fine

        # RSU node: add only if delivery was confirmed.
        rsu_node = None
        if delivered and last_hop is not None:
            rsu_node = 999   # display-only pseudo-node
            rsu_edge_key = (last_hop, rsu_node)
            if rsu_edge_key not in seen_edges:
                edges_to_draw.append((last_hop, rsu_node, True))
                children.setdefault(last_hop, []).append(rsu_node)

        # --- Layout: BFS levels from origin ----------------------------
        # level  -> Y axis (tree grows downward)
        # sibling index -> X axis (siblings spread horizontally)
        levels = {origin: 0}
        q = [origin]
        while q:
            u = q.pop(0)
            for v in children.get(u, []):
                if v not in levels:
                    levels[v] = levels[u] + 1
                    q.append(v)

        # Nodes reachable only via multi-parent edges may not be in BFS
        # tree yet; assign them the level of their earliest-known parent.
        for (p, c, _b) in edges_to_draw:
            if c not in levels and p in levels:
                levels[c] = levels[p] + 1

        if rsu_node is not None and rsu_node not in levels:
            levels[rsu_node] = max(levels.values()) + 1

        # Group nodes by level; sort siblings for deterministic layout.
        level_nodes: dict = {}
        for nid, lv in levels.items():
            level_nodes.setdefault(lv, []).append(nid)

        H_SPACING = 160   # horizontal gap between siblings (px)
        V_SPACING = 120   # vertical gap between levels (px)

        nodes: dict = {}
        for lv in sorted(level_nodes.keys()):
            siblings = sorted(level_nodes[lv])
            n = len(siblings)
            # Centre siblings around x=0.
            for i, nid in enumerate(siblings):
                x = (i - (n - 1) / 2.0) * H_SPACING
                y = lv * V_SPACING
                nodes[nid] = QPointF(x, y)

        title = f"Message {origin}:{msg:08X}  —  {'Delivered' if delivered else 'NOT delivered'}"
        win = TreeWindow(title, nodes, edges_to_draw, rsu_node)
        self._tree_windows.append(win)
        win.show()

    def on_watchdog(self, ticket):
        m = QMessageBox(self)
        m.setText("Parsing is taking a long time. Continue?")
        m.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        cb = QCheckBox("Don't ask again")
        m.setCheckBox(cb)
        r = m.exec()
        ticket.allow = (r == QMessageBox.Yes)
        ticket.dont_ask_again = cb.isChecked()
        ticket.release()

    def context_menu(self,pos):
        idx=self.table.indexAt(pos)
        if not idx.isValid():
            return
        r=idx.row()
        origin=int(self.table.item(r,3).text())
        msg=int(self.table.item(r,4).text())
        delivered=self.table.item(r,6).text()=="True"

        menu = QMenu(self)
        act = QAction("Show distribution tree", self)
        act.triggered.connect(lambda: self.show_tree(origin, msg, delivered))
        menu.addAction(act)
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