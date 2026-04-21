#!/usr/bin/env python3
"""
WSAN Log Viewer (fixed columns + Excel-like multi-filters)

- Parses metadata columns before ':' (tab-separated):
  Time(ms), TranslatorID, MotesInRange, messageLength.  [1](https://autuni-my.sharepoint.com/personal/twv1212_autuni_ac_nz/Documents/Microsoft%20Copilot%20Chat%20Files/WSAN%20Protocol%20Analyzer%20Functional%20Specification.pdf)
- Normalizes the hex dump after ':' (no blanks/tabs/newlines).
- Searches for "WSAN" signature (0x5753414E) inside the hex and decodes
  the WSAN wire frame fields as defined in wsan_protocol.h. [2](https://autuni-my.sharepoint.com/personal/twv1212_autuni_ac_nz/Documents/Microsoft%20Copilot%20Chat%20Files/wsan_analyzer.py)
- Shows a fixed set of columns in a maximized window.
- Adds per-column filters with:
    * OR inside a column using '|', e.g. 'DATA|QUERY'
    * Empty/non-empty tests: '{empty}', '{nonempty}'
    * Negation using '!', e.g. '!QUERY', '!{empty}'
  Filters across different columns combine with AND.
"""

from __future__ import annotations

import os
import re
import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import filedialog, ttk
from typing import Dict, List, Optional, Tuple


# --- Constants for WSAN parsing (wire format from wsan_protocol.h) ----
WSAN_SIG_HEX = "5753414E"   # ASCII "WSAN" as hex
WSAN_MIN_FRAME_LEN = 32     # wsan_parse() requires >= 32 bytes
U32_BROADCAST = 0xFFFFFFFF

MSGTYPE_NAME = {
    0: "QUERY",
    1: "ACK",
    2: "DATA",
    4: "EMERGENCY",
}

# --- Column definitions (requested order / naming) --------------------
COLUMNS = [
    ("time_ms", "Time"),
    ("translator_id", "TranslatorID"),
    ("sender_id", "SenderID"),
    ("role", "Role"),
    ("type_name", "Type"),
    ("msg_id", "MsgID"),
    ("target_id", "TargetID"),
    ("ts_ms", "Time Created"),
    ("origin_id", "OriginID"),
    ("payload_dec", "Payload"),
    ("payload_hex", "Payload [HEX]"),
    ("cs_ok", "Checksum"),
    ("raw_hex", "RAW"),
]


@dataclass
class WsanParsed:
    """
    What: Container for parsed WSAN fields for one line.
    Methods: Data-only dataclass.
    Creates: Stores decoded WSAN fields and validation flags.
    """
    found: bool = False
    error: str = ""

    marker: str = ""
    sender_id: Optional[int] = None
    msg_type: Optional[int] = None
    msg_type_name: str = ""
    msg_id: Optional[int] = None
    target_id: Optional[int] = None
    origin_id: Optional[int] = None
    ts_ms: Optional[int] = None

    payload_hex: str = ""
    payload_decoded: str = ""

    cs_ok: Optional[bool] = None


class Tooltip:
    """
    What: Simple tooltip for Tkinter widgets (hover help).
    Methods: Show/hide a small toplevel window on Enter/Leave.
    Creates: A Toplevel window with a Label when visible.
    """
    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text
        self.tipwin: Optional[tk.Toplevel] = None

        self.widget.bind("<Enter>", self._show)
        self.widget.bind("<Leave>", self._hide)

    def _show(self, _ev=None) -> None:
        """
        What: Show tooltip near the mouse pointer.
        Methods: Create a borderless Toplevel positioned by pointer coords.
        Creates: Tooltip window and label.
        """
        if self.tipwin is not None:
            return

        x = self.widget.winfo_pointerx() + 12
        y = self.widget.winfo_pointery() + 12

        tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        lbl = ttk.Label(
            tw,
            text=self.text,
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            padding=(6, 4),
        )
        lbl.pack()

        self.tipwin = tw

    def _hide(self, _ev=None) -> None:
        """
        What: Hide tooltip.
        Methods: Destroy the tooltip window if it exists.
        Creates: None.
        """
        if self.tipwin is not None:
            self.tipwin.destroy()
            self.tipwin = None


def _hex_to_bytes(hex_str: str) -> Optional[bytes]:
    """
    What: Convert a hex string to bytes safely.
    Methods: Validates even length; uses bytes.fromhex().
    Creates: None (returns bytes or None on error).
    """
    if not hex_str:
        return b""
    if len(hex_str) % 2 != 0:
        return None
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        return None


def _u32_be(b: bytes, off: int) -> int:
    """
    What: Read a 32-bit unsigned integer in Big-Endian from b[off..off+3].
    Methods: int.from_bytes(..., 'big').
    Creates: None.
    """
    return int.from_bytes(b[off:off + 4], byteorder="big", signed=False)


def _i16_le(b: bytes, off: int) -> int:
    """
    What: Read a 16-bit signed integer in Little-Endian from b[off..off+1].
    Methods: int.from_bytes(..., 'little', signed=True).
    Creates: None.
    """
    return int.from_bytes(b[off:off + 2], byteorder="little", signed=True)


def _u16_le(b: bytes, off: int) -> int:
    """
    What: Read a 16-bit unsigned integer in Little-Endian from b[off..off+1].
    Methods: int.from_bytes(..., 'little', signed=False).
    Creates: None.
    """
    return int.from_bytes(b[off:off + 2], byteorder="little", signed=False)


def _chk8_sum_lsb(buf: bytes) -> int:
    """
    What: Compute WSAN Chk8 = LSB of sum of bytes over the given buffer.
    Methods: Linear sum and AND 0xFF (matches wsan_chk8()).
    Creates: Local accumulator integer.
    """
    s = 0
    for x in buf:
        s += x
    return s & 0xFF


def normalize_hex_blob(hex_blob: str) -> str:
    """
    What: Normalize a hex dump string by removing whitespace and keeping
          only hex digits.
    Methods: Regex filter for [0-9A-Fa-f] groups and join.
    Creates: Uppercased normalized hex string.
    """
    if not hex_blob:
        return ""
    only_hex = re.findall(r"[0-9A-Fa-f]+", hex_blob)
    return "".join(only_hex).upper()


def split_log_line(line: str) -> Tuple[List[str], str]:
    """
    What: Split one log line into metadata fields and normalized hex.
    Methods:
      - Split at first ':' into left(meta) and right(hex).
      - Meta is tab-separated; keep all fields.
      - Hex part may include '0x' prefix.
    Creates:
      - meta_fields: list[str]
      - hex_norm: normalized hex string (no blanks)
    """
    line = line.rstrip("\r\n")
    if ":" not in line:
        meta = re.split(r"\t+", line.strip()) if line.strip() else []
        return meta, ""

    left, right = line.split(":", 1)
    meta_fields = re.split(r"\t+", left.strip()) if left.strip() else []

    hex_raw = right.strip()
    if hex_raw.lower().startswith("0x"):
        hex_raw = hex_raw[2:]

    return meta_fields, normalize_hex_blob(hex_raw)


def format_target_id(v: Optional[int]) -> str:
    """
    What: Format TargetID with Broadcast substitution for 0xFFFFFFFF.
    Methods: Replace U32_BROADCAST with "Broadcast".
    Creates: Formatted string.
    """
    if v is None:
        return ""
    if v == U32_BROADCAST:
        return "Broadcast"
    return str(v)


def decode_payload(msg_type: Optional[int], payload: bytes) -> str:
    """
    What: Decode known WSAN payload layouts into a readable string.
    Methods:
      - QUERY: 5 bytes (ef_flag + ef_origin_id BE).
      - ACK:   9 bytes (acked_type + acked_origin BE + acked_msg BE).
      - DATA:  17 bytes (x,y,v,dir,rssi,f1,f2,ttl) per wsan_protocol.h.
      - EMERGENCY: "EFBR"+code+metrics(7) => 12 bytes.
    Creates: Human-readable payload string; "" if unknown.
    """
    if msg_type is None:
        return ""

    try:
        if msg_type == 0 and len(payload) >= 5:
            ef_flag = payload[0]
            ef_origin = int.from_bytes(payload[1:5], "big", signed=False)
            return f"ef_flag={ef_flag} ef_origin={ef_origin}"

        if msg_type == 1 and len(payload) >= 9:
            acked_type = payload[0]
            acked_origin = int.from_bytes(payload[1:5], "big", signed=False)
            acked_msg = int.from_bytes(payload[5:9], "big", signed=False)
            at_name = MSGTYPE_NAME.get(acked_type, f"{acked_type}")
            return (f"acked_type={at_name} acked_origin={acked_origin} "
                    f"acked_msg={acked_msg}")

        if msg_type == 2 and len(payload) >= 17:
            # DATA payload layout from wsan_protocol.h:
            # x_dm(int16 LE), y_dm(int16 LE), v_dmps(u16 LE), dir8(u8),
            # rssi_dbm(int8), friend1(u32 BE), friend2(u32 BE), ttl8(u8)
            x = _i16_le(payload, 0)
            y = _i16_le(payload, 2)
            v = _u16_le(payload, 4)
            dir8 = payload[6]
            rssi = int.from_bytes(payload[7:8], "big", signed=True)
            f1 = int.from_bytes(payload[8:12], "big", signed=False)
            f2 = int.from_bytes(payload[12:16], "big", signed=False)
            ttl = payload[16]

            f1_s = "Empty" if f1 == U32_BROADCAST else str(f1)
            f2_s = "Empty" if f2 == U32_BROADCAST else str(f2)

            return (f"x_dm={x} y_dm={y} v_dmps={v} dir8={dir8} rssi={rssi} "
                    f"f1={f1_s} f2={f2_s} ttl={ttl}")

        if msg_type == 4 and len(payload) >= 12:
            if payload[0:4] != b"EFBR":
                return "EF payload: missing 'EFBR' signature"
            code = payload[4]
            x = _i16_le(payload, 5)
            y = _i16_le(payload, 7)
            v = _u16_le(payload, 9)
            dir8 = payload[11]
            return f"ef_code={code} x_dm={x} y_dm={y} v_dmps={v} dir8={dir8}"

    except Exception as e:
        return f"decode_error={e}"

    return ""


def parse_wsan_from_hexnorm(hex_norm: str) -> WsanParsed:
    """
    What: Locate and parse a WSAN frame inside normalized hex.
    Methods:
      - Find "WSAN" signature inside capture.
      - Parse wire fields as in wsan_protocol.h:
        "WSAN"(4) + MsgLen(3) + Marker(3) + SenderID(4) + MsgType(1) +
        MsgID(4) + TargetID(4) + OriginID(4) + Payload + TimeStamp(4) + CS(1).
      - Validate checksum Chk8 (LSB sum of bytes before CS).
    Creates: WsanParsed with decoded fields or error.
    """
    res = WsanParsed()
    if not hex_norm:
        return res

    idx = hex_norm.find(WSAN_SIG_HEX)
    if idx < 0:
        return res

    wsan_hex = hex_norm[idx:]
    b = _hex_to_bytes(wsan_hex)
    if b is None:
        res.error = "Invalid WSAN hex substring"
        return res

    if len(b) < WSAN_MIN_FRAME_LEN:
        res.error = f"Too short for WSAN ({len(b)} bytes)"
        return res

    if b[0:4] != b"WSAN":
        res.error = "Signature mismatch after WSAN search"
        return res

    # MsgLen is 3 bytes at offsets 4..6. The body length uses bytes 5..6.
    body_len = (b[5] << 8) | b[6]
    frame_len = 7 + body_len  # 4+3 + body_len

    if len(b) < frame_len:
        res.error = f"Truncated WSAN: need {frame_len}, have {len(b)}"
        return res

    frame = b[:frame_len]
    cs_got = frame[-1]
    cs_calc = _chk8_sum_lsb(frame[:-1])
    res.cs_ok = (cs_calc == cs_got)

    res.found = True
    res.marker = frame[7:10].decode("ascii", errors="replace")
    res.sender_id = _u32_be(frame, 10)
    res.msg_type = frame[14]
    res.msg_type_name = MSGTYPE_NAME.get(res.msg_type,
                                         f"UNKNOWN({res.msg_type})")
    res.msg_id = _u32_be(frame, 15)
    res.target_id = _u32_be(frame, 19)
    res.origin_id = _u32_be(frame, 23)

    # Payload starts at offset 27. TimeStamp is right after payload.
    payload_len = body_len - 25
    payload_off = 27
    payload_end = payload_off + max(payload_len, 0)
    ts_off = payload_end

    payload = frame[payload_off:payload_end]
    res.payload_hex = payload.hex().upper()
    res.payload_decoded = decode_payload(res.msg_type, payload)
    res.ts_ms = _u32_be(frame, ts_off)

    return res


def match_filter(expr: str, value: str) -> bool:
    """
    What: Match a single filter expression against a cell value.
    Methods:
      - OR with '|': 'A|B|C' means any sub-expression matches.
      - Negation with '!': '!DATA' means the match must be false.
      - '{empty}' and '{nonempty}' test emptiness of the cell.
      - Default match is case-insensitive substring.
    Creates: True if the expression matches; False otherwise.
    """
    expr = (expr or "").strip()
    if not expr:
        return True

    value = value or ""

    neg = False
    if expr.startswith("!"):
        neg = True
        expr = expr[1:].strip()

    low = expr.lower()
    if low == "{empty}":
        ok = (value == "")
        return (not ok) if neg else ok

    if low == "{nonempty}":
        ok = (value != "")
        return (not ok) if neg else ok

    parts = [p.strip() for p in expr.split("|") if p.strip()]
    if not parts:
        return True

    vlow = value.lower()
    ok = any(p.lower() in vlow for p in parts)

    return (not ok) if neg else ok


class LogViewerApp:
    """
    What: Tkinter GUI app: fixed columns + multi-filters + batch rendering.
    Methods:
      - Loads file and parses lines into an in-memory row list.
      - Displays only the requested columns.
      - Adds per-column filter Entry widgets; AND logic across columns.
    Creates:
      - Tk root, filter widgets, Treeview, scrollbars, row buffers.
    """

    def __init__(self, root: tk.Tk, path: Optional[str] = None) -> None:
        self.root = root
        self.root.title("WSAN Log Viewer")

        # Maximize window where possible.
        try:
            self.root.state("zoomed")  # Windows
        except tk.TclError:
            try:
                self.root.attributes("-zoomed", True)  # Some Linux WMs
            except tk.TclError:
                self.root.geometry("1400x800")

        self.path = path
        self.all_rows: List[Dict[str, str]] = []
        self.filtered_idx: List[int] = []
        self.filter_vars: Dict[str, tk.StringVar] = {}
        self._filter_job: Optional[str] = None

        self._build_ui()

        if self.path and os.path.isfile(self.path):
            self.load_file(self.path)

    def _build_ui(self) -> None:
        """
        What: Build toolbar, filter row, Treeview, scrollbars, status bar.
        Methods: Tkinter Frames with pack/grid layout.
        Creates: Widgets and binds events.
        """
        top = ttk.Frame(self.root)
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(top, text="Open log...", command=self._on_open).pack(
            side=tk.LEFT, padx=6, pady=6
        )
        ttk.Button(top, text="Reload", command=self._on_reload).pack(
            side=tk.LEFT, padx=6, pady=6
        )
        ttk.Button(top, text="Clear filters", command=self._clear_filters).pack(
            side=tk.LEFT, padx=6, pady=6
        )

        self.lbl_status = ttk.Label(top, text="Ready")
        self.lbl_status.pack(side=tk.LEFT, padx=12)
        self.lbl_status.configure(wraplength=1200, justify="left")

        # Filter row: one field per column (AND across columns).
        filt = ttk.Frame(self.root)
        filt.pack(side=tk.TOP, fill=tk.X)

        tip_text = (
            "Filter syntax:\n"
            "- Type substring (case-insensitive)\n"
            "- OR: 'A|B' (e.g., DATA|QUERY)\n"
            "- Empty: {empty}\n"
            "- Non-empty: {nonempty}\n"
            "- NOT: ! (e.g., !QUERY, !{empty})\n"
            "Across columns: AND.\n"
            "Updates after ~200 ms."
        )

        for key, title in COLUMNS:
            v = tk.StringVar(value="")
            self.filter_vars[key] = v

            box = ttk.Frame(filt)
            box.pack(side=tk.LEFT, fill=tk.X, expand=True)

            ttk.Label(box, text=title, anchor="w").pack(side=tk.TOP,
                                                        fill=tk.X)
            e = ttk.Entry(box, textvariable=v)
            e.pack(side=tk.TOP, fill=tk.X, padx=2, pady=2)
            e.bind("<KeyRelease>", self._on_filter_changed)

            Tooltip(e, tip_text)

        # Table frame.
        frame = ttk.Frame(self.root)
        frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, show="headings")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._define_columns()

        # Copy selected row as TSV.
        self.tree.bind("<Control-c>", self._on_copy)

    def _define_columns(self) -> None:
        """
        What: Configure Treeview columns based on requested COLUMNS list.
        Methods: Set headings and initial widths.
        Creates: Treeview column configuration.
        """
        col_keys = [k for k, _ in COLUMNS]
        self.tree["columns"] = col_keys

        for key, title in COLUMNS:
            self.tree.heading(key, text=title)
            if key in ("payload_hex", "payload_dec", "raw_hex"):
                self.tree.column(key, width=520, stretch=True, anchor="w")
            else:
                self.tree.column(key, width=140, stretch=False, anchor="w")

    def _on_open(self) -> None:
        """
        What: Open-file handler for toolbar button.
        Methods: Tk file dialog and load_file().
        Creates: Updates current path and UI.
        """
        path = filedialog.askopenfilename(
            title="Open log file",
            filetypes=[("Text files", "*.txt *.log"), ("All files", "*.*")]
        )
        if path:
            self.path = path
            self.load_file(path)

    def _on_reload(self) -> None:
        """
        What: Reload current file.
        Methods: Calls load_file() if path exists.
        Creates: Refreshes rows and view.
        """
        if self.path and os.path.isfile(self.path):
            self.load_file(self.path)

    def _on_copy(self, _ev=None) -> None:
        """
        What: Copy selected row as TSV for easy paste into Excel.
        Methods: Read Treeview values in column order; join with tabs.
        Creates: Clipboard content.
        """
        sel = self.tree.selection()
        if not sel:
            return
        item_id = sel[0]
        vals = self.tree.item(item_id, "values")
        text = "\t".join(str(v) for v in vals)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.lbl_status.config(text="Copied selected row as TSV")

    def load_file(self, path: str) -> None:
        """
        What: Parse the file into rows and render.
        Methods:
          - Parse meta fields and WSAN fields.
          - Keep only requested columns.
          - Batch insert for UI responsiveness.
        Creates:
          - all_rows: list of dicts, filtered_idx: indices after filtering.
        """
        self.lbl_status.config(text=f"Loading: {os.path.basename(path)}")
        self.root.update_idletasks()

        self.all_rows.clear()

        with open(path, "r", errors="replace") as f:
            for line in f:
                meta, hex_norm = split_log_line(line)

                # Meta columns:
                # meta1=Time(ms), meta2=TranslatorID, meta3=MotesInRange,
                # meta4=messageLength.  [1](https://autuni-my.sharepoint.com/personal/twv1212_autuni_ac_nz/Documents/Microsoft%20Copilot%20Chat%20Files/WSAN%20Protocol%20Analyzer%20Functional%20Specification.pdf)
                time_ms = meta[0] if len(meta) > 0 else ""
                translator = meta[1] if len(meta) > 1 else ""

                ws = parse_wsan_from_hexnorm(hex_norm)

                row: Dict[str, str] = {}
                row["time_ms"] = time_ms
                row["translator_id"] = translator
                row["sender_id"] = "" if ws.sender_id is None else str(ws.sender_id)
                row["role"] = ws.marker
                row["type_name"] = ws.msg_type_name
                row["msg_id"] = "" if ws.msg_id is None else str(ws.msg_id)
                row["target_id"] = format_target_id(ws.target_id)
                row["ts_ms"] = "" if ws.ts_ms is None else str(ws.ts_ms)
                row["origin_id"] = "" if ws.origin_id is None else str(ws.origin_id)
                row["payload_dec"] = ws.payload_decoded
                row["payload_hex"] = ws.payload_hex
                row["cs_ok"] = "" if ws.cs_ok is None else ("OK" if ws.cs_ok else "BAD")
                row["raw_hex"] = hex_norm

                self.all_rows.append(row)

        self._clear_filters(silent=True)
        self.apply_filters(render=True)

    def _on_filter_changed(self, _ev=None) -> None:
        """
        What: Debounced filter change handler.
        Methods: Schedule apply_filters() after short delay.
        Creates: Cancels previous scheduled job, sets new one.
        """
        if self._filter_job is not None:
            try:
                self.root.after_cancel(self._filter_job)
            except tk.TclError:
                pass
        self._filter_job = self.root.after(200, self.apply_filters, True)

    def _clear_filters(self, silent: bool = False) -> None:
        """
        What: Clear all filter fields.
        Methods: Set all filter StringVar to empty.
        Creates: Resets filter state; optionally triggers filtering.
        """
        for v in self.filter_vars.values():
            v.set("")
        if not silent:
            self.apply_filters(render=True)

    def _row_matches_filters(self, row: Dict[str, str]) -> bool:
        """
        What: Check if a row matches all active filters (AND across columns).
        Methods: Uses match_filter() for OR/negation/empty tokens.
        Creates: Returns True if matches; False otherwise.
        """
        for key, _title in COLUMNS:
            expr = self.filter_vars[key].get()
            cell = row.get(key, "") or ""
            if not match_filter(expr, cell):
                return False
        return True

    def apply_filters(self, render: bool = True) -> None:
        """
        What: Apply current filters to all_rows and optionally re-render.
        Methods: Build index list for matching rows; batch render to Treeview.
        Creates: Updates filtered_idx and UI.
        """
        self.filtered_idx = [
            i for i, r in enumerate(self.all_rows) if self._row_matches_filters(r)
        ]

        if render:
            self.tree.delete(*self.tree.get_children())
            self.lbl_status.config(
                text=(f"Matched {len(self.filtered_idx)}/{len(self.all_rows)}. "
                      "Rendering...")
            )
            self._insert_rows_batched(0, batch=500)

    def _insert_rows_batched(self, start: int, batch: int = 500) -> None:
        """
        What: Insert filtered rows in batches to avoid GUI freezes.
        Methods: Use Tk 'after' to schedule next batch.
        Creates: Treeview items; updates status.
        """
        end = min(start + batch, len(self.filtered_idx))
        col_keys = self.tree["columns"]

        for j in range(start, end):
            i = self.filtered_idx[j]
            r = self.all_rows[i]
            values = [r.get(k, "") for k in col_keys]
            self.tree.insert("", "end", values=values)

        if end < len(self.filtered_idx):
            self.lbl_status.config(
                text=f"Rendering {end}/{len(self.filtered_idx)}..."
            )
            self.root.after(10, self._insert_rows_batched, end, batch)
        else:
            self.lbl_status.config(
                text=(
                    f"Done. Showing {len(self.filtered_idx)} rows.  "
                    "Filters: substring; OR='A|B'; {empty}/{nonempty}; "
                    "NOT='!'. Columns combine with AND."
                )
            )


def main(argv: List[str]) -> int:
    """
    What: Entry point; opens GUI viewer for a given file path (optional).
    Methods: CLI arg parsing; start Tkinter main loop.
    Creates: Tk root and LogViewerApp instance.
    """
    path = argv[1] if len(argv) > 1 else None
    root = tk.Tk()
    _app = LogViewerApp(root, path=path)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))