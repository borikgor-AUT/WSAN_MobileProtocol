#!/usr/bin/env python3
import sqlite3
import threading
import time
import re
import sys
import os
import socket
from datetime import datetime, date

# =========================
# Config
# =========================
LOG_FILE = "cooja_log_dynamic.txt"
HOST = "localhost"
PORT = 6000

# SQLite performance & retention
BATCH_SIZE = 20            # number of rows to buffer before commit
BATCH_INTERVAL = 2.0        # seconds between forced commits
PRUNE_EVERY_SEC = 3600      # run pruning every hour
RETENTION_DAYS = 7          # keep only the last N days of data
DEFAULT_LIMIT = 100         # server-side cap if client forgets LIMIT

# Log rotation (truncate-in-place to keep tail + archive full log)
MAX_LOG_BYTES = 5 * 1024 * 1024       # 5 MB
TRUNCATE_TO_BYTES = 2 * 1024 * 1024   # keep the last 2 MB
CHECK_LOG_EVERY_SEC = 30
ARCHIVE_DIR = "log_archive"
if not os.path.exists(ARCHIVE_DIR):
    os.makedirs(ARCHIVE_DIR)
# =========================
# Regex
# =========================
sensor_pattern = re.compile(
    r"\[(\d{2}:\d{2}:\d{2})\]\s*\[Coord(\d+)\]\s*\[SENSOR\]\s*mote=(\d+)\s*data=(.*?)\s*rssi=(-?\d+)"
)
query_pattern = re.compile(r"\[QUERY-Coord(\d+)\]\s*(.*)")

# =========================
# DB handling
# =========================
db_connections = {}
db_locks = {}
insert_buffers = {}
last_commit_times = {}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sensor_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mote_id INTEGER,
    timestamp TEXT,
    sensor_type TEXT,
    value REAL,
    rssi INTEGER
);
"""

INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_sensor_type ON sensor_data(sensor_type)",
    "CREATE INDEX IF NOT EXISTS idx_value ON sensor_data(value)",
    "CREATE INDEX IF NOT EXISTS idx_ts ON sensor_data(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_mote_ts ON sensor_data(mote_id, timestamp)"
]

PRAGMAS = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA mmap_size=3000000000"
]

def get_db(coord_id: int):
    if coord_id not in db_connections:
        db_name = f"mote_data_{coord_id}.db"
        conn = sqlite3.connect(db_name, check_same_thread=False)
        cur = conn.cursor()
        for p in PRAGMAS:
            cur.execute(p)
        cur.executescript(SCHEMA_SQL)
        for idx in INDEX_SQL:
            cur.execute(idx)
        conn.commit()
        db_connections[coord_id] = conn
        db_locks[coord_id] = threading.Lock()
        insert_buffers[coord_id] = []
        last_commit_times[coord_id] = time.time()
    return db_connections[coord_id]

# =========================
# Insert buffering
# =========================
def _flush_buffer(coord_id: int):
    buf = insert_buffers[coord_id]
    if not buf:
        return
    conn = get_db(coord_id)
    with db_locks[coord_id]:
        conn.executemany(
            "INSERT INTO sensor_data (mote_id, timestamp, sensor_type, value, rssi) VALUES (?, ?, ?, ?, ?)",
            buf
        )
        conn.commit()
        insert_buffers[coord_id].clear()
        last_commit_times[coord_id] = time.time()

def _maybe_flush(coord_id: int):
    if len(insert_buffers[coord_id]) >= BATCH_SIZE or \
       (time.time() - last_commit_times[coord_id]) >= BATCH_INTERVAL:
        _flush_buffer(coord_id)

# =========================
# Log follower & rotation
# =========================
def follow_log(file_path: str):
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    if not os.path.exists(file_path):
        open(file_path, 'a').close()

    with open(file_path, "r", buffering=1) as f:
        f.seek(0, os.SEEK_END)
        last_check = time.time()
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                if time.time() - last_check >= CHECK_LOG_EVERY_SEC:
                    _rotate_log_if_needed(file_path)
                    last_check = time.time()
                continue
            insert_sensor_line(line.strip())

def _rotate_log_if_needed(file_path: str):
    try:
        size = os.path.getsize(file_path)
        if size <= MAX_LOG_BYTES:
            return

        # --- Archive full log before truncating ---
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_path = os.path.join(ARCHIVE_DIR, f"cooja_log_dynamic_{ts}.txt")
        try:
            os.rename(file_path, archive_path)
            print(f"[INFO] Archived log to {archive_path}")
            open(file_path, 'a').close()  # recreate fresh log file
            return
        except Exception as e:
            print(f"[WARN] Log archive failed: {e}, falling back to truncate")

        # --- Fallback: truncate to tail ---
        with open(file_path, 'rb+') as f:
            if size > TRUNCATE_TO_BYTES:
                f.seek(-TRUNCATE_TO_BYTES, os.SEEK_END)
            else:
                f.seek(0, os.SEEK_SET)
            tail = f.read()
            f.seek(0)
            f.truncate(0)
            f.write(tail)
            f.flush()
        print(f"[INFO] Log truncated to last {TRUNCATE_TO_BYTES} bytes")

    except Exception as e:
        print(f"[WARN] Log rotation failed: {e}")

# =========================
# Line parsing & inserts
# =========================
def _to_iso_datetime(hms: str) -> str:
    today = date.today().isoformat()
    return f"{today} {hms}"

def insert_sensor_line(line: str):
    match = sensor_pattern.search(line)
    if not match:
        return

    hms = match.group(1)
    coord_id = int(match.group(2))
    mote_id = int(match.group(3))
    data_str = match.group(4)
    rssi = int(match.group(5))

    get_db(coord_id)
    iso_ts = _to_iso_datetime(hms)

    fields = data_str.split()
    pending = []
    for field in fields:
        field = field.strip()
        if "=" in field:
            k, v = field.split("=", 1)
            try:
                pending.append((mote_id, iso_ts, k, float(v), rssi))
            except ValueError:
                continue

    insert_buffers[coord_id].extend(pending)
    _maybe_flush(coord_id)

# =========================
# Pruning thread
# =========================
def prune_old_data_loop():
    while True:
        time.sleep(PRUNE_EVERY_SEC)
        for coord_id, conn in list(db_connections.items()):
            try:
                with db_locks[coord_id]:
                    conn.execute(
                        "DELETE FROM sensor_data WHERE timestamp < datetime('now', ?)",
                        (f"-{RETENTION_DAYS} days",)
                    )
                    conn.commit()
                    conn.execute("PRAGMA optimize")
            except Exception as e:
                print(f"[WARN] Prune failed for Coord{coord_id}: {e}")

# =========================
# TCP Query server
# =========================
def run_server(host=HOST, port=PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    print(f"[INFO] Python server listening on {host}:{port}")
    while True:
        conn_socket, addr = sock.accept()
        print(f"[INFO] Coordinator connected from {addr}")
        threading.Thread(target=handle_client, args=(conn_socket,), daemon=True).start()

def _enforce_limit(sql: str) -> str:
    s = sql.strip().rstrip(';')
    if not s.lower().startswith("select"):
        return "--REFUSED--"
    if re.search(r"\blimit\b", s, flags=re.IGNORECASE):
        return s + ";"
    return f"{s} LIMIT {DEFAULT_LIMIT};"

def handle_client(conn_socket: socket.socket):
    buffer = ""
    with conn_socket:
        while True:
            data = conn_socket.recv(1024)
            if not data:
                break
            buffer += data.decode(errors='ignore')
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                m = query_pattern.match(line)
                if not m:
                    continue
                coord_id = int(m.group(1))
                sql_in = m.group(2)
                sql = _enforce_limit(sql_in)
                if sql == "--REFUSED--":
                    conn_socket.sendall(f"[ERROR-Coord{coord_id}] Only SELECT queries are allowed.\n".encode())
                    continue

                conn = get_db(coord_id)
                try:
                    cur = conn.cursor()
                    cur.execute(sql)
                    rows = cur.fetchall()
                    formatted = "\n".join(["(" + ", ".join(map(str, r)) + ")" for r in rows])
                    response = f"[RESULT-Coord{coord_id}]\n{formatted}\n"
                    print(response)
                    conn_socket.sendall(response.encode())
                except Exception as e:
                    conn_socket.sendall(f"[ERROR-Coord{coord_id}] {e}\n".encode())

# =========================
# Main
# =========================
if __name__ == "__main__":
    threading.Thread(target=follow_log, args=(LOG_FILE,), daemon=True).start()
    threading.Thread(target=prune_old_data_loop, daemon=True).start()
    run_server(HOST, PORT)