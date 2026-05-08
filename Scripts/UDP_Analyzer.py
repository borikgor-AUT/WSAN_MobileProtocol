#!/usr/bin/env python3
"""
NullNet Analyzer (Mote Output Log Based)

Parses mote output log and computes:
- Generated messages
- Delivered messages (RSU-based)
- Packet Delivery Ratio (PDR)
- Latency
- Hop count
- TX count
- Bytes transmitted (Level A)

Author: Boris Gor (spec), implementation via Copilot (then fixed properly)
"""

import re
import sys
from dataclasses import dataclass
from typing import Dict, Tuple, Optional


# ---------- Data model ----------

@dataclass
class MessageStats:
    origin: int
    msg_id: int
    created_time: Optional[int] = None
    delivered_time: Optional[int] = None
    min_hop: Optional[int] = None
    tx_count: int = 0
    bytes_tx: int = 0


# ---------- Regex patterns ----------

RE_CREATE = re.compile(r"CREATE origin=(\d+) msg=(\d+) time=(\d+)")
RE_MBL_RX = re.compile(r"MBL RX origin=(\d+) msg=(\d+) hop=(\d+)")
RE_MBL_TX = re.compile(r"MBL TX origin=(\d+) msg=(\d+) hop=(\d+) len=(\d+)")
RE_MBL_RTX = re.compile(r"MBL RTX origin=(\d+) msg=(\d+) hop=(\d+) len=(\d+)")
RE_RSU_RX = re.compile(r"RSU RX origin=(\d+) msg=(\d+) hop=(\d+) len=(\d+) time=(\d+)")


# ---------- Analyzer ----------

class NullNetAnalyzer:
    def __init__(self):
        # self.messages: Dict[Tuple[int, int], MessageStats] =
        self.messages: Dict[Tuple[int, int], MessageStats] = {}

    def get_msg(self, origin: int, msg_id: int) -> MessageStats:
        key = (origin, msg_id)
        if key not in self.messages:
            self.messages[key] = MessageStats(origin, msg_id)
        return self.messages[key]

    def process_line(self, line: str):
        if m := RE_CREATE.search(line):
            origin, msg, time = map(int, m.groups())
            self.get_msg(origin, msg).created_time = time

        elif m := RE_MBL_TX.search(line):
            origin, msg, hop, length = map(int, m.groups())
            s = self.get_msg(origin, msg)
            s.tx_count += 1
            s.bytes_tx += length

        elif m := RE_MBL_RTX.search(line):
            origin, msg, hop, length = map(int, m.groups())
            s = self.get_msg(origin, msg)
            s.tx_count += 1
            s.bytes_tx += length

        elif m := RE_MBL_RX.search(line):
            origin, msg, hop = map(int, m.groups())
            s = self.get_msg(origin, msg)
            if s.min_hop is None or hop < s.min_hop:
                s.min_hop = hop

        elif m := RE_RSU_RX.search(line):
            origin, msg, hop, length, time = map(int, m.groups())
            s = self.get_msg(origin, msg)
            s.delivered_time = time
            if s.min_hop is None or hop < s.min_hop:
                s.min_hop = hop

    def report(self):
        generated = len(self.messages)
        delivered = sum(1 for m in self.messages.values() if m.delivered_time is not None)

        print(f"Generated messages : {generated}")
        print(f"Delivered messages : {delivered}")
        print(f"PDR                : {delivered / generated:.3f}" if generated else "PDR: N/A")

        latencies = [
            m.delivered_time - m.created_time
            for m in self.messages.values()
            if m.delivered_time is not None and m.created_time is not None
        ]

        if latencies:
            print(f"Average latency    : {sum(latencies) / len(latencies):.2f}")
        else:
            print("Average latency    : N/A")


# ---------- Main ----------

def main(log_path: str):
    analyzer = NullNetAnalyzer()
    print("Starting analyzer version 0.0.2")

    with open(log_path, "r") as f:
        for line in f:
            analyzer.process_line(line)

    analyzer.report()


if __name__ == "__main__":
    # if len(sys.argv) != 2:
    #     print("Usage: nullnet_analyzer.py <mote_output_log.txt>")
    #     sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: UDP_Analyzer.py <mote_output_log.txt>")
        sys.exit(1)

    main(sys.argv[1])