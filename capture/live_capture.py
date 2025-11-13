# capture/live_capture.py
import os
import pandas as pd
from scapy.all import sniff, get_if_list
from features.flow_builder import build_flows


class LiveCapture:
    def __init__(self, iface=None, packet_count=100):
        self.iface = iface
        self.packet_count = packet_count
        self.flows_df = pd.DataFrame()

    def start_capture(self):
        """
        Capture live packets, group them into flows, and return a dict of flows.
        Validates interface and privileges first for clearer errors.
        """
        # Validate root privileges
        if os.geteuid() != 0:
            raise PermissionError("Live capture requires root privileges (sudo).")

        # Validate interface
        if self.iface is None:
            raise ValueError("No interface provided. Use --iface to specify one (e.g., wlp0s20f3).")
        available = get_if_list()
        if self.iface not in available:
            raise ValueError(f"Interface '{self.iface}' not found. Available: {', '.join(available)}")

        print(f"🔹 Starting live capture on iface={self.iface} for {self.packet_count} packets...")
        packets = sniff(iface=self.iface, count=self.packet_count)
        flows = build_flows(packets)
        print(f"✅ Captured {len(packets)} packets and built {len(flows)} flows")
        return flows

