# capture/live_capture.py
import pandas as pd
from scapy.all import sniff
from features.flow_builder import build_flows


class LiveCapture:
    def __init__(self, iface=None, packet_count=100):
        self.iface = iface
        self.packet_count = packet_count
        self.flows_df = pd.DataFrame()

    def start_capture(self):
        """
        Capture live packets, group them into flows, and return a dict of flows.
        """
        print(f"🔹 Starting live capture on iface={self.iface} for {self.packet_count} packets...")
        packets = sniff(iface=self.iface, count=self.packet_count)
        flows = build_flows(packets)
        print(f"✅ Captured {len(packets)} packets and built {len(flows)} flows")
        return flows

