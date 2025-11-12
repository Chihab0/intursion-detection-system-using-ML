# capture/live_capture.py
import pandas as pd
from scapy.all import sniff
from features.feature_extractor import compute_flow_features


class LiveCapture:
    def __init__(self, iface=None, packet_count=100):
        self.iface = iface
        self.packet_count = packet_count
        self.flows_df = pd.DataFrame()

    def start_capture(self):
        """
        Capture live packets and extract features in batches.
        """
        print(f"🔹 Starting live capture on iface={self.iface} for {self.packet_count} packets...")
        packets = sniff(iface=self.iface, count=self.packet_count)
        self.flows_df = compute_flow_features(packets)
        print(f"✅ Captured {len(packets)} packets and extracted flows: {self.flows_df.shape[0]} rows")
        return self.flows_df

