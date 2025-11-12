# capture/pcap_reader.py
import pandas as pd
from scapy.all import rdpcap, TCP, UDP
from features.feature_extractor import compute_flow_features


class PCAPReader:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.flows_df = pd.DataFrame()

    def read_pcap(self):
        packets = rdpcap(self.pcap_file)
        self.flows_df = compute_flow_features(packets)  # returns DataFrame with top-20 features
        return self.flows_df
