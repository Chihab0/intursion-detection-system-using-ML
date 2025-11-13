# capture/pcap_reader.py
from scapy.all import rdpcap
from features.flow_builder import build_flows


class PCAPReader:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def read_pcap(self):
        packets = rdpcap(self.pcap_file)
        flows = build_flows(packets)
        return flows
