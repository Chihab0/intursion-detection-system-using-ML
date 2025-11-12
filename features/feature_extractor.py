# features/feature_extractor.py
import pandas as pd
from scapy.all import TCP, UDP, IP


def compute_flow_features(flow_pkts):
    """
    Compute the 20 selected features for a single flow (list of packets).
    Returns a dictionary.
    """
    if len(flow_pkts) == 0:
        return {}

    # Sort packets by time
    flow_pkts = sorted(flow_pkts, key=lambda x: x.time)

    # Determine forward/backward by direction (first packet direction)
    first_pkt = flow_pkts[0]
    src_ip = first_pkt[IP].src
    src_port = first_pkt[TCP].sport if TCP in first_pkt else (first_pkt[UDP].sport if UDP in first_pkt else 0)

    fwd_pkts = []
    bwd_pkts = []

    for pkt in flow_pkts:
        pkt_src_ip = pkt[IP].src
        pkt_src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        if pkt_src_ip == src_ip and pkt_src_port == src_port:
            fwd_pkts.append(pkt)
        else:
            bwd_pkts.append(pkt)

    # Helper to get packet lengths
    def pkt_len(pkt):
        return len(pkt)

    # Helper to get header lengths
    def header_len(pkt):
        if TCP in pkt:
            return pkt[TCP].dataofs * 4
        elif UDP in pkt:
            return 8
        return 0

    # Helper to get IAT
    def iat(pkts):
        if len(pkts) < 2:
            return [0]
        return [pkts[i].time - pkts[i-1].time for i in range(1, len(pkts))]

    # Features
    features = {}
    features['Destination Port'] = bwd_pkts[-1][TCP].dport if bwd_pkts and TCP in bwd_pkts[-1] else 0
    features['Flow Duration'] = flow_pkts[-1].time - flow_pkts[0].time
    features['Total Fwd Packets'] = len(fwd_pkts)
    features['Total Backward Packets'] = len(bwd_pkts)
    features['Total Length of Fwd Packets'] = sum(pkt_len(pkt) for pkt in fwd_pkts)
    features['Total Length of Bwd Packets'] = sum(pkt_len(pkt) for pkt in bwd_pkts)
    features['Fwd Packet Length Max'] = max([pkt_len(pkt) for pkt in fwd_pkts], default=0)
    features['Fwd Packet Length Min'] = min([pkt_len(pkt) for pkt in fwd_pkts], default=0)
    features['Fwd Packet Length Mean'] = (sum(pkt_len(pkt) for pkt in fwd_pkts) / len(fwd_pkts)) if fwd_pkts else 0
    features['Bwd Packet Length Max'] = max([pkt_len(pkt) for pkt in bwd_pkts], default=0)
    features['Bwd Packet Length Min'] = min([pkt_len(pkt) for pkt in bwd_pkts], default=0)
    features['Bwd Packet Length Mean'] = (sum(pkt_len(pkt) for pkt in bwd_pkts) / len(bwd_pkts)) if bwd_pkts else 0
    features['Flow Bytes/s'] = sum(pkt_len(pkt) for pkt in flow_pkts) / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
    features['Flow Packets/s'] = len(flow_pkts) / features['Flow Duration'] if features['Flow Duration'] > 0 else 0
    features['Fwd IAT Mean'] = sum(iat(fwd_pkts))/len(iat(fwd_pkts)) if len(fwd_pkts) > 1 else 0
    features['Bwd IAT Mean'] = sum(iat(bwd_pkts))/len(iat(bwd_pkts)) if len(bwd_pkts) > 1 else 0
    features['Fwd Header Length'] = sum(header_len(pkt) for pkt in fwd_pkts)
    features['Bwd Header Length'] = sum(header_len(pkt) for pkt in bwd_pkts)
    features['Average Packet Size'] = sum(pkt_len(pkt) for pkt in flow_pkts) / len(flow_pkts)
    features['Subflow Fwd Bytes'] = sum(pkt_len(pkt) for pkt in fwd_pkts)  # can be further split into sub-intervals if needed

    return features


def extract_features(flows_dict):
    """
    flows_dict: dict of flow_key -> list_of_packets
    Returns a DataFrame with one row per flow and computed features
    """
    rows = []
    for flow_key, pkts in flows_dict.items():
        features = compute_flow_features(pkts)
        if features:
            rows.append(features)
    return pd.DataFrame(rows)
