# features/feature_extractor.py
from typing import Dict, List, Any
import pandas as pd
from scapy.all import TCP, UDP, IP, ICMP


def compute_flow_features(flow_pkts: List[Any]) -> Dict[str, Any]:
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
    src_ip = first_pkt[IP].src if IP in first_pkt else ""
    dst_ip_first = first_pkt[IP].dst if IP in first_pkt else ""
    src_port = first_pkt[TCP].sport if TCP in first_pkt else (first_pkt[UDP].sport if UDP in first_pkt else 0)

    fwd_pkts: List[Any] = []
    bwd_pkts: List[Any] = []

    for pkt in flow_pkts:
        if IP not in pkt:
            continue
        pkt_src_ip = pkt[IP].src
        pkt_src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        if pkt_src_ip == src_ip and pkt_src_port == src_port:
            fwd_pkts.append(pkt)
        else:
            bwd_pkts.append(pkt)

    # Helper to get packet lengths
    def pkt_len(pkt: Any) -> int:
        return int(len(pkt))

    # Helper to get header lengths
    def header_len(pkt: Any) -> int:
        if TCP in pkt:
            try:
                dofs = pkt[TCP].dataofs or 5
            except Exception:
                dofs = 5
            return int(max(5, dofs) * 4)
        elif UDP in pkt:
            return 8
        return 0

    # Helper to get IAT
    def iat(pkts: List[Any]) -> List[float]:
        if len(pkts) < 2:
            return [0.0]
        return [float(pkts[i].time) - float(pkts[i - 1].time) for i in range(1, len(pkts))]

    # Destination Port: prefer forward direction dport, else from first packet
    def get_dest_port() -> int:
        if fwd_pkts:
            pkt = fwd_pkts[0]
            if TCP in pkt:
                return int(pkt[TCP].dport)
            if UDP in pkt:
                return int(pkt[UDP].dport)
            if ICMP in pkt:
                return 0
        if TCP in first_pkt:
            return int(first_pkt[TCP].dport)
        if UDP in first_pkt:
            return int(first_pkt[UDP].dport)
        return 0

    # Determine dst_ip from forward packets when possible
    dst_ip = fwd_pkts[0][IP].dst if fwd_pkts and IP in fwd_pkts[0] else dst_ip_first

    start_time = float(flow_pkts[0].time)
    end_time = float(flow_pkts[-1].time)

    # Features
    features: Dict[str, Any] = {}
    # Metadata useful for heuristics (not used by model input)
    features['Src IP'] = src_ip
    features['Dst IP'] = dst_ip
    features['Start Time'] = start_time
    features['End Time'] = end_time

    # Top features used by the model
    features['Destination Port'] = get_dest_port()
    duration = end_time - start_time
    features['Flow Duration'] = duration
    features['Total Fwd Packets'] = len(fwd_pkts)
    features['Total Backward Packets'] = len(bwd_pkts)
    features['Total Length of Fwd Packets'] = sum(pkt_len(pkt) for pkt in fwd_pkts)
    features['Total Length of Bwd Packets'] = sum(pkt_len(pkt) for pkt in bwd_pkts)
    features['Fwd Packet Length Max'] = max([pkt_len(pkt) for pkt in fwd_pkts], default=0)
    features['Fwd Packet Length Min'] = min([pkt_len(pkt) for pkt in fwd_pkts], default=0)
    features['Fwd Packet Length Mean'] = (sum(pkt_len(pkt) for pkt in fwd_pkts) / len(fwd_pkts)) if fwd_pkts else 0.0
    features['Bwd Packet Length Max'] = max([pkt_len(pkt) for pkt in bwd_pkts], default=0)
    features['Bwd Packet Length Min'] = min([pkt_len(pkt) for pkt in bwd_pkts], default=0)
    features['Bwd Packet Length Mean'] = (sum(pkt_len(pkt) for pkt in bwd_pkts) / len(bwd_pkts)) if bwd_pkts else 0.0
    total_bytes = sum(pkt_len(pkt) for pkt in flow_pkts)
    features['Flow Bytes/s'] = (total_bytes / duration) if duration > 0 else 0.0
    features['Flow Packets/s'] = (len(flow_pkts) / duration) if duration > 0 else 0.0
    features['Fwd IAT Mean'] = (sum(iat(fwd_pkts)) / len(iat(fwd_pkts))) if len(fwd_pkts) > 1 else 0.0
    features['Bwd IAT Mean'] = (sum(iat(bwd_pkts)) / len(iat(bwd_pkts))) if len(bwd_pkts) > 1 else 0.0
    features['Fwd Header Length'] = sum(header_len(pkt) for pkt in fwd_pkts)
    features['Bwd Header Length'] = sum(header_len(pkt) for pkt in bwd_pkts)
    features['Average Packet Size'] = (total_bytes / len(flow_pkts)) if flow_pkts else 0.0
    features['Subflow Fwd Bytes'] = sum(pkt_len(pkt) for pkt in fwd_pkts)

    return features


def extract_features(flows_dict: Dict[Any, List[Any]]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, pkts in flows_dict.items():
        features = compute_flow_features(pkts)
        if features:
            rows.append(features)
    return pd.DataFrame(rows)
