# features/flow_builder.py
from scapy.all import TCP, UDP, IP
import pandas as pd


def build_flows(packets):
    """
    Group packets into flows based on 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)
    Returns a dict: {flow_key: list_of_packets}
    """
    flows = {}
    for pkt in packets:
        if IP not in pkt:
            continue
        proto = None
        sport = dport = 0

        if TCP in pkt:
            proto = 'TCP'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = 'UDP'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue  # ignore non TCP/UDP packets

        flow_key = (pkt[IP].src, pkt[IP].dst, sport, dport, proto)
        if flow_key not in flows:
            flows[flow_key] = []
        flows[flow_key].append(pkt)
    return flows
