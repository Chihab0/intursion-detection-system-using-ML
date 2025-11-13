# features/flow_builder.py
from scapy.all import TCP, UDP, IP, ICMP
from typing import Dict, List, Tuple, Any


def _canonical_flow_key(pkt) -> Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]] | None:
    """
    Build a direction-agnostic flow key so that packets in both directions
    belong to the same flow. Protocol is preserved.
    """
    if IP not in pkt:
        return None

    if TCP in pkt:
        proto = 'TCP'
        a = (pkt[IP].src, int(pkt[TCP].sport))
        b = (pkt[IP].dst, int(pkt[TCP].dport))
    elif UDP in pkt:
        proto = 'UDP'
        a = (pkt[IP].src, int(pkt[UDP].sport))
        b = (pkt[IP].dst, int(pkt[UDP].dport))
    elif ICMP in pkt:
        proto = 'ICMP'
        # No ports; use 0 placeholders
        a = (pkt[IP].src, 0)
        b = (pkt[IP].dst, 0)
    else:
        return None

    ends = tuple(sorted([a, b]))  # direction-agnostic endpoints
    return (proto, ends)  # type: ignore[return-value]


def build_flows(packets: List[Any]) -> Dict[Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]], List[Any]]:
    """
    Group packets into bidirectional flows using a direction-agnostic 5-tuple.
    Returns a dict: {flow_key: list_of_packets}
    """
    flows: Dict[Tuple[str, Tuple[Tuple[str, int], Tuple[str, int]]], List[Any]] = {}
    for pkt in packets:
        key = _canonical_flow_key(pkt)
        if key is None:
            continue
        if key not in flows:
            flows[key] = []
        flows[key].append(pkt)
    return flows
