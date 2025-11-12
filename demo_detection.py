# demo_detection.py
import argparse
from scapy.all import sniff, rdpcap
from capture.live_capture import start_capture  # existing capture function
from features.flow_builder import build_flows
from detection.flow_features import get_features  # your feature extractor
from ml.predict import predict_flow  # your model predictor

def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection Demo")
    parser.add_argument("--pcap", type=str, help="PCAP file to analyze")
    parser.add_argument("--live", action="store_true", help="Use live capture")
    parser.add_argument("--count", type=int, default=50, help="Number of packets for live capture")
    args = parser.parse_args()

    if args.pcap:
        print(f"Analyzing PCAP: {args.pcap}")
        packets = rdpcap(args.pcap)
    elif args.live:
        print("Starting live capture... Press Ctrl+C to stop.")
        packets = start_capture(count=args.count)  # already implemented
    else:
        print("Please specify either --pcap FILE or --live")
        return

    flows = build_flows(packets)  # group packets into flows

    print("\n=== Detection Results ===")
    for flow_key, flow_packets in flows.items():
        features = get_features(flow_packets)        # your existing feature extractor
        label = predict_flow(features)               # ML model decides
        print(f"Flow: {flow_key} | Packets: {len(flow_packets)} | Predicted: {label}")

if __name__ == "__main__":
    main()

