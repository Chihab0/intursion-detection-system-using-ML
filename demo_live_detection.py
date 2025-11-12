# demo_live_detection.py
from scapy.all import sniff
from features.flow_builder import build_flows

def predict_flow(packets):
    """
    Dummy prediction function.
    Replace this with your ML engine later.
    For now, we just label flows with more than 10 packets as 'Suspicious'.
    """
    if len(packets) > 10:
        return "Suspicious"
    return "Normal"

def live_packet_handler(packet_list):
    # Group packets into flows
    flows = build_flows(packet_list)
    
    # Process each flow
    for flow_key, packets in flows.items():
        print(f"\nFlow: {flow_key} | Packets: {len(packets)}")
        label = predict_flow(packets)
        print(f"Predicted label: {label}")

def main():
    print("Starting live capture... Press Ctrl+C to stop.")
    
    # Capture packets in real-time
    captured_packets = sniff(count=50)  # adjust count or remove for continuous capture
    
    live_packet_handler(captured_packets)

if __name__ == "__main__":
    main()

