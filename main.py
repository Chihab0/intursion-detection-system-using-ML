# main.py
import os
from capture.live_capture import start_live_capture
from capture.pcap_reader import read_pcap_file
from detection.engine import DetectionEngine

def main():
    # Initialize detection engine
    engine = DetectionEngine()

    # Option 1: Live capture
    print("⚡ Starting live packet capture...")
    flows_df = start_live_capture(duration=30)  # capture for 30 seconds
    if not flows_df.empty:
       print("✅ Live capture finished. Detecting flows...")
       detected_df = engine.predict_flows(flows_df)
       engine.log_results(detected_df)
    else:
        print("No flows captured in live capture.")

    # Option 2: Read from pcap file
    pcap_path = "../l-ids/data/pcaps/scan.pcap"
    if os.path.exists(pcap_path):
        print(f"⚡ Reading PCAP file: {pcap_path}")
        flows_df = read_pcap_file(pcap_path)
        if not flows_df.empty:
            print("✅ PCAP read finished. Detecting flows...")
            detected_df = engine.predict_flows(flows_df)
            engine.log_results(detected_df)
        else:
            print("No flows extracted from PCAP.")
    else:
        print(f"PCAP file not found: {pcap_path}")

if __name__ == "__main__":
    main()

