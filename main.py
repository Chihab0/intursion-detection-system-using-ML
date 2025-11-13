# main.py
import os
from capture.live_capture import LiveCapture
from capture.pcap_reader import PCAPReader
from detection.engine import DetectionEngine

def main():
    # Initialize detection engine
    engine = DetectionEngine()

    # Option 1: Live capture (requires root/sudo privileges)
    use_live_capture = False  # Set to True to use live capture (requires sudo)
    
    if use_live_capture:
        print("⚡ Starting live packet capture...")
        print("⚠️  Note: Live capture requires root privileges. Run with: sudo python3 main.py")
        try:
            capturer = LiveCapture(iface=None, packet_count=100)
            flows = capturer.start_capture()
            if flows:
                print("✅ Live capture finished. Detecting flows...")
                detected_df = engine.predict_flows(flows)
                if not detected_df.empty:
                    engine.log_results(detected_df)
                else:
                    print("No features extracted from captured flows.")
            else:
                print("No flows captured in live capture.")
        except PermissionError:
            print("❌ Permission denied. Please run with sudo: sudo python3 main.py")
            return

    # Option 2: Read from pcap file (default, no special privileges needed)
    else:
        pcap_path = "/home/chihab/Downloads/NMap-Captures/nmap_ACK"  # You can provide your own PCAP file
        if os.path.exists(pcap_path):
            print(f"⚡ Reading PCAP file: {pcap_path}")
            reader = PCAPReader(pcap_path)
            flows = reader.read_pcap()
            if flows:
                print("✅ PCAP read finished. Detecting flows...")
                detected_df = engine.predict_flows(flows)
                if not detected_df.empty:
                    engine.log_results(detected_df)
                    print(f"\n📊 Detection Summary:")
                    print(f"   Total flows analyzed: {len(detected_df)}")
                    print(f"   Detection results:")
                    for label, count in detected_df['ML_Label'].value_counts().items():
                        print(f"      - {label}: {count}")
                else:
                    print("No features extracted from PCAP flows.")
            else:
                print("No flows extracted from PCAP.")
        else:
            print(f"❌ PCAP file not found: {pcap_path}")
            print("   To use live capture instead, set use_live_capture=True and run with sudo.")

if __name__ == "__main__":
    main()

