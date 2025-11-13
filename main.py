# main.py
import os
import argparse
from capture.live_capture import LiveCapture
from capture.pcap_reader import PCAPReader
from detection.engine import DetectionEngine


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--live', action='store_true', help='Use live packet capture (requires sudo)')
    group.add_argument('--pcap', type=str, help='Path to PCAP file to analyze')
    parser.add_argument('--iface', type=str, default='wlp0s20f3', help='Network interface for live capture (default: wlp0s20f3)')
    parser.add_argument('--count', type=int, default=100, help='Number of packets to capture in live mode (default: 100)')
    
    args = parser.parse_args()
    
    # Initialize detection engine
    engine = DetectionEngine()

    # Option 1: Live capture (requires root/sudo privileges)
    if args.live:
        print("⚡ Starting live packet capture...")
        print(f"⚠️  Note: Live capture requires root privileges. Run with: sudo python3 main.py --live --iface {args.iface}")
        try:
            capturer = LiveCapture(iface=args.iface, packet_count=args.count)
            flows = capturer.start_capture()
            if flows:
                print("✅ Live capture finished. Detecting flows...")
                detected_df = engine.predict_flows(flows)
                if not detected_df.empty:
                    engine.log_results(detected_df)
                    print(f"\n📊 Detection Summary:")
                    print(f"   Total flows analyzed: {len(detected_df)}")
                    print(f"   Detection results:")
                    for label, count in detected_df['ML_Label'].value_counts().items():
                        print(f"      - {label}: {count}")
                else:
                    print("No features extracted from captured flows.")
            else:
                print("No flows captured in live capture.")
        except PermissionError as e:
            print(f"❌ {e}")
            print("👉 Either run with sudo or grant CAP_NET_RAW to python to avoid sudo:")
            print("   sudo setcap cap_net_raw+eip $(readlink -f $(which python3))")
            return
        except ValueError as e:
            print(f"❌ {e}")
            return
        except ImportError as e:
            print(f"❌ Missing packages when running with sudo: {e}")
            print("👉 Install deps for the sudo environment or use a venv with sudo -E:")
            print("   sudo python3 -m pip install -r requirements.txt")
            print("   # or")
            print("   python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt")
            print("   sudo -E .venv/bin/python main.py --live --iface {args.iface} --count {args.count}")
            return

    # Option 2: Read from pcap file
    else:
        pcap_path = args.pcap
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
            print("   To use live capture instead, run: sudo python3 main.py --live --iface wlp0s20f3")


if __name__ == "__main__":
    main()

