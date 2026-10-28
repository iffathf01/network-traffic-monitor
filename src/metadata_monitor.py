# Libraries
import sys				
import time 				# asks computer's CPU for exact time
from scapy.all import sniff, IP		# loads Scapy, captures raw packets, and isolates network addresses


traffic_baseline = {}			# if computer sends 50k bytes of data or more, flag it
BURST_THRESHOLD_BYTES = 50000
TIME_WINDOW_SECONDS = 2.0

def analyze_metadata(packet):		# if packet has ip address, send source IP, destination IP, packet size, time down to millisec
ip_layer = packet.getlayer(IP)    
if ip_layer:
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        current_time = time.time()

        if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."):
            if src_ip not in traffic_baseline:
                traffic_baseline[src_ip] = [0, current_time]
                
            traffic_baseline[src_ip][0] += packet_size
            time_delta = current_time - traffic_baseline[src_ip][1]
            
            if time_delta <= TIME_WINDOW_SECONDS:
                if traffic_baseline[src_ip][0] > BURST_THRESHOLD_BYTES:
                    print("\n[■ METADATA ALERT] Potential Data Leak / High-Volume Burst!")
                    print(f" -> Origin Host: {src_ip} -> Destination IP: {dst_ip}")
                    print(f" -> Metrics: {traffic_baseline[src_ip][0]} bytes pushed within {time_delta:.2f}s window.")
                    traffic_baseline[src_ip] = [0, current_time]
            else:
                traffic_baseline[src_ip] = [packet_size, current_time]

def main():
    print("=" * 70)
    print(" INITIALIZING ENCRYPTED TRAFFIC METADATA ANALYSIS ENGINE (ETM) ")
    print("=" * 70)
    print("[*] Binding interface capture hooks to native network adapter sockets...")
    print("[*] Passive auditing state: OPERATIONAL. Terminate anytime using Ctrl+C.")
    try:
        sniff(prn=analyze_metadata, store=False)
    except KeyboardInterrupt:
        print("\n[*] Detaching network adapter capture hooks. Exiting cleanly.")
        sys.exit(0)
    except PermissionError:
        print("\n[■ ERROR] Process token mismatch. Terminal must be run as Administrator/Root.")
        sys.exit(1)

if __name__ == '__main__':
    main()
