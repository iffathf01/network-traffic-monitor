# Libraries
import sys				
import time 				# asks computer's CPU for exact time
from scapy.all import sniff, IP		# loads Scapy, captures raw packets, and isolates network addresses


traffic_baseline = {}			# if computer sends 50k bytes of data or more, flag it
BURST_THRESHOLD_BYTES = 50000
TIME_WINDOW_SECONDS = 2.0

# if packet has ip address, send source IP, destination IP, packet size, time down to millisec
def analyze_metadata(packet):
    ip_layer = packet.getlayer(IP)
    if ip_layer:
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        current_time = time.time()

        if src_ip.startswith(("192.168.","10.","172.")):			# filters out regular IP addresses
            if src_ip not in traffic_baseline:					# ignores IP addresses already recognized from before
                traffic_baseline[src_ip] = [0, current_time]
                
            traffic_baseline[src_ip][0] += packet_size				# adds packet size to the traffic baseline
            time_delta = current_time - traffic_baseline[src_ip][1]		# calculates how long it took from first packet to the last packet 
            
            if traffic_baseline[src_ip][0] >= BURST_THRESHOLD_BYTES:								# checks if 50k bytes or more in 2 seconds
                if time_delta <= TIME_WINDOW_SECONDS:
                    print("\n[METADATA ALERT] High-Volume Burst")							# if yes, print
                    print(f" -> Origin Host: {src_ip} -> Destination IP: {dst_ip}")
                    print(f" -> Metrics: {traffic_baseline[src_ip][0]} bytes pushed within {time_delta:.2f}s window.")
                    traffic_baseline[src_ip] = [0, current_time]
                else:
                    traffic_baseline[src_ip] = [packet_size, current_time]
def main():
    print("=" * 70)
    print(" NETWORK TRAFFIC MONITOR ACTIVATED ")
    print("=" * 70)
    print("[*] Starting packet scanner...")
    print("[*] Monitoring traffic. Press Ctrl + C to stop.")
    
    try:
        sniff(prn=analyze_metadata, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping scanner. Exiting cleanly.")
        sys.exit(0)
    except PermissionError:
        print("\n[ERROR] Access denied. Please run this terminal as Administrator/Root.")
        sys.exit(1)

if __name__ == '__main__':
    main()
