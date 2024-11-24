import matplotlib
matplotlib.use('Agg')  # RH Note - For saving plots to files error 
import scapy.all as scapy 
import threading  
import time  
from collections import defaultdict  
import matplotlib.pyplot as plt  
import logging  
import keyboard  # exit with Ctrl+Q
import pandas as pd  
import seaborn as sns


throughput_data = defaultdict(int)  
throughput_history = defaultdict(list)  
latency_data = {}  
unique_macs = set()
unique_ips = set()
packet_count = defaultdict(int)
connections = set()  
connections_per_protocol = defaultdict(int)
connection_timestamps = defaultdict(list)
sniffing_active = threading.Event()
exit_flag = threading.Event()
log_file = "network_events.log"
output_lock = threading.Lock()  # race conditon issues 
avg_latency = 0


logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def process_packet(packet):
    src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, timestamp = (
        None, None, None, None, None, None, None, time.time(),
    )

    # Check if the packet has Ethernet layer
    if packet.haslayer(scapy.Ether):
        src_mac = getattr(packet[scapy.Ether], "src", None)
        dst_mac = getattr(packet[scapy.Ether], "dst", None)
        protocol = "Ethernet"
        if src_mac and dst_mac:
            unique_macs.update([src_mac, dst_mac])  # Add to the MAC address set.
            logging.info(f"{protocol} - Src: {src_mac}:{src_port or 'None'}, "
                         f"Dst: {dst_mac}:{dst_port or 'None'}, Size: {len(packet)}, Timestamp: {timestamp}")
            connection = (src_mac, dst_mac)
            if connection not in connections:
                connections.add(connection)
                connections_per_protocol[protocol] += 1
                connection_timestamps[protocol].append(timestamp)

    # Check if the packet has IP layer
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = "IP"
        unique_ips.update([src_ip, dst_ip])  # Add to the IP address set.
        throughput_data[protocol] += len(packet)
        packet_count[protocol] += 1
        connection = (src_ip, dst_ip)
        if connection not in connections:
            connections.add(connection)
            connections_per_protocol[protocol] += 1
            connection_timestamps[protocol].append(timestamp)

    # Check if the packet has TCP layer
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        protocol = "TCP"
        tcp_flags = getattr(packet[scapy.TCP], "flags", None)
        if tcp_flags:
            logging.info(f"{protocol} - Src: {src_ip}:{src_port}, "
                         f"Dst: {dst_ip}:{dst_port}, Size: {len(packet)}, Timestamp: {timestamp}")
        connection = (src_ip, dst_ip, src_port, dst_port)
        if connection not in connections:
            connections.add(connection)
            connections_per_protocol[protocol] += 1
            connection_timestamps[protocol].append(timestamp)

        # Latency measurement
        if src_ip and dst_ip:
            if (dst_ip, src_ip) in latency_data and "start" in latency_data[(dst_ip, src_ip)]:
                latency_data[(dst_ip, src_ip)]["end"] = timestamp
            elif (src_ip, dst_ip) not in latency_data:
                latency_data[(src_ip, dst_ip)] = {"start": timestamp}

    # Check if the packet has UDP layer
    if packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        protocol = "UDP"
        connection = (src_ip, dst_ip)
        if connection not in connections:
            connections.add(connection)
            connections_per_protocol[protocol] += 1
            connection_timestamps[protocol].append(timestamp)

        # Latency tracking for UDP (same as TCP logic)
        if src_ip and dst_ip:
            if (dst_ip, src_ip) in latency_data and "start" in latency_data[(dst_ip, src_ip)]:
                latency_data[(dst_ip, src_ip)]["end"] = timestamp
            elif (src_ip, dst_ip) not in latency_data:
                latency_data[(src_ip, dst_ip)] = {"start": timestamp}

    if protocol:  # Gen handling for any other protocol detected ( to avoid errors)
        throughput_data[protocol] += len(packet)
        packet_count[protocol] += 1
        logging.info(f"{protocol} - Src: {src_ip or src_mac}:{src_port or 'None'}, "
                     f"Dst: {dst_ip or dst_mac}:{dst_port or 'None'}, Size: {len(packet)}, Timestamp: {timestamp}")


def parse_log_file(file_path): 
    log_data = []
    with open(file_path, "r") as file:
        for line in file:
            if "Size:" in line:
                parts = line.split(" - ", 1)
                if len(parts) == 2:
                    timestamp_part, details_part = parts
                    timestamp = " ".join(timestamp_part.split()[:2])
                    protocol = timestamp_part.split()[-1]  
                    size_info = details_part.split("Size:")
                    if len(size_info) > 1:
                        size = size_info[1].split(",")[0].strip() 
                        if size.isdigit():
                            log_data.append({"timestamp": timestamp, "protocol": protocol, "size": int(size)})
    df = pd.DataFrame(log_data)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    df = df.dropna(subset=["timestamp"])
    return df


def create_visualizations(log_df, latency_data, unique_ips, unique_macs, log_file):
    sns.set_theme(style="whitegrid")  #  aesthetics
    

    # Throughput Over Time Visualization
    log_df["time_sec"] = (log_df["timestamp"] - log_df["timestamp"].min()).dt.total_seconds()
    throughput = log_df.groupby(["protocol", "time_sec"])["size"].sum().reset_index()
    protocols_of_interest = ["Ethernet", "IP", "TCP", "UDP"]
    throughput = throughput[throughput["protocol"].isin(protocols_of_interest)]
    plt.figure(figsize=(14, 8))
    for protocol in protocols_of_interest:
        data = throughput[throughput["protocol"] == protocol]
        if not data.empty:
            plt.plot(data["time_sec"], data["size"], label=protocol, linewidth=2)
    plt.title("Throughput Over Time (Per Protocol)", fontsize=20, weight="bold")
    plt.xlabel("Time (seconds)", fontsize=16)
    plt.ylabel("Throughput (bytes)", fontsize=16)
    plt.legend(title="Protocol", fontsize=12, loc="upper left")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("throughput_over_time.png", bbox_inches="tight")
    plt.clf()

    # Latency Distribution Visualization
    latencies = [
        (data["end"] - data["start"]) * 1000
        for conn, data in latency_data.items()
        if "start" in data and "end" in data
    ]
    if latencies:
        latency_values = pd.Series(latencies).sort_values()
        plt.figure(figsize=(12, 8))
        plt.plot(latency_values.index, latency_values.values, color="blue", linewidth=2, label="Average")
        plt.title("Latency Distribution", fontsize=20, weight="bold")
        plt.xlabel("Connections", fontsize=16)
        plt.ylabel("Latency (ms)", fontsize=16)
        plt.legend(fontsize=12)
        plt.grid(True, linestyle="--", alpha=0.5)
        plt.tight_layout()
        plt.savefig("latency_distribution.png", bbox_inches="tight")
        plt.clf()
    else:
        print("No latency data available for visualization.")

    # Protocol Usage Visualization
    counts = log_df["protocol"].value_counts()
    unique_ips_count = len(unique_ips)
    unique_macs_count = len(unique_macs)
    data = counts.to_dict()
    data["Unique IPs"] = unique_ips_count
    data["Unique MACs"] = unique_macs_count
    categories = list(data.keys())
    values = list(data.values())

    plt.figure(figsize=(14, 8))
    sns.barplot(x=categories, y=values, edgecolor="black")  # Removed the palette to avoid the warning
    for i, value in enumerate(values):
        plt.text(i, value + max(values) * 0.02, str(value), ha="center", fontsize=12, weight="bold")
    plt.title("Protocol Usage and Unique Entities", fontsize=20, weight="bold")
    plt.xlabel("Category", fontsize=16)
    plt.ylabel("Count", fontsize=16)
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig("protocol_usage_updated.png", bbox_inches="tight")
    plt.clf()

    print("All visualizations saved successfully.")

# Throughput calculation
def calculate_throughput(interval=10):
    while not exit_flag.is_set():
        start_time = time.time()
        time.sleep(interval)
        if exit_flag.is_set():  # NO printing after exit 
            break
        end_time = time.time()
        elapsed_time = end_time - start_time
        print("--- Throughput (bps) ---")
        for protocol, bytes_count in throughput_data.items():
            throughput_bps = (bytes_count * 8) / interval   
            print(f"{protocol}: {throughput_bps:.2f} bps")
            throughput_history[protocol].append((time.time() * 1000, throughput_bps)) 
        print("------------------------")
        throughput_data.clear()

# Real-time statistics display
def display_real_time_statistics(interval=30):
    while not exit_flag.is_set():
        if not unique_ips and not unique_macs:  #dont print when we havent collected any traffic yet
            time.sleep(interval)
            continue  # Skip , cleaner output 
        
        with output_lock:  # race condition
            print("\n" + "=" * 30)
            print("--- Real-Time Network Statistics ---")
            print(f"Unique IP Addresses: {len(unique_ips)}")
            print(f"Unique MAC Addresses: {len(unique_macs)}")

            for protocol, count in packet_count.items():
                avg_size = throughput_data[protocol] / count if count > 0 else 0
                print(f"{protocol}:")
                print(f"  - Connections: {connections_per_protocol.get(protocol, 0)}")
                print(f"  - Total Packets: {count}")
                print(f"  - Average Packet Size: {avg_size:.2f} bytes")
        
        time.sleep(interval)  # every 30 seconds

# Start real-time statistics display in a separate thread , Race condition
threading.Thread(target=display_real_time_statistics, daemon=True).start()

# Latency calculation
def calculate_latency():
    total_latency = 0
    count = 0
    for conn_key, times in latency_data.items():
        if "start" in times and "end" in times:
            latency = (times["end"] - times["start"]) * 1000
            total_latency += latency
            count += 1
            avg_latency= total_latency / count if count > 0 else 0
    print(f"\nAverage Latency: {avg_latency:.2f} ms") 

def calculate_network_metrics(interval=30):
    last_connection_count = len(connections)  # Initialize with the current total connections
    
    while not exit_flag.is_set():
        if not unique_ips and not unique_macs: 
            time.sleep(interval)
            continue  # Skip
        with output_lock:
            print("\n" + "=" * 30)
            print("--- Network Metrics ---")

            # Reset interval-specific metrics
            new_connections = len(connections) - last_connection_count
            last_connection_count = len(connections)  # Update for the next interval

            # Unique IPs and MACs
            total_unique_ips = len(unique_ips)
            total_unique_macs = len(unique_macs)
            print(f"Total Unique IP Addresses: {total_unique_ips}")
            print(f"Total Unique MAC Addresses: {total_unique_macs}")
            print(f"Total Connections: {len(connections)}")
            print(f"New Connections (last {interval} seconds): {new_connections}")
            connection_rate = new_connections / interval
            print(f"Connection Rate: {connection_rate:.2f} connections/second")

            # Protocol metrics
            for protocol, count in packet_count.items():
                avg_size = throughput_data[protocol] / count if count > 0 else 0
                connection_rate_protocol = (
                    len(connection_timestamps[protocol]) /
                    (time.time() - connection_timestamps[protocol][0])
                    if protocol in connection_timestamps and connection_timestamps[protocol]
                    else 0
                )
                print(f"{protocol} Metrics:")
                print(f"  - Total Packets: {count}")
                print(f"  - Average Packet Size: {avg_size:.2f} bytes")
                print(f"  - Connection Rate: {connection_rate_protocol:.2f} connections/second")
                print("=" * 30)
        time.sleep(interval)
            
# Start real-time network metrics display in a separate thread , Race condition
threading.Thread(target=calculate_network_metrics, daemon=True).start()

# Graceful termination
def graceful_exit():
    calculate_latency()
    print("\nStopping server and sniffing...")
    exit_flag.set()  # stop ALL threads
    sniffing_active.set()  # Stop sniffing
    log_df = parse_log_file(log_file)
    create_visualizations(log_df, latency_data, unique_ips, unique_macs, log_file)
    print("Server stopped.")
    time.sleep(1) 
    with output_lock:
        exit(0)  


def monitor_stop_key():
    print("Press Ctrl+Q to stop the server...")
    keyboard.wait("ctrl+q")
    graceful_exit()


def start_sniffing():
    sniffing_active.set()
    scapy.sniff(prn=process_packet, stop_filter=lambda _: exit_flag.is_set())


# Main func
if __name__ == "__main__":
    try:
        threading.Thread(target=monitor_stop_key, daemon=True).start()
        threading.Thread(target=calculate_throughput).start()
        threading.Thread(target=calculate_network_metrics, daemon=True).start()
        start_sniffing()
    except KeyboardInterrupt:
        graceful_exit()