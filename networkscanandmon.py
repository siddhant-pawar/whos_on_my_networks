""" Before running this code install nmap:
https://nmap.org/download and 
also install python-nmap:
pip install python-nmap"""
import nmap
import networkx as nx
import matplotlib.pyplot as plt
import psutil
import time
from threading import Thread

def scan_local_network():
    # Create nmap PortScanner object
    nm = nmap.PortScanner()
    
    # Perform a comprehensive scan on the local network (adjust CIDR notation as per your network)
    try:
        nm.scan(hosts='192.168.1.0/24', arguments='-O')
    except nmap.PortScannerError as e:
        print(f"Nmap error: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []
    
    # List to store discovered devices
    connected_devices = []
    
    # Iterate over scanned hosts
    for host in nm.all_hosts():
        ip_address = nm[host]['addresses'].get('ipv4', 'Unknown')
        mac_address = nm[host]['addresses'].get('mac', 'Unknown')
        device_name = nm[host]['hostnames'][0]['name'] if 'hostnames' in nm[host] and nm[host]['hostnames'] else 'Unknown'
        
        # Check if 'osmatch' exists and has at least one entry
        os_info = 'Unknown'
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            if 'osclass' in nm[host]['osmatch'][0] and nm[host]['osmatch'][0]['osclass']:
                os_info = nm[host]['osmatch'][0]['osclass'][0].get('osfamily', 'Unknown')
        
        connected_devices.append({
            'IP Address': ip_address,
            'MAC Address': mac_address,
            'Device Name': device_name,
            'OS': os_info
        })
    
    return connected_devices

def visualize_network(devices):
    # Create a network graph
    G = nx.Graph()
    
    # Add nodes and edges
    for device in devices:
        node_label = f"{device['Device Name']} ({device['IP Address']})"
        G.add_node(node_label, os=device['OS'])
    
    # Add edges between all nodes to visualize the network connections
    for i, device1 in enumerate(devices):
        for j, device2 in enumerate(devices):
            if i != j:
                G.add_edge(f"{device1['Device Name']} ({device1['IP Address']})",
                           f"{device2['Device Name']} ({device2['IP Address']})")
    
    return G

def draw_network(G):
    pos = nx.spring_layout(G)
    os_labels = nx.get_node_attributes(G, 'os')
    node_colors = [hash(os_labels[node]) % 10 for node in G.nodes()]  # Color nodes by OS hash

    plt.clf()  # Clear the current figure
    nx.draw_networkx(G, pos, with_labels=True, node_color=node_colors, cmap=plt.cm.rainbow, font_weight='bold')
    plt.title("Network Devices and Connections")
    plt.pause(0.1)  # Pause to allow the plot to update

def monitor_network_usage(G, interval=1):
    plt.ion()  # Enable interactive mode
    fig = plt.figure(figsize=(15, 10))
    print("Monitoring network usage... Press Ctrl+C to stop.")
    
    try:
        while True:
            net_io = psutil.net_io_counters(pernic=True)
            
            # Print the stats for each network interface
            for iface, stats in net_io.items():
                print(f"{iface}: bytes sent={stats.bytes_sent}, bytes received={stats.bytes_recv}")
            
            # Update graph visualization
            draw_network(G)
            
            # Wait for the specified interval
            time.sleep(interval)
            print("="*40)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    finally:
        plt.ioff()  # Disable interactive mode
        plt.show()

# Example usage:
if __name__ == "__main__":
    devices = scan_local_network()
    if devices:
        print("Connected devices details:")
        for device in devices:
            print(f"Name: {device['Device Name']}, IP: {device['IP Address']}, MAC: {device['MAC Address']}, OS: {device['OS']}")
        
        G = visualize_network(devices)
        
        # Monitor network usage
        monitor_network_usage(G, interval=1)
    else:
        print("No devices found or an error occurred.")
