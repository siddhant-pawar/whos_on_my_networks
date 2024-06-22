# whos_on_my_networks
This Python script for real-time usage monitoring LAN. It aids network administrators in managing and securing networks by providing insights into device connections, OS details, and live traffic monitoring, suitable for both educational and practical network management purposes.
## Purpose:
The script is designed to scan a local network, visualize the network topology, and monitor network usage in real-time. It utilizes various Python libraries to achieve these tasks seamlessly.

## Applications:
- Network Administration:
  - Useful for network administrators to visualize and monitor devices on a local network.
- Security Monitoring:
  - Provides insights into connected devices and potential vulnerabilities.
- Educational Purposes:
  - Demonstrates integration of network scanning, graph visualization, and real-time monitoring using Python libraries.
  
## Dependencies:
- External Dependencies:
  - Requires ```nmap``` for network scanning (download from https://nmap.org/download).
- Python Dependencies:
  - Install using ```pip install python-nmap networkx matplotlib psutil```.

### Key Components and Functions:
- ### Network Scanning (scan_local_network function):
  - Uses nmap (```nmap.PortScanner()```) to perform a comprehensive scan of the local network.
  - The scan is configured for the CIDR notation ```192.168.1.0/24``` (adjustable as per network configuration) to discover connected devices.
  - Retrieves information such as IP address, MAC address, device name, and operating system using the ```-O``` option for OS detection.

- ### Network Visualization (visualize_network function):
  - Constructs a network graph using networkx (```nx.Graph()```).
  - Adds nodes to the graph for each discovered device, labeled with the device name and IP address.
  - Establishes edges between nodes to represent network connections between devices.

- ### Graph Drawing (draw_network function):
  - Uses ```matplotlib``` to draw the network graph.
  - Nodes are colored based on a hash of the operating system type (```os_labels```) to visually differentiate devices.
  - Applies a spring layout (```nx.spring_layout```) to position nodes in the graph for better clarity.

- ### Network Monitoring (```monitor_network_usage``` function):

    - Sets up an interactive plot (```plt.ion()```) with matplotlib to continuously monitor network usage.
    - Creates a figure (fig) to display the network graph and statistics.
    - Uses psutil to fetch network I/O statistics (```psutil.net_io_counters```) per network interface.
    - Updates the network graph visualization (```draw_network```) with current network connections and device states.
    - Prints network statistics (bytes sent and received) for each network interface in real-time.
    - Pauses for a specified interval (```interval```) between updates.
    - Gracefully stops monitoring on ```KeyboardInterrupt``` (```Ctrl+C```), switching off interactive mode (```plt.ioff()```) and displaying the final plot.

- ### Main Execution (__main__ section):

  - Checks if the script is executed directly (```if __name__ == "__main__":```).
  - Invokes ```scan_local_network``` to discover devices connected to the local network.
  - If devices are found, prints detailed information about each device (name, IP address, MAC address, OS).
  - Constructs a network graph (```G```) using ```visualize_network```.
  - Initiates network monitoring (```monitor_network_usage(G)```) to visualize and monitor network usage in real-time
