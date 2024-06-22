
""" Before running this code install nmap:
https://nmap.org/download and 
also install python-nmap:
pip install python-nmap"""

import nmap

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

# Example usage:
if __name__ == "__main__":
    devices = scan_local_network()
    if devices:
        print("Connected devices details:")
        for device in devices:
            print(f"Name: {device['Device Name']}, IP: {device['IP Address']}, MAC: {device['MAC Address']}, OS: {device['OS']}")
    else:
        print("No devices found or an error occurred.")
