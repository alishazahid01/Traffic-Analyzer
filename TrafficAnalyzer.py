# Network sniffer and Analyze Packet
import netifaces
import pyshark
from scapy.all import sniff, wrpcap

# Function for finding all networks
def find_all_networks():
    interfaces = netifaces.interfaces() # Get a list of available network interfaces

    interfaces_list = []

    for interface in interfaces:
        interface_info = {
            'name': interface,
            'ip': netifaces.ifaddresses(interface).get(netifaces.AF_INET, [{'addr': 'No IP'}])[0]['addr'],
        }
        interfaces_list.append(interface_info)

    return interfaces_list

# Capturing packets and saving them to a file
def packet_capturing(packet):
    global captured_packets

    captured_packets.append(packet)  # Add the captured packet to the list

    if len(captured_packets) >= 10:
        wrpcap("packets.pcap", captured_packets)  # Save the captured packets to a pcap file
        print("Packets captured and saved successfully.")

# Analyze packets and write to a file
def packet_analyzer():
    # Open the output file in write mode
    with open("packet_info.txt", "w") as file:
        # Reading packet file
        capture = pyshark.FileCapture("packets.pcap")

        # Iterate over the packets
        for packet in capture:
            # Process each packet
            if 'IP' in packet:
                ip_layer = packet['IP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto

                file.write(f"Source IP: {src_ip}\n")
                file.write(f"Destination IP: {dst_ip}\n")
                file.write(f"Protocol: {protocol}\n")

                if 'TCP' in packet:
                    tcp_layer = packet['TCP']
                    src_port = tcp_layer.srcport
                    dst_port = tcp_layer.dstport
                    flags = tcp_layer.flags

                    file.write(f"Source Port: {src_port}\n")
                    file.write(f"Destination Port: {dst_port}\n")
                    file.write(f"Flags: {flags}\n")

                elif 'UDP' in packet:
                    udp_layer = packet['UDP']
                    src_port = udp_layer.srcport
                    dst_port = udp_layer.dstport

                    file.write(f"Source Port: {src_port}\n")
                    file.write(f"Destination Port: {dst_port}\n")

                elif 'ICMP' in packet:
                    icmp_layer = packet['ICMP']
                    icmp_type = icmp_layer.type
                    icmp_code = icmp_layer.code

                    file.write(f"ICMP Type: {icmp_type}\n")
                    file.write(f"ICMP Code: {icmp_code}\n")

        print("Packet information written to packet_info.txt successfully.")

if __name__ == "__main__":
    networks = find_all_networks()

    # Checking availability of the networks
    if len(networks) > 0:
        print("Networks Found :)")
        for network in networks:
            print(network)

        # Which interface user wants to use from the available interfaces
        select_iface = input("Enter the interface: ")
        select_filtering = input("Enter the filter (tcp/udp): ")

        # Initialize the list to store captured packets
        captured_packets = []

        # Network sniff
        sniff(iface=select_iface, filter=select_filtering, prn=packet_capturing, count=10)
        
        # Call packet_analyzer function
        packet_analyzer()

    else:
        print("No Network Found :(")
