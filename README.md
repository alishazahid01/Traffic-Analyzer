# Traffic-Analyzer
Network Sniffer and Packet Analyzer
Introduction
This Python script captures network packets on a specified network interface, filters the packets based on user-defined criteria (TCP/UDP), and saves the captured packets to a .pcap file. Additionally, it analyzes the captured packets and extracts essential information like source IP, destination IP, protocol, source port, destination port, and flags (for TCP packets). The script utilizes the netifaces, pyshark, and scapy libraries for network interfacing, packet capturing, and analysis, respectively.
Components
1. Finding Available Networks
    • The find_all_networks() function uses the netifaces library to find all available network interfaces and their IP addresses.
    • It returns a list of dictionaries containing interface names and corresponding IP addresses.
2. Packet Capturing
    • The packet_capturing(packet) function appends captured packets to a global list (captured_packets).
    • When the number of captured packets reaches 10, it saves the packets to a .pcap file using the wrpcap() function from scapy.
3. Packet Analysis
    • The packet_analyzer() function reads the saved .pcap file using pyshark.FileCapture.
    • It iterates through the captured packets and processes each packet based on its protocol (TCP, UDP, or ICMP).
    • It extracts essential information from each packet and writes it to a packet_info.txt file.
4. Main Execution
    • The script prompts the user to enter the network interface to sniff packets on (select_iface) and the filtering criteria (select_filtering) - either 'tcp' or 'udp'.
    • It calls the sniff() function from scapy to capture packets on the specified interface and filter.
    • After capturing packets, it calls the packet_analyzer() function to analyze and write packet information to packet_info.txt.
How to Use
    1. Available Networks:
        ◦ Run the script.
        ◦ The script will display available network interfaces and their IP addresses.
    2. Select Interface and Filtering Criteria:
        ◦ Enter the desired network interface name when prompted.
        ◦ Enter the filtering criteria ('tcp' or 'udp').
    3. Packet Capture and Analysis:
        ◦ The script will capture packets on the specified interface based on the filtering criteria.
        ◦ After capturing 10 packets, it will save them to packets.pcap and analyze the packets, writing the extracted information to packet_info.txt.
Note
    • Adjust Number of Packets: Modify the count parameter in the sniff() function to capture a different number of packets.
    • Permissions: Ensure the script has necessary permissions to access network interfaces for packet capturing. Run the script with appropriate privileges (e.g., using sudo on Linux).
