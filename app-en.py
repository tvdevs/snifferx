from scapy.all import IP, TCP, UDP, ICMP, sniff
from scapy.layers.dns import DNS

def print_banner():
    print(r"""
    ----------------------- [Sniffer X] ------------------------
        ________      ____________________           ____  __
        __  ___/_________(_)__  __/__  __/_____________  |/ /
        _____ \__  __ \_  /__  /_ __  /_ _  _ \_  ___/_    / 
        ____/ /_  / / /  / _  __/ _  __/ /  __/  /   _    |  
        /____/ /_/ /_//_/  /_/    /_/    \___//_/    /_/|_|  
                Developed by Kesdy | Instagram: @kesdyy                           
    """)

def packet_callback(packet):
    try:
        # If the packet is an IP packet
        if packet.haslayer(IP):
            ip_src = packet[IP].src  # Source IP address
            ip_dst = packet[IP].dst  # Destination IP address

            # Prepare output format
            output = f"[IP] Source: {ip_src} -> Destination: {ip_dst}"

            # If it's a TCP packet
            if packet.haslayer(TCP):
                output += f" | [TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}"

            # If it's a UDP packet
            elif packet.haslayer(UDP):
                output += f" | [UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}"

            # If it's an ICMP packet
            elif packet.haslayer(ICMP):
                output += f" | [ICMP] Type: {packet[ICMP].type}"

            # If it's a DNS packet
            if packet.haslayer(DNS):
                dns_query = packet[DNS].qd.qname.decode("utf-8") if packet[DNS].qd else "None"
                output += f" | [DNS] Query: {dns_query}"

            print(output)

    except Exception as e:
        print(f"An error occurred: {e}")

def start_sniffer():
    # Ask the user to input the interface and the number of packets
    iface = input("Enter the network interface to listen on (e.g., wlan0, eth0): ")
    packet_count = int(input("Enter the number of packets you want to listen to: "))
    
    # Start the sniffer
    try:
        sniff(iface=iface, prn=packet_callback, store=0, count=packet_count)
    except Exception as e:
        print(f"Error starting sniffer: {e}")

def start_filtered_sniffer():
    iface = input("Enter the network interface to listen on (e.g., wlan0, eth0): ")
    packet_count = int(input("Enter the number of packets you want to listen to: "))
    protocol_filter = input("Choose the protocol you want to filter (tcp, udp, icmp, dns): ").lower()

    def filtered_callback(packet):
        if protocol_filter == "tcp" and packet.haslayer(TCP):
            packet_callback(packet)
        elif protocol_filter == "udp" and packet.haslayer(UDP):
            packet_callback(packet)
        elif protocol_filter == "icmp" and packet.haslayer(ICMP):
            packet_callback(packet)
        elif protocol_filter == "dns" and packet.haslayer(DNS):
            packet_callback(packet)

    try:
        sniff(iface=iface, prn=filtered_callback, store=0, count=packet_count)
    except Exception as e:
        print(f"Error starting sniffer: {e}")

def start_logging_sniffer():
    iface = input("Enter the network interface to listen on (e.g., wlan0, eth0): ")
    packet_count = int(input("Enter the number of packets you want to listen to: "))
    log_file = input("Enter the name of the log file: ")
    
    with open(log_file, "w") as f:
        def log_callback(packet):
            try:
                if packet.haslayer(IP):
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    output = f"[IP] Source: {ip_src} -> Destination: {ip_dst}"

                    if packet.haslayer(TCP):
                        output += f" | [TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}"
                    elif packet.haslayer(UDP):
                        output += f" | [UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}"
                    elif packet.haslayer(ICMP):
                        output += f" | [ICMP] Type: {packet[ICMP].type}"
                    if packet.haslayer(DNS):
                        dns_query = packet[DNS].qd.qname.decode("utf-8") if packet[DNS].qd else "None"
                        output += f" | [DNS] Query: {dns_query}"
                    
                    print(output)
                    f.write(output + "\n")
            except Exception as e:
                print(f"An error occurred: {e}")
                f.write(f"An error occurred: {e}\n")
        
        try:
            sniff(iface=iface, prn=log_callback, store=0, count=packet_count)
        except Exception as e:
            print(f"Error starting sniffer: {e}")

def main():
    print_banner()
    print("Options:")
    print("1. Start Packet Sniffer")
    print("2. Filter by Specific Protocol")
    print("3. Logging Mode")
    print("4. Exit")

    choice = input("Select an option (1-4): ")

    if choice == "1":
        start_sniffer()
    elif choice == "2":
        start_filtered_sniffer()
    elif choice == "3":
        start_logging_sniffer()
    elif choice == "4":
        print("Exiting...")
    else:
        print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
