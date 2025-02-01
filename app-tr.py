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
                Kesdy Tarafından | Instagram: @kesdyy                           
    """)

def packet_callback(packet):
    try:
        # Paket IP paketi ise
        if packet.haslayer(IP):
            ip_src = packet[IP].src  # Kaynak IP adresi
            ip_dst = packet[IP].dst  # Hedef IP adresi

            # Çıkış formatını hazırlayalım
            output = f"[IP] Kaynak: {ip_src} -> Hedef: {ip_dst}"

            # TCP protokolü varsa
            if packet.haslayer(TCP):
                output += f" | [TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}"

            # UDP protokolü varsa
            elif packet.haslayer(UDP):
                output += f" | [UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}"

            # ICMP protokolü varsa
            elif packet.haslayer(ICMP):
                output += f" | [ICMP] Tür: {packet[ICMP].type}"

            # DNS protokolü varsa
            if packet.haslayer(DNS):
                dns_query = packet[DNS].qd.qname.decode("utf-8") if packet[DNS].qd else "Yok"
                output += f" | [DNS] Sorgu: {dns_query}"

            print(output)

    except Exception as e:
        print(f"Bir hata oluştu: {e}")

def start_sniffer():
    # Kullanıcıya arayüz ve paket sayısını seçme imkanı sunalım
    iface = input("Dinlenecek ağ arayüzünü girin (ör. wlan0, eth0): ")
    packet_count = int(input("Dinlemek istediğiniz paket sayısını girin: "))
    
    # Sniffer'ı başlat
    try:
        sniff(iface=iface, prn=packet_callback, store=0, count=packet_count)
    except Exception as e:
        print(f"Sniffer çalıştırılırken hata: {e}")

def start_filtered_sniffer():
    iface = input("Dinlenecek ağ arayüzünü girin (ör. wlan0, eth0): ")
    packet_count = int(input("Dinlemek istediğiniz paket sayısını girin: "))
    protocol_filter = input("Filtrelemek istediğiniz protokolü seçin (tcp, udp, icmp, dns): ").lower()

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
        print(f"Sniffer çalıştırılırken hata: {e}")

def start_logging_sniffer():
    iface = input("Dinlenecek ağ arayüzünü girin (ör. wlan0, eth0): ")
    packet_count = int(input("Dinlemek istediğiniz paket sayısını girin: "))
    log_file = input("Log dosyasının adını girin: ")
    
    with open(log_file, "w") as f:
        def log_callback(packet):
            try:
                if packet.haslayer(IP):
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    output = f"[IP] Kaynak: {ip_src} -> Hedef: {ip_dst}"

                    if packet.haslayer(TCP):
                        output += f" | [TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}"
                    elif packet.haslayer(UDP):
                        output += f" | [UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}"
                    elif packet.haslayer(ICMP):
                        output += f" | [ICMP] Tür: {packet[ICMP].type}"
                    if packet.haslayer(DNS):
                        dns_query = packet[DNS].qd.qname.decode("utf-8") if packet[DNS].qd else "Yok"
                        output += f" | [DNS] Sorgu: {dns_query}"
                    
                    print(output)
                    f.write(output + "\n")
            except Exception as e:
                print(f"Bir hata oluştu: {e}")
                f.write(f"Bir hata oluştu: {e}\n")
        
        try:
            sniff(iface=iface, prn=log_callback, store=0, count=packet_count)
        except Exception as e:
            print(f"Sniffer çalıştırılırken hata: {e}")

def main():
    print_banner()
    print("Seçenekler:")
    print("1. Paket Dinleyiciyi Başlat")
    print("2. Belirli Bir Protokolü Filtreleme")
    print("3. Loglama")
    print("4. Çıkış")

    choice = input("Bir seçenek seçin (1-4): ")

    if choice == "1":
        start_sniffer()
    elif choice == "2":
        start_filtered_sniffer()
    elif choice == "3":
        start_logging_sniffer()
    elif choice == "4":
        print("Çıkış yapılıyor...")
    else:
        print("Geçersiz seçenek. Lütfen tekrar deneyin.")

if __name__ == "__main__":
    main()
