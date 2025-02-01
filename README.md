# README (SnifferX)

English:
SnifferX Tool
This is a network packet sniffer tool developed by Kesdy. It allows users to capture and analyze packets on a specified network interface. The tool supports multiple modes including basic packet sniffing, filtering by protocol, and logging packets to a file.

Features:
Captures and displays network packets.
Can filter packets by protocol (TCP, UDP, ICMP, DNS).
Logs captured packets to a file for later analysis.
Supports multiple network interfaces like wlan0, eth0, etc.
How to Use:
Run the script.
Choose one of the available modes:
Start a basic packet sniffer.
Filter packets by protocol.
Log packets to a file.
Enter the network interface (e.g., wlan0, eth0) and the number of packets you wish to capture.
The program will display captured packets in real-time and log the information if chosen.
Note: The sniffer will stop after capturing the specified number of packets. Use the logging feature to save the data for further analysis.

Note 2 : 
The Scapy library is required.
To install it, use the following command:
`pip install scapy`


-------------------------------------------------------------------------------------------------------------------------------------------------
Türkçe:
SnifferX Aracı
Bu, Kesdy tarafından geliştirilen bir ağ paket dinleyici aracıdır. Kullanıcıların belirli bir ağ arayüzünde paketleri yakalayıp analiz etmelerini sağlar. Araç, temel paket dinleme, protokole göre filtreleme ve paketleri dosyaya kaydetme gibi birden fazla modu destekler.

Özellikler:
Ağ paketlerini yakalar ve görüntüler.
Paketleri protokole göre filtreleyebilir (TCP, UDP, ICMP, DNS).
Yakalanan paketleri bir dosyaya kaydedebilir.
wlan0, eth0 gibi birden fazla ağ arayüzünü destekler.
Kullanım:
Script'i çalıştırın.
Kullanılabilir modlardan birini seçin:
Temel paket dinleyiciyi başlatın.
Paketleri protokole göre filtreleyin.
Paketleri bir dosyaya kaydedin.
Ağ arayüzünü (örneğin, wlan0, eth0) ve yakalamak istediğiniz paket sayısını girin.
Program, yakalanan paketleri gerçek zamanlı olarak görüntüleyecek ve seçilirse verileri dosyaya kaydedecektir.
Not: Sniffer, belirtilen paket sayısını yakaladıktan sonra duracaktır. Verileri kaydetmek için loglama özelliğini kullanabilirsiniz.

Note 2 : 
Scapy kütüphanesi gereklidir.
Yüklemek için aşağıdaki komutu kullanın:
`pip install scapy`
