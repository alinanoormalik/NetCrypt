from scapy.all import sniff, IP, TCP, UDP, ICMP,ARP, Raw          #scappy library for packet sniffing

PACKET_BATCH = 5                                                  # Pause after every 5 packets
packet_count = 0                                                  #counter for all packets captured

def process_packet(packet):
    global packet_count
    packet_count += 1                                             #increase packet count

    if IP in packet:                                      
        ip_layer = packet[IP]
        proto = "Other"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        elif ARP in packet:
            proto = "ARP"
        print(f"[{proto}] {ip_layer.src} -> {ip_layer.dst}")     #print source and destination ip for packet type

        if Raw in packet:                                        #printing first 32 bits of Raw data: the actual payload/content of the packet, shown if available

            raw_data = packet[Raw].load
            print(f"    Raw data: {raw_data[:32]}...")
    
    #to ask again after packet_batch limit
    if packet_count % PACKET_BATCH == 0:
        user_input = input(f"\n🛑 {PACKET_BATCH} packets captured. Continue? (y/n): ").strip().lower()
        print("\n")
        if user_input != 'y':
            print("🔚 Sniffer stopped by user.")
            exit()

#Starting sniffing and not storing the packet in memory
print("               🚀 SnifferX    ")
print("Packet Sniffer started.Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)
