# SnifferX - Packet Sniffer

**Overview**:
SnifferX is a Python packet sniffer that captures network packets and displays basic information like protocol type (TCP, UDP, ICMP), source/destination IPs, and raw data when available.

**Features**:
- Captures **IP** layer packets, **TCP**, **UDP** and **ICMP** packets.
- Displays protocol, source/destination IP addresses, and **Raw Data** if available.
- Pauses after every 5 packets and asks to continue or stop.

**How to Use**:
1. Install Scapy: `pip install scapy`
2. Run the script: `python snifferX.py`
3. The sniffer will start capturing packets. After every 5 packets, it asks if you want to continue or stop.
4. Type `y` to continue, or `n` to stop.

**Output Example**:
               🚀 SnifferX    
Packet Sniffer started.Press Ctrl+C to stop.

[TCP] 185.117.83.139 -> 192.168.100.14

    Raw data: b"\xd2\xadY\x94'\xd2\xd4@\xa9\x8a\xfb\xb9+\x0fo=\xf0J\xf6\x15(Q\x85J\xf6\x05\xe9\x103\xdf\xf6\x02"...

[TCP] 192.168.100.14 -> 185.117.83.139

[TCP] 192.168.100.14 -> 185.117.83.139

[TCP] 101.78.134.82 -> 192.168.100.71

    Raw data: b'\x89\xc8\xbe\x1a\xc3\x96\xf0U\x9a\xdev\x1b\x90\r-\xf9\xeac\x97\x89\x90\xa4\x0c\xaax\xcf\xf5%M0\xc8y'...

[TCP] 192.168.100.71 -> 101.78.134.82

🛑 5 packets captured. Continue? (y/n):   