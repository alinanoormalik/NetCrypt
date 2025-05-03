# Guardify – Wi-Fi Device Monitor & Rogue Access Point Detector
**Guardify** is a Python script that monitors devices connected to your Wi-Fi network and detects unauthorized (rogue) routers. 
It uses ARP requests to identify devices, shows their vendor info and type, and keeps a history of all devices that have connected.

---

## ⚙️ What It Does

- Scans your local network for connected devices  
- Identifies devices by MAC address and vendor  
- Classifies them as Laptop, Mobile, Router, etc.  
- Alerts you about unknown or unauthorized devices  
- Detects suspicious or rogue routers  
- Saves device history to a local file

---

## 🔧 Before You Run

### 1. **Change the IP Range**
Edit the `IP_RANGE` variable near the top of the script:
IP_RANGE = "192.168.100.0/24"  # Replace with your actual subnet
You can find your IP range by checking your local IP and adjusting accordingly (e.g., 192.168.1.0/24).

### 2. Set Your Authorized Devices
Update the AUTHORIZED_DEVICES dictionary with the MAC addresses of devices you trust:
AUTHORIZED_DEVICES = {
    "60:F6:77:8A:A9:53": "My Laptop",
    "2A:EA:EA:D4:18:DF": "My Phone",
    "28:11:EC:93:55:C8": "My Router"
}
This ensures only your known devices are marked as authorized.

---

📦 Requirements

Python 3.x
- `scapy`
- `manuf`
- **Npcap (required for ARP scanning to work on Windows):**  
  Download from [https://nmap.org/npcap](https://nmap.org/npcap)

You can install the Python libraries using pip:
pip install scapy manuf

Install dependencies:
pip install scapy python-manuf

- Run
Root/admin privileges

sudo python guardify.py
---
You’ll see a menu with these options
1. Monitor Devices on Network
2. Scan for Rogue Access Points
3. Show Known Device History
4. Exit

---
## 📤 Expected Output
- Device Monitor:  
  `[UNAUTHORIZED] Unknown Device | IP: 192.168.100.22 | MAC: 7C:D9:5C:AE:12:34 | Vendor: Unknown Vendor | Type: Possible Mobile (Randomized MAC)`

- Rogue AP Detection:  
  `⚠️ Rogue Router Detected! MAC: 00:1D:A1:FF:EE:11 | IP: 192.168.100.11 | Vendor: TP-Link`

- Known Device History:  
  `60:F6:77:8A:A9:53 | First Seen: Sat May 03 15:40:21 2025 | Vendor: Dell | Type: Laptop / PC`

---
📌 Notes
Device history is saved in `device_history.json` in the same folder.
New, unknown devices are flagged during scans.
Rogue router is detected if not listed in authorized devices.
Works best on Linux (for full ARP functionality)
This script does not modify your network — it's passive monitoring

---
## ⚠️ Disclaimer
This script is intended for use on your own local network only. Do not use it on networks you do not own or have explicit permission to analyze.

---

👤 Author
Created by Alina Noor Malik – a simple tool for keeping an eye on your Wi-Fi environment.