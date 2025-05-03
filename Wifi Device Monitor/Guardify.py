import os                                                                                  #Interact with OS
import platform                                                                            #Detect OS type
import time                                                                                #Time-related functions
import threading                                                                           #Running tasks simultaneously
import json                                                                                #Load and save history in json file
from scapy.all import ARP, Ether, srp                                                      #Sending receiving packets
from manuf import manuf                                                                    #Get manufacturer from device's MAC address




IP_RANGE = "192.168.100.0/24"                                                             #To scan IP range(change this based on your local network range)
SCAN_INTERVAL = 60                                                                        #Network scanning interval

#Mac addresses of authorized deivces you trust(change according to your devices)
AUTHORIZED_DEVICES = {
    "60:F6:77:8A:A9:53": "My Laptop",
   "2A:EA:EA:D4:18:DF": "My Phone",
   "28:11:EC:93:55:C8": "My Router"
}

#File to save device history
DEVICE_LOG_FILE = "device_history.json"
mac_parser = manuf.MacParser()

#Lists of devices to classify the devices
ROUTER_VENDORS = ["tp-link", "netgear", "asus", "d-link", "cisco", "zte", "huawei", "linksys", "mikrotik"]
MOBILE_VENDORS = ["apple", "samsung", "xiaomi", "oppo", "vivo", "realme", "nokia", "google", "oneplus", "huawei"]
LAPTOP_VENDORS = ["hp", "dell", "lenovo", "asus", "acer", "msi", "toshiba"]
OEM_VENDORS = ["hon hai", "foxconn", "pegatron", "wistron"]

#To check if Mac address is randomized(often used by mobile devices for privacy)
def is_randomized_mac(mac):
    try:
        first_octet = int(mac.split(":")[0], 16)                                         #Extract first part of MAC address
        return bool(first_octet & 0b10)                                                  #Check if second bit is set for randomization
    except:
        return False

#To get manufcturer from MAC address
def get_mac_vendor(mac):
    mac = mac.upper().replace("-", ":")                                                  #Ensure MAC address is in correct format
    vendor = mac_parser.get_manuf(mac)                                                   #Get vendor from Mac
    return vendor if vendor else "Unknown Vendor"
 
#To classify type of device based on vendor
def get_device_type(mac, vendor):
    vendor = vendor.lower()                                                              #Convert to lowercase for comparison

    #Check vendor name to classify devices
    if any(router in vendor for router in ROUTER_VENDORS):
        return "Router / Access Point"
    if any(m in vendor for m in MOBILE_VENDORS):
        return "Mobile Phone"
    if any(p in vendor for p in LAPTOP_VENDORS):
        return "Laptop / PC"
    if any(oem in vendor for oem in OEM_VENDORS):
        return "OEM Device (Likely Mobile)"
    if is_randomized_mac(mac) and vendor == "unknown vendor":
        return "Possible Mobile (Randomized MAC)"
    return "Unknown Device"

#Function to ping all IP addresses in a given IP range to find devices which are online
def ping_sweep(ip_range):
    base_ip = ip_range.split('/')[0].rsplit('.', 1)[0]                                 #Get base IP
    for i in range(1, 255):                                                            #Check IPs from .1 to .254
        ip = f"{base_ip}.{i}"                                                          #Generate each IP address in range
        if platform.system().lower() == "windows":                                     #Check if system is windows to run ping
            os.system(f"ping -n 1 -w 200 {ip} >nul")
        else:                                                                          #Ping for other than Window system
            os.system(f"ping -c 1 -W 1 {ip} >/dev/null 2>&1")

#To scan network and find devices based on ARP requests
def scan_network(ip_range):
    devices = {}                                                                      #To store devices
    base_ip = ip_range.split('/')[0].rsplit('.', 1)[0]                                #Get base IP
    threads = []                                                                      #List to keep concurrent scanning threads
  
    #To scan single IP address using ARP request
    def scan(ip):
        arp = ARP(pdst=ip)                                                            #ARP request for target IP
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")                                        #Ethernet frame to broadcast to all devices
        packet = ether / arp                                                          #Combining ARP & ethernet frame
        result = srp(packet, timeout=2, verbose=0)[0]                                 #Send packet and wait for response
        for _, received in result:                                                    #Loop through responses
            mac = received.hwsrc.upper()                                              #Get MAC from response
            ip = received.psrc                                                        #Get IP from response
            devices[mac] = ip                                                         #Add IP & MAC to dictionary

    #Scan all IP in range & creating threads for each IP
    for i in range(1, 255):                                                           #Iterate .1 to .254
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=scan, args=(ip,))                                 #Thread to scan list
        threads.append(t)                                                             #Start thread
        t.start()
    
    #Wait for all threads to finish
    for t in threads:
        t.join()

    return devices                                                                   #Return dictionary

#To load device history from json file
def load_device_history():
    if os.path.exists(DEVICE_LOG_FILE):                                             #Check if history file exists
        with open(DEVICE_LOG_FILE, "r") as f:                                       #Open file in read format
            return json.load(f)                                                     #Load and return json file
    return {}                                                                       #Return empty if no file

#To save device history in json file
def save_device_history(history):
    with open(DEVICE_LOG_FILE, "w") as f:                                           #Open file in write format
        json.dump(history, f, indent=2)                                             #Write histroy in file


#To monitor devices on network
def device_monitor():
    device_history = load_device_history()                                          #Load history from file      

    print("\n🛰️ Scanning Wi-Fi Network...")                                           

    ping_sweep(IP_RANGE)                                                           #Ping network to check active devices
    active_devices = scan_network(IP_RANGE)                                        #Scan to find active devices

    
    #Loop through all active devices found
    for mac, ip in active_devices.items():
        vendor = get_mac_vendor(mac)                                              #Get manufacturer of device
        dev_type = get_device_type(mac, vendor)                                   #Get device type
        label = AUTHORIZED_DEVICES.get(mac, "Unknown Device")                     #Label for authorized devices
        status = "AUTHORIZED" if mac in AUTHORIZED_DEVICES else "UNAUTHORIZED"    #Check if authorized or not
        
        #Print device information
        print(f"[{status}] {label} | IP: {ip} | MAC: {mac} | Vendor: {vendor} | Type: {dev_type}")
        
        #If device is new,add to history file
        if mac not in device_history:                                             #Log information when device was first seen
            device_history[mac] = {
                "first_seen": time.ctime(),                                 
                "vendor": vendor,
                "type": dev_type
            }
            print(f"[!] 🚨 New device detected: {mac} ({vendor})")                #Notify user of new device

    save_device_history(device_history)


    #Return to menu
    input("\nPress Enter to go back to the main menu...")


#To detect rogue(unauthorized) router
def detect_rogue_access_points():
    print("\n📡 Scanning for Rogue Access Points...")

    ping_sweep(IP_RANGE)                                                           #Ping netowork for active devices
    devices = scan_network(IP_RANGE)                                               #Scan network for active devices

    rogue_found = False                                                            #Flag to check if rogue router found
    
    #Loop through all devices to check for rogue router
    for mac, ip in devices.items():
        vendor = get_mac_vendor(mac)                                               #Print rogue router information
        if any(router in vendor.lower() for router in ROUTER_VENDORS) and mac not in AUTHORIZED_DEVICES:
            print(f"⚠️ Rogue Router Detected! MAC: {mac} | IP: {ip} | Vendor: {vendor}")     
            rogue_found = True                                                     #Set flag to true

    if not rogue_found:                                                            #If no rogue router found
        print("\n✅ No rogue routers detected.")



#Main Menu
def main_menu():
    while True:
        print("\n" + "="*45)
        print("              🔧 Guardify               ")
        print("  WiFi Device Monitor & Rogue AP Detector ")
        print("="*45)
        print("1. Monitor Devices on Network")
        print("2. Scan for Rogue Access Points")
        print("3. Show Known Device History")
        print("4. Exit")
        choice = input("\nSelect an option (1-4): ")
        
        #Handling user choice
        if choice == "1":
            device_monitor()
        elif choice == "2":
            detect_rogue_access_points()
        elif choice == "3":
            history = load_device_history()
            for mac, info in history.items():                                      #How device history will be displayed
                print(f"{mac} | First Seen: {info['first_seen']} | Vendor: {info['vendor']} | Type: {info['type']}")
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

#Start program
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Program interrupted.")                                        #Handling exceptions

