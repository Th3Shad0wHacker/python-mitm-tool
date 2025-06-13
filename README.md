   ___    __                        ____       __                       __        
   /   |  / /_  _________  ____     / __ \_____/ /__________ _   _______/ /____  __
  / /| | / __ \/ ___/ __ \/ __ \   / / / / ___/ __/ ___/ __ \ | / / ___/ //_/ / / /
 / ___ |/ / / / /  / /_/ / / / /  / /_/ (__  ) /_/ /  / /_/ / |/ (__  ) ,< / /_/ / 
/_/  |_/_/ /_/_/   \____/_/ /_/   \____/____/\__/_/   \____/|___/____/_/|_|\__, /  
                                                                          /____/

Author: Ahron Ostrovsky
Instagram: https://instagram.com/ahron_ostrovsky
YouTube:   https://www.youtube.com/Ahron_ostrovsky

--------------------------------------------------------------------------------
NAME
    Network ARP Spoof Detector & Attacker
    
DESCRIPTION
    This tool is a Python-based ARP Spoofing simulator that allows a user to:
    - Scan a local network for active devices
    - Select a target device
    - Perform ARP Poisoning to intercept traffic
    - Sniff and display DNS requests from the victim
    - Restore the network state upon exit

FEATURES
    ✔ Displays local IP, gateway, and network range
    ✔ Beautiful colored terminal output using Colorama
    ✔ Built-in ARP scanner using Scapy
    ✔ DNS request sniffer from target
    ✔ Ctrl+C support for safe network restoration
    ✔ Cool ASCII art banner with credits

REQUIREMENTS
    - Python 3.x
    - Libraries: scapy, colorama
    - Admin/root privileges
    - OS: Windows/Linux (with slight adjustments)

INSTALLATION
    pip install scapy colorama

USAGE
    1. Run the script as administrator:
       > python3 arpon.py
       
    2. The script will:
       - Detect your local IP and gateway
       - Scan for active devices in your subnet
       - Let you choose a device to attack
       - Start poisoning and sniffing DNS
       
    3. Press Ctrl+C at any time to stop and restore network state

DISCLAIMER
    ⚠️ This tool is for educational purposes only.
    ⚠️ Do not use on networks you do not own or have permission to test.

LICENSE
    © 2025 Ahron Ostrovsky. All rights reserved.
    This code is part of a cybersecurity project for the Israeli high school final exam (Bagrut).
