# Python MITM Tool

## Description

This project is a Python-based ARP spoofing tool designed for educational and cybersecurity research purposes. It enables a user to scan a local network, select a target device, execute an ARP poisoning attack, sniff DNS traffic, and restore the network upon exit.

## Features

- Local network IP and gateway discovery
- ARP-based device scanner
- Target selection from scanned devices
- ARP spoofing to intercept victim traffic
- DNS request sniffer
- Automatic network restoration on exit
- Clean and simple terminal interface

## Requirements

- Python 3.x
- Operating System: Windows or Linux (minor adjustments may be required)
- Admin/root privileges

### Python Libraries

Install the required libraries with:
pip install scapy colorama
Usage
Run the script with administrator privileges:

bash
Copy
Edit
python arp_mitm.py
Workflow
Detects local IP and gateway

Scans the subnet for active devices

Allows the user to select a target

Performs ARP poisoning and DNS sniffing

Restores network settings on Ctrl+C

Legal Disclaimer
This tool is intended for educational use only.
Do not use it on networks you do not own or have explicit permission to test.

Author
Ahron Ostrovsky

Instagram

YouTube

License
This project is licensed under the MIT License. See the LICENSE file for details.
