# QrNX's MITM All-in-One Tool

This is a Man-in-the-Middle (MITM) attack tool developed by QrNX. This tool allows you to perform various network security tests such as network scanning, port scanning, ARP poisoning, and packet capturing.

## Features

- Network Scanning: Used to scan devices on the network within a given IP range.
- Port Scanning: Used to scan open ports on a specific IP address.
- ARP Poisoning: Performs ARP poisoning attacks to target network traffic.
- Packet Capture: Listens to network traffic and monitors HTTP requests.

## Setup

1. Install the necessary Python libraries:
   ```bash
   pip3 install scapy pyfiglet
   ```
2. Run it in the command line in the project directory:
   ```bash
   python3 mitm_all_in_one.py
   ```
## Usage
  - Network Scanner: Select 1 and enter the IP range (e.g., 10.10.9.4/24).
  - Port Scanner: Select 2 and enter the target IP (e.g., 10.10.9.4).
  - ARP Poison: Select 3 and enter the first target IP and then the router IP (e.g., enter 10.10.9.4, then press enter, and enter 10.10.9.1).  
  - Packet Sniffer: Select 4. You need to start ARP poisoning first in another terminal. You will see RAW HTTP packets.

## Notes
It is not suitable for any illegal use and is not recommended; it is intended for testing and learning purposes only. Mustafa Mert Çolak, also known as QrNX, is not responsible for any misuse.
