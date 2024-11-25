# Linux System Information Gathering Script

A Python script designed to collect detailed information about a Linux system, including hardware details, network status, and security configurations. It also provides the ability to monitor real-time network traffic using `tcpdump`.

---

## Features

- **Basic System Information**: Displays general information about the system.
- **Event Logs**: Extracts and displays event logs.
- **User Accounts**: Lists all user accounts on the system.
- **USB History**: Displays a history of connected USB devices.
- **Scheduled Tasks**: Lists scheduled tasks.
- **GPU Information**: 
  - Basic GPU details.
  - Detailed GPU information with an option to force scanning in virtualized environments.
- **Drivers Information**: Lists installed drivers.
- **Antivirus Status**: Displays the status of antivirus software.
- **Firewall Status**: Shows the status of the firewall.
- **Services Status**: Displays the status of essential system services.
- **LUKS Encryption Status**: Shows LUKS encryption information.
- **System Stats**: Displays memory, CPU, and disk statistics.
- **Network Status**: Provides network configuration and status.
- **Traffic Monitoring**: Monitors real-time network traffic using `tcpdump` with the ability to specify a network interface.

---

## Usage

### **Basic Usage**
Run all functions:
sudo python3 script.py

# Examples
Monitor traffic on the default interface (eth0):
sudo python3 script.py --monitor-traffic

Monitor traffic on a specific interface (e.g., wlan0):
sudo python3 script.py --monitor-traffic -i wlan0

Display detailed GPU information with forced scanning:
sudo python3 script.py --detailed-gpu-info --force-gpu-check

Run selected options only:
sudo python3 script.py --basic-info --usb-history --network-status
