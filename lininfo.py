import platform
import os
import glob
import psutil
import pyudev
import subprocess
import distro  
import argparse
import logging


# Basic system information
def basic_info():
    print(f"Computer Name: {platform.node()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor()}")
    print(f"Architecture: {platform.architecture()[0]}")

    # Fetch CPU information using lscpu0
    cpu_info = subprocess.check_output("lscpu", shell=True, text=True)
    print("\nCPU Information:")
    print(cpu_info)

    # Fetch memory information
    mem_info = psutil.virtual_memory()
    print(f"\nTotal Physical Memory: {mem_info.total / (1024**3):.2f} GB")
    print(f"Available Memory: {mem_info.available / (1024**3):.2f} GB")

    # Fetch disk information using lsblk
    disk_info = subprocess.check_output("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT", shell=True, text=True)
    print("\nDisk Information:")
    print(disk_info)

    # Fetch partitions and mount points using df
    partition_info = subprocess.check_output("df -h", shell=True, text=True)
    print("\nPartition Information:")
    print(partition_info)

    # Fetch OS details
    print("\nOperating System Information:")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Version: {platform.version()}")
    print(f"Linux Distribution: {distro.name()} {distro.version()}")

    # Fetch BIOS information
    try:
        bios_info = subprocess.check_output("dmidecode -t bios", shell=True, text=True)
        print("\nBIOS Information:")
        print(bios_info)
    except FileNotFoundError:
        print("dmidecode not found. Install it with 'sudo apt install dmidecode'.")

    # Fetch motherboard information
    try:
        board_info = subprocess.check_output("dmidecode -t baseboard", shell=True, text=True)
        print("\nMotherboard Information:")
        print(board_info)
    except FileNotFoundError:
        print("dmidecode not found. Install it with 'sudo apt install dmidecode'.")

    # Fetch battery information (if applicable)
    try:
        battery_info = subprocess.check_output("upower -i $(upower -e | grep BAT)", shell=True, text=True)
        print("\nBattery Information:")
        print(battery_info)
    except subprocess.CalledProcessError:
        print("Battery information not available or upower is not installed.")

    # Get system uptime
    uptime = subprocess.check_output("uptime -p", shell=True, text=True)
    print(f"\nSystem Uptime: {uptime.strip()}")



def is_admin():
  
    return os.geteuid() == 0

def is_virtualized():

    try:
        with open('/proc/cpuinfo', 'r') as cpuinfo:
            if any(term in cpuinfo.read().lower() for term in ["hypervisor", "kvm", "vmware", "xen"]):
                return True, get_virtualization_details()
        return False, None
    except FileNotFoundError:
        return False, None
        
        
def get_virtualization_details():

    details = {}
    try:
        result = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True)
        details["Hypervisor"] = result.stdout.strip() if result.returncode == 0 else "Unknown"
    except FileNotFoundError:
        details["Hypervisor"] = "systemd-detect-virt not found"

    # Get vCPU and memory info
    try:
        details["vCPUs"] = os.cpu_count()
        with open('/proc/meminfo', 'r') as meminfo:
            for line in meminfo:
                if line.startswith("MemTotal:"):
                    details["Memory"] = line.split(":")[1].strip()
    except Exception as e:
        details["Error"] = f"Failed to get virtualization details: {e}"
    
    return details
    
def user_accounts():
    print("\nUser Accounts Information:")

    try:
        # Run 'getent passwd' to retrieve user account information
        result = subprocess.run(['getent', 'passwd'], stdout=subprocess.PIPE, text=True)
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                parts = line.split(':')
                username = parts[0]
                home_directory = parts[5]
                shell = parts[6]
                print(f"Username: {username}, Home Directory: {home_directory}, Default Shell: {shell}")
        else:
            print("No user accounts found.")
    except Exception as e:
        print(f"Error retrieving user accounts: {e}")

def event_logs(filter_keyword=None):
  
    if not is_admin():
        print("ERROR: This script needs to be run as root to access certain logs.")
        exit(1)
    
    print("\nFetching categorized event logs:")
    
    # Define categories and their typical Linux log file mappings
    log_categories = {
        "Security Logs": ["/var/log/auth.log", "/var/log/secure"],
        "System Logs": ["/var/log/syslog", "/var/log/messages"],
        "Application Logs": glob.glob("/var/log/*.log"),  # General application logs
        "Application-specific Logs": ["/var/log/apache2/error.log", "/var/log/nginx/error.log", "/var/log/docker.log"],
        "Defender Logs": ["/var/log/fail2ban.log", "/var/log/rkhunter.log", "/var/log/clamav/clamav.log"],  # Example security-related logs
        "Firewall Logs": [
            "/var/log/ufw.log",  
            "/var/log/kern.log",  # Kernel logs (for iptables)
            "/var/log/messages",  # General messages (for iptables)
            "/var/log/audit/audit.log"  # SELinux logs
        ]
    }
    
    # If no keyword provided, default to displaying last 10 lines of logs
    if filter_keyword:
        print(f"Filtering logs for keyword: '{filter_keyword}'")
    else:
        print("No filter keyword provided. Displaying the last 10 lines of each log file.")
    
    # Iterate through each category
    for category, log_files in log_categories.items():
        print(f"\n{category}:\n{'-' * len(category)}")
        
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    print(f"\nContents of {log_file}:")
                    # Use grep to filter by keyword or display the last 10 lines if no keyword is provided
                    command = ["grep", filter_keyword, log_file] if filter_keyword else ["tail", "-n", "10", log_file]
                    output = subprocess.run(
                        command,
                        text=True,
                        capture_output=True
                    )
                    if output.stdout:
                        print(output.stdout)
                    
                else:
                    print(f"{log_file} not found.")
            except Exception as e:
                print(f"Error accessing {log_file}: {e}")



def usb_history():
    print("\nUSB Device History:")
    context = pyudev.Context()
    for device in context.list_devices(subsystem="usb"):
        print(f"Device: {device.get('ID_MODEL')} | Vendor: {device.get('ID_VENDOR')} | Serial: {device.get('ID_SERIAL_SHORT')}")



def basic_gpu_info():
    # Static GPU information using lshw
    print("\n Basic GPU Information (lshw):")
    try:
        result = subprocess.run(["lshw", "-C", "display"], capture_output=True, text=True)
        print(result.stdout if result.stdout else "No GPU found using lshw.")
    except FileNotFoundError:
        print("lshw not found. Install it using 'sudo apt install lshw'.")

    # GPU driver and OpenGL information using glxinfo
    print("\nOpenGL and GPU Driver Information (glxinfo):")
    try:
        result = subprocess.run(["glxinfo"], capture_output=True, text=True)
        if result.stdout:
            lines = result.stdout.splitlines()
            for line in lines:
                if any(key in line.lower() for key in ["opengl", "renderer", "version"]):
                    print(line.strip())
        else:
            print("No information found using glxinfo.")
    except FileNotFoundError:
        print("glxinfo not found. Install it using 'sudo apt install mesa-utils'.")

    # NVIDIA GPU real-time information using nvidia-smi (if applicable)
    print("\nNVIDIA GPU Real-Time Information (nvidia-smi):")
    try:
        result = subprocess.run(["nvidia-smi"], capture_output=True, text=True)
        print(result.stdout if result.stdout else "No NVIDIA GPU found using nvidia-smi.")
    except FileNotFoundError:
        print("nvidia-smi not found. Ensure NVIDIA drivers and tools are installed.")

    # Additional hardware details from /proc/driver/nvidia (if applicable)
    print("\nAdditional NVIDIA Hardware Details (/proc/driver/nvidia):")
    try:
        with open("/proc/driver/nvidia/version", "r") as file:
            print(file.read())
    except FileNotFoundError:
        print("No additional NVIDIA hardware details found.")

def detailed_gpu_info(force_check=False):
  
    virtualized, details = is_virtualized()

    if virtualized and not force_check:
        print("\nSystem is running in a virtualized environment. Skipping Detailed GPU info.")
        print("\nVirtualization Details:")
        for key, value in details.items():
            print(f"{key}: {value}")
        logging.info("GPU check skipped due to virtualization. Details: %s", details)
        return

    if virtualized and force_check:
        print("\nSystem is virtualized, but forcing GPU info check as per user request.")
        logging.info("GPU check forced despite virtualization.")

    # GPU scanning
    print("\nDetailed GPU Information:")
    try:
        for device in os.listdir("/sys/class/drm"):
            if "card" in device:
                try:
                    hwmon_path = f"/sys/class/drm/{device}/device/hwmon"
                    if not os.path.exists(hwmon_path):
                        print(f"Device: {device} - No hwmon path available (virtualized?).")
                        continue
                    hwmon_dir = os.listdir(hwmon_path)[0]
                    temp_path = f"{hwmon_path}/{hwmon_dir}/temp1_input"
                    with open(temp_path, "r") as temp_file:
                        temp = int(temp_file.read().strip()) / 1000
                    print(f"Device: {device} - Temperature: {temp}°C")
                except Exception as e:
                    print(f"Device: {device} - An error occurred: {e}")
                    logging.error("Error fetching GPU info for %s: %s", device, e)
    except FileNotFoundError:
        print("No GPU information found.")
        logging.error("GPU information retrieval failed. /sys/class/drm not found.")
	

def scheduled_tasks():
    print("\nScheduled Tasks (Cron Jobs):")
    
    try:
        # Retrieve system-wide cron jobs
        print("\nSystem-wide Cron Jobs:")
        with open("/etc/crontab", "r") as system_cron:
            print(system_cron.read())
        
        # Retrieve user-specific cron jobs
        user = os.getlogin()
        print(f"\nCron Jobs for User: {user}")
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("No user-specific cron jobs found or access denied.")

    except FileNotFoundError as e:
        print(f"Error accessing cron files: {e}")
    except PermissionError:
        print("Permission denied. Try running the script as root or the correct user.")




def drivers_info():
    print("\nInstalled Drivers (lsmod):")

    try:
        # Run lsmod to get the list of loaded kernel modules
        result = subprocess.run(["lsmod"], capture_output=True, text=True)

        if result.stdout:
            # Process each line after the header line
            modules = [line.split()[0] for line in result.stdout.strip().split("\n")[1:]]

            for module in modules:
                description = "Not available"
                try:
                    # Run modinfo for each module to get its description
                    modinfo_result = subprocess.run(
                        ["modinfo", module], capture_output=True, text=True
                    )
                    if modinfo_result.stdout:
                        # Extract the description line
                        for line in modinfo_result.stdout.splitlines():
                            if line.startswith("description:"):
                                description = line.split(":", 1)[1].strip()
                                break
                except FileNotFoundError:
                    description = "modinfo command not found"

                # Print driver and its description in the same line
                print(f"{module:<20} | Description: {description}")
        else:
            print("No drivers found.")
    except FileNotFoundError:
        print("lsmod command not found. Are you on a Linux-based OS?")


def antivirus_info():
    print("\nAntivirus Information:")

    # List of known antivirus daemons and commands
    av_commands = {
        "ClamAV": {
            "check_daemon": "clamd",
            "check_command": "clamscan --version"
        },
        "Sophos": {
            "check_daemon": "sav-protect",
            "check_command": "/opt/sophos-av/bin/savdstatus"
        },
        "ESET": {
            "check_daemon": "esets",
            "check_command": "/opt/eset/esets/sbin/esets_daemon --version"
        },
        "Kaspersky": {
            "check_daemon": "klnagent",
            "check_command": "/opt/kaspersky/klnagent/bin/klnagentapp --version"
        },
        "Bitdefender": {
            "check_daemon": "bdscan",
            "check_command": "/opt/BitDefender/bin/bdscan --version"
        }
    }

    detected_av = []

    for av_name, commands in av_commands.items():
        try:
            # Check if the antivirus daemon is running
            daemon_check = subprocess.run(
                ["pgrep", "-x", commands["check_daemon"]],
                capture_output=True, text=True
            )
            if daemon_check.returncode == 0:
                version_check = subprocess.run(
                    commands["check_command"].split(),
                    capture_output=True, text=True
                )
                version_info = version_check.stdout.strip() if version_check.returncode == 0 else "Version info unavailable"
                detected_av.append((av_name, "Running", version_info))
            else:
                detected_av.append((av_name, "Not Running", "N/A"))
        except FileNotFoundError:
            # Skip adding "Not Installed" antivirus to the list
            continue

    # Print only relevant antivirus information
    if detected_av:
        for av_name, status, version in detected_av:
            print(f"Antivirus: {av_name}, Status: {status}, Version: {version}")
    else:
        print("No antivirus software detected.")


# Get Firewall status with more details
def firewall_status():
    print("\nFirewall Status:")
    ufw_result = None
    # Check ufw status
    try:
        print("\nUFW Status:")
        ufw_result = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True)
        if ufw_result.returncode == 0:
            print(ufw_result.stdout.strip())
        else:
            print("UFW is not active or not installed.")
    except FileNotFoundError:
        print("UFW not found. Skipping UFW status check.")

    # Retrieve detailed iptables rules
    try:
        print("\niptables Rules (Filter Table):")
        iptables_result = subprocess.run(["iptables", "-L", "-v", "-n"], capture_output=True, text=True)
        if iptables_result.returncode == 0:
            print(iptables_result.stdout.strip())
        else:
            print("No iptables rules found or iptables is not configured.")
    except FileNotFoundError:
        print("iptables not found. Ensure it is installed if you want detailed rule inspection.")

    # Additional: Check active network zones (firewalld, if available)
    try:
        print("\nfirewalld Zones (if applicable):")
        firewalld_result = subprocess.run(["firewall-cmd", "--get-active-zones"], capture_output=True, text=True)
        if firewalld_result.returncode == 0:
            print(firewalld_result.stdout.strip())
        else:
            print("firewalld not active or not installed.")
    except FileNotFoundError:
        print("firewalld not found. Skipping firewalld status check.")


def Services_Status():
    print("\nList all Services Status :")
    try:
        result = subprocess.run(["systemctl", "list-unit-files", "--type=service"], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout.strip())
            
        else:
            print("Failed to retrieve startup services.")
    except Exception as e:
        print("Could not retrieve startup applications. Exception:", e)



def luks_status(drive=None):
    if drive:
        print(f"\nLUKS Encryption Status for Drive {drive}:")
        try:
            result = subprocess.run(['cryptsetup', 'status', drive], capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"Drive {drive} is not encrypted with LUKS or cannot retrieve status.")
        except FileNotFoundError:
            print("cryptsetup is not installed. Please install it to check LUKS status.")
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("\nLUKS Encryption Status for All Drives:")
        try:
            result = subprocess.run(['lsblk', '-f'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"An error occurred while checking drives: {e}")


def system_stats():
    print("\nSystem Statistics:")
    # CPU Information
    print(f"CPU Cores: {psutil.cpu_count(logical=True)}")
    print(f"CPU Usage: {psutil.cpu_percent(interval=1)}%")

    # Memory Information
    mem = psutil.virtual_memory()
    print(f"Total Memory: {mem.total / (1024 ** 3):.2f} GB")
    print(f"Available Memory: {mem.available / (1024 ** 3):.2f} GB")
    print(f"Used Memory: {mem.used / (1024 ** 3):.2f} GB")

    # Disk Information
    print("Disk Partitions:")
    for partition in psutil.disk_partitions():
        print(f"  Device: {partition.device}")
        print(f"    Mountpoint: {partition.mountpoint}")
        print(f"    Filesystem: {partition.fstype}")
        usage = psutil.disk_usage(partition.mountpoint)
        print(f"    Total Size: {usage.total / (1024 ** 3):.2f} GB")
        print(f"    Used: {usage.used / (1024 ** 3):.2f} GB")
        print(f"    Free: {usage.free / (1024 ** 3):.2f} GB")
        print(f"    Usage Percentage: {usage.percent}%")



def network_status():
    try:
        print("\n==== Network Interfaces ====")
        # Display network interfaces and their statuses
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
        print(result.stdout)
        
        print("\n==== Routing Table ====")
        # Show the routing table
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        print(result.stdout)
        
        print("\n==== DNS Configuration ====")
        # Show DNS configuration
        try:
            with open('/etc/resolv.conf', 'r') as resolv_conf:
                print(resolv_conf.read())
        except FileNotFoundError:
            print("DNS configuration file not found.")
            
        print("\n==== Hostname Resolution ====")
        # Show DNS configuration
        try:
            with open('/etc/hosts', 'r') as hosts_conf:
                print(hosts_conf.read())
        except FileNotFoundError:
            print("Hostname file not found.")     
        
        print("\n==== Active Connections ====")
        # Display active network connections
        result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
        print(result.stdout)
        
        print("\n==== Wireless Network Information ====")
        # Show wireless network details if the `iwconfig` command is available
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        if "no wireless extensions" not in result.stdout.lower():
            print(result.stdout)
        else:
            print("No wireless network information available.")
        
        print("\n==== Network Statistics ====")
        # Show network statistics
        result = subprocess.run(['netstat', '-i'], capture_output=True, text=True)
        print(result.stdout)

    except Exception as e:
        print("An error occurred while gathering network information:", e)


def monitor_traffic(interface="eth0"):
    try:
        print(f"Starting tcpdump on interface '{interface}'...\nPress Ctrl+C to stop capturing packets.")
        subprocess.run(["sudo", "tcpdump", "-i", interface, "-nn"])
    except KeyboardInterrupt:
        print("\ntcpdump monitoring stopped by user.")
    except Exception as e:
        print(f"An error occurred while running tcpdump: {e}")


def parse_arguments():
    parser = argparse.ArgumentParser(description="System Information Gathering Script")
    parser.add_argument("--basic-info", action="store_true", help="Display basic system information.")
    parser.add_argument("--event-logs", action="store_true", help="Extract event log information.")
    parser.add_argument("--user-accounts", action="store_true", help="Display user account information.")
    parser.add_argument("--usb-history", action="store_true", help="Display USB device history.")
    parser.add_argument("--scheduled-tasks", action="store_true", help="Display scheduled tasks.")
    parser.add_argument("--basic-gpu-info", action="store_true", help="Display basic GPU information.")
    parser.add_argument("--detailed-gpu-info", action="store_true", help="Display detailed GPU information.")
    parser.add_argument("--force-gpu-check", action="store_true", help="Force GPU scanning even in virtualized environments.")
    parser.add_argument("--drivers-info", action="store_true", help="Display installed drivers.")
    parser.add_argument("--antivirus-info", action="store_true", help="Display antivirus information.")
    parser.add_argument("--firewall-status", action="store_true", help="Display firewall status.")
    parser.add_argument("--services-status", action="store_true", help="Display the status of all services.")
    parser.add_argument("--luks-status", action="store_true", help="Display LUKS encryption status.")
    parser.add_argument("--system-stats", action="store_true", help="Display system stats (memory, CPU, disk).")
    parser.add_argument("--network-status", action="store_true", help="Display network status.")
    parser.add_argument("--monitor-traffic", action="store_true", help="Enable real-time network traffic monitoring using tcpdump.")
    parser.add_argument("--filter", type=str, help="Keyword to filter log events.")
    parser.add_argument("-i","--interface", help="Network interface to monitor (default: eth0).")
    return parser.parse_args()

# Main Execution
def main():
    args = parse_arguments()

    if any(vars(args).values()):  
        if args.basic_info: basic_info()
        if args.event_logs: event_logs(filter_keyword=args.filter)
        if args.user_accounts: user_accounts()
        if args.usb_history: usb_history()
        if args.scheduled_tasks: scheduled_tasks()
        if args.basic_gpu_info: basic_gpu_info()
        if args.detailed_gpu_info: detailed_gpu_info(force_check=args.force_gpu_check)
        if args.drivers_info: drivers_info()
        if args.antivirus_info: antivirus_info()
        if args.firewall_status: firewall_status()
        if args.services_status: Services_Status()
        if args.luks_status: luks_status()
        if args.system_stats: system_stats()
        if args.network_status: network_status()
        if args.monitor_traffic: monitor_traffic(interface=args.interface if args.interface else "eth0")
    else: 
        print("\n--- Running All Functions ---")
        basic_info()
        event_logs()
        user_accounts()
        usb_history()
        scheduled_tasks()
        basic_gpu_info()
        detailed_gpu_info()
        drivers_info()
        antivirus_info()
        firewall_status()
        Services_Status()
        luks_status()
        system_stats()
        network_status()

if __name__ == "__main__":
    main()
    
