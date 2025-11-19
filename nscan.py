import sys
import socket
import threading
import concurrent.futures
import argparse
import json
import time
import logging
from datetime import datetime
from colorama import Fore, Style, init

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Ether, ARP, srp, send, AsyncSniffer, conf

# Initialize colorama
init(autoreset=True)

# --- Globals for Stealth Scan ---
open_ports_stealth = {} # {port: {'ttl': 64, 'os': '..'}}

# --- HELPER FUNCTIONS ---

def estimate_os(ttl):
    """Guesses OS based on TTL."""
    if ttl <= 64: return "Linux/Unix"
    elif ttl <= 128: return "Windows"
    elif ttl <= 255: return "Cisco/Network Device"
    return "Unknown"

def grab_banner(ip, port):
    """Connects to a port to read the banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        # Send a generic trigger
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner if banner else "No Banner"
    except:
        return "N/A"

# --- MODE 1: CONNECT SCAN (Standard) ---
def scan_port_connect(ip, port, results_list):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            # If open, grab banner immediately
            banner = grab_banner(ip, port)
            print(f"{Fore.GREEN}[+] Port {port:<5} is OPEN  {Fore.RESET}({banner[:40]})")
            results_list.append({'port': port, 'status': 'Open', 'banner': banner, 'type': 'Connect'})
    except:
        pass

# --- MODE 2: STEALTH SCAN (SYN) ---
def process_packet(packet):
    """Callback for the background sniffer."""
    if packet.haslayer(TCP) and packet[TCP].flags == 0x12: # SYN-ACK
        port = packet[TCP].sport
        ttl = packet[IP].ttl
        
        if port not in open_ports_stealth:
            os_guess = estimate_os(ttl)
            open_ports_stealth[port] = {'ttl': ttl, 'os': os_guess}
            print(f"{Fore.GREEN}[+] Port {port:<5} is OPEN  {Fore.RESET}(TTL: {ttl} -> {os_guess})")

def send_syn_packet(target, port):
    try:
        pkt = IP(dst=target)/TCP(dport=port, sport=54321, flags="S")
        send(pkt, verbose=0)
    except:
        pass

# --- MODE 3: NETWORK DISCOVERY (ARP) ---
def scan_network(subnet):
    print(f"[*] Sending ARP Broadcasts to {subnet}...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
    result = srp(packet, timeout=2, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# --- MAIN RUNNER ---
def main():
    parser = argparse.ArgumentParser(description="NScan - Advanced Python Network Scanner")
    
    # Arguments
    parser.add_argument("target", help="Target IP, Domain, or Subnet (for discovery)")
    parser.add_argument("-p", "--ports", help="Port Range (e.g. 1-1024)", default="1-1024")
    parser.add_argument("-t", "--threads", help="Number of threads", type=int, default=100)
    parser.add_argument("--stealth", help="Enable SYN Stealth Scan (Root/Admin only)", action="store_true")
    parser.add_argument("--discover", help="Enable Network Discovery Mode (ARP)", action="store_true")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    # --- HEADER ---
    print(f"{Fore.CYAN}{Style.BRIGHT}NSCAN v1.0 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    results_data = {}

    # --- DISCOVERY MODE ---
    if args.discover:
        try:
            devices = scan_network(args.target)
            print(f"\n{Fore.GREEN}[+] Found {len(devices)} devices:\n")
            print(f"{'IP ADDRESS':<20} {'MAC ADDRESS':<20}")
            print("-" * 45)
            for d in devices:
                print(f"{d['ip']:<20} {d['mac']:<20}")
            
            results_data['discovery'] = devices
        except PermissionError:
            print(f"{Fore.RED}[!] Error: Discovery requires Administrator/Root privileges.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")

    # --- PORT SCAN MODE ---
    else:
        # 1. Resolve Target
        try:
            target_ip = socket.gethostbyname(args.target)
            print(f"Target: {args.target} ({target_ip})")
        except:
            print(f"{Fore.RED}[!] Could not resolve target.")
            sys.exit(1)

        # 2. Parse Ports
        try:
            start_p, end_p = map(int, args.ports.split('-'))
            ports = range(start_p, end_p + 1)
            print(f"Ports:  {start_p}-{end_p}")
        except:
            print(f"{Fore.RED}[!] Invalid port format. Use start-end (e.g. 1-1024)")
            sys.exit(1)

        # 3. Execute Scan
        if args.stealth:
            # STEALTH MODE
            print(f"Mode:   {Fore.YELLOW}STEALTH SYN SCAN{Fore.RESET} (Admin Required)")
            print("-" * 60)
            
            conf.verb = 0
            sniffer = AsyncSniffer(filter=f"src host {target_ip} and tcp", prn=process_packet, store=False)
            sniffer.start()
            time.sleep(1)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(send_syn_packet, target_ip, p) for p in ports}
                concurrent.futures.wait(futures)
            
            time.sleep(2)
            sniffer.stop()
            
            # Add banner grabbing post-scan for open ports
            print(f"\n[*] Grabbing banners for {len(open_ports_stealth)} open ports...")
            final_results = []
            for port, info in open_ports_stealth.items():
                banner = grab_banner(target_ip, port)
                final_results.append({
                    'port': port, 'status': 'Open', 'protocol': 'TCP', 
                    'ttl': info['ttl'], 'os_guess': info['os'], 'banner': banner
                })
            results_data['scan'] = final_results

        else:
            # CONNECT MODE
            print(f"Mode:   {Fore.BLUE}STANDARD CONNECT SCAN{Fore.RESET}")
            print("-" * 60)
            scan_results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = {executor.submit(scan_port_connect, target_ip, p, scan_results) for p in ports}
                concurrent.futures.wait(futures)
            results_data['scan'] = scan_results

    # --- JSON EXPORT ---
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results_data, f, indent=4)
            print(f"\n{Fore.CYAN}[*] Results saved to {args.output}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save output: {e}")

    print("-" * 60)
    print("Scan Complete.")

if __name__ == "__main__":
    main()