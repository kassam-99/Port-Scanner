import datetime
import random
import socket
import ssl
import threading
import time
from queue import Queue
from typing import Dict, List, Optional, Tuple
import ipaddress
import requests
import scapy.all as scapy
from bs4 import BeautifulSoup
from ReportGenerator import Report_Generator



PORTScannerLogo = """
\033[35m
 /$$$$$$$                       /$$            /$$$$$$                                                             
| $$__  $$                     | $$           /$$__  $$                                                            
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$        | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/        |  $$$$$$  /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
| $$____/| $$  \ $$| $$  \__/  | $$           \____  $$| $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
| $$     | $$  | $$| $$        | $$ /$$       /$$  \ $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
| $$     |  $$$$$$/| $$        |  $$$$/      |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
|__/      \______/ |__/         \___/         \______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
\033[0m

Author: Kassam Dakhlalah               
Github: kassam-99                      
Version: 3.0, 8th June 2024               
This project is open source
For any information on editing         
the project, please refer to PortScanner.txt                                   
                                                       
"""

class NetworkConfig:
    """Base configuration for network scanning."""
    def __init__(self):
        self.GEOIP = "http://ip-api.com/json/"
        

        self.transport_mapping = {
            "tcp": socket.SOCK_STREAM,
            "udp": socket.SOCK_DGRAM
        }
        
        self.TCP_Ports = {
            "http": 80,                     # Hypertext Transfer Protocol (HTTP)
            "https": 443,                   # HTTP Secure (HTTPS)
            "ftp": 21,                      # File Transfer Protocol (FTP)
            "ssh": 22,                      # Secure Shell (SSH)
            "telnet": 23,                   # Telnet protocol
            "smtp": 25,                     # Simple Mail Transfer Protocol (SMTP)
            "dns": 53,                      # Domain Name System (DNS)
            "dhcp": 67,                     # Dynamic Host Configuration Protocol (DHCP)
            "tftp": 69,                     # Trivial File Transfer Protocol (TFTP)
            "snmp": 161,                    # Simple Network Management Protocol (SNMP)
            "ldap": 389,                    # Lightweight Directory Access Protocol (LDAP)
            "imap": 143,                    # Internet Message Access Protocol (IMAP)
            "pop3": 110,                    # Post Office Protocol version 3 (POP3)
            "mysql": 3306,                  # MySQL Database Server
            "postgresql": 5432,             # PostgreSQL Database Server
            "rdp": 3389,                    # Remote Desktop Protocol (RDP)
            "vnc": 5900,                    # Virtual Network Computing (VNC)
            "http-alt": 8080,               # Alternative HTTP port
            "ftp-data": 20,                 # FTP data transfer
            "sftp": 115,                    # Secure FTP
            "ldapssl": 636,                 # LDAP over SSL
            "smtps": 465,                   # SMTP over SSL
            "submission": 587,              # SMTP submission (mail submission)
            "whois": 43,                    # WHOIS protocol
            "mssql": 1433,                  # Microsoft SQL Server
            "mysqls": 3307,                 # MySQL over SSL
            "mysqlx": 33060,                # MySQL X Protocol
            "nntp": 119,                    # Network News Transfer Protocol (NNTP)
            "irc": 194,                     # Internet Relay Chat (IRC)
            "pop3s": 995,                   # POP3 over SSL
            "imaps": 993,                   # IMAP over SSL
            "git": 9418,                    # Git Version Control System
            "rdp-admin": 4115,              # Remote Desktop Services Admin
            "smb": 445,                     # Server Message Block (SMB)
            "kerberos": 88,                 # Kerberos Authentication
            "kerberos-admin": 749,          # Kerberos Administration
            "squid-http": 3128,             # Squid Proxy
            "socks": 1080,                  # SOCKS Proxy
            "alt-https": 8443,              # Alternative HTTPS port
            "murmur": 64738,                # Mumble Server
            "rtmp": 1935,                   # Real-Time Messaging Protocol (RTMP)
            "nfs": 2049,                    # Network File System (NFS)
            "teamspeak": 10011,             # TeamSpeak 3 Server Query
            "minecraft": 25565,             # Minecraft Server
            "redis": 6379,                  # Redis Server
            "mqtt": 1883,                   # MQTT Protocol
            "mosquitto": 8883,              # Mosquitto MQTT over SSL
        }
        
        self.UDP_Ports = {
            "dns": 53,                      # Domain Name System (DNS)
            "dhcp": 67,                     # Dynamic Host Configuration Protocol (DHCP)
            "tftp": 69,                     # Trivial File Transfer Protocol (TFTP)
            "snmp": 161,                    # Simple Network Management Protocol (SNMP)
            "ntp": 123,                     # Network Time Protocol (NTP)
            "syslog": 514,                  # System Logging Protocol (Syslog)
            "openvpn": 1194,                # OpenVPN Protocol
            "radius": 1812,                 # RADIUS authentication protocol
            "syslog-ssl": 6514,             # Encrypted syslog messages
            "netbios-ns": 137,              # NetBIOS Name Service
            "netbios-dgm": 138,             # NetBIOS Datagram Service
            "ms-sql-m": 1434,               # Microsoft SQL Server browser service
            "bootpc": 68,                   # BOOTP/DHCP client
            "bootps": 67,                   # BOOTP/DHCP server
            "rip": 520,                     # Routing Information Protocol (RIP)
            "isakmp": 500,                  # Internet Security Association and Key Management Protocol (ISAKMP)
            "h323": 1719,                   # H.323 (Used for VoIP)
            "sip": 5060,                    # Session Initiation Protocol (SIP)
            "rtp": 5004,                    # Real-time Transport Protocol (RTP)
            "bittorrent": 6881,             # BitTorrent Protocol
            "mdns": 5353,                   # Multicast DNS
            "coap": 5683,                   # Constrained Application Protocol (CoAP)
            "stun": 3478,                   # Session Traversal Utilities for NAT (STUN)
            "dhcpv6-client": 546,           # DHCPv6 client
            "dhcpv6-server": 547,           # DHCPv6 server
            "olsr": 698,                    # Optimized Link State Routing Protocol (OLSR)
            "wemo": 49153,                  # WeMo Home Automation
        }
        
        self.common_ports = {
            "FTP": 21,
            "SSH": 22,
            "Telnet": 23,
            "DNS": 53,
            "DHCP Server": 67,
            "DHCP Client": 68,
            "HTTP": 80,
            "NTP": 123,
            "SNMP": 161,
            "HTTPS": 443,
            "IKE": 500,
            "Syslog": 514,
            "PPTP VPN": 1723,
            "SSDP": 1900,
            "RDP": 3389,
            "STUN": 3478,
            "NAT-T": 4500,
            "UniFi Controller": 8443
        }


    def show_usage_examples(self) -> None:
        """Display usage examples for the scanner."""
        examples = """
# Usage Examples
Below are examples demonstrating all possible options for each parameter when running the scanner.

1. Basic Single Host Scan (all options):
   - Single IP with TCP connect scan, minimal ports, verbose output, and aggressive timing:
     > Enter choice: 1
     > Targets: 192.168.1.1
     > Transport: tcp
     > Ports: 80
     > Timeout: 1
     > Retries: 2
     > Verbose: true
     > Timing: T4
     > Scan type: connect

   - Single IP with UDP SYN scan, multiple ports, quiet output, and slow timing:
     > Enter choice: 1
     > Targets: 192.168.1.1
     > Transport: udp
     > Ports: 53,161
     > Timeout: 5
     > Retries: 5
     > Verbose: false
     > Timing: T0
     > Scan type: syn

   - Single IP with TCP SYN scan, port range, moderate timing:
     > Enter choice: 1
     > Targets: 192.168.1.1
     > Transport: tcp
     > Ports: 1-100
     > Timeout: 3
     > Retries: 3
     > Verbose: true
     > Timing: T3
     > Scan type: syn

   - Single IP with named ports (e.g., http, ssh), fast timing:
     > Enter choice: 1
     > Targets: 192.168.1.1
     > Transport: tcp
     > Ports: http,ssh
     > Timeout: 0.5
     > Retries: 1
     > Verbose: false
     > Timing: T5
     > Scan type: connect

2. Subnet Scan (all options):
   - Subnet with TCP connect scan, common ports, verbose, and polite timing:
     > Enter choice: 1
     > Targets: 192.168.1.0/24
     > Transport: tcp
     > Ports: 22,80,443
     > Timeout: 2
     > Retries: 3
     > Verbose: true
     > Timing: T2
     > Scan type: connect

   - Subnet with UDP SYN scan, wide port range, quiet, and sneaky timing:
     > Enter choice: 1
     > Targets: 192.168.1.0/24
     > Transport: udp
     > Ports: 1-1000
     > Timeout: 4
     > Retries: 4
     > Verbose: false
     > Timing: T1
     > Scan type: syn

   - Subnet with TCP SYN scan, specific ports, normal timing:
     > Enter choice: 1
     > Targets: 192.168.1.0/24
     > Transport: tcp
     > Ports: 80,443,3306
     > Timeout: 2
     > Retries: 2
     > Verbose: true
     > Timing: T3
     > Scan type: syn

   - Subnet with mixed ports (named and numeric), aggressive timing:
     > Enter choice: 1
     > Targets: 192.168.1.0/24
     > Transport: tcp
     > Ports: ftp,80,443
     > Timeout: 1
     > Retries: 1
     > Verbose: false
     > Timing: T4
     > Scan type: connect

3. Multiple Hosts Scan (all options):
   - Multiple IPs with TCP connect scan, small port range, verbose, and insane timing:
     > Enter choice: 1
     > Targets: 192.168.1.1,192.168.1.2,192.168.1.3
     > Transport: tcp
     > Ports: 80-85
     > Timeout: 0.5
     > Retries: 1
     > Verbose: true
     > Timing: T5
     > Scan type: connect

   - Multiple IPs with UDP SYN scan, named ports, quiet, and paranoid timing:
     > Enter choice: 1
     > Targets: 192.168.1.1,192.168.1.10
     > Transport: udp
     > Ports: dns,snmp
     > Timeout: 6
     > Retries: 5
     > Verbose: false
     > Timing: T0
     > Scan type: syn

   - Multiple IPs with TCP SYN scan, mixed ports, moderate timing:
     > Enter choice: 1
     > Targets: 192.168.1.1,192.168.1.100
     > Transport: tcp
     > Ports: 22,80-90,443
     > Timeout: 3
     > Retries: 3
     > Verbose: true
     > Timing: T3
     > Scan type: syn
"""
        print("\033[32m=== Usage Examples ===\033[0m")
        print(examples)

class PortScanner(NetworkConfig):
    """Main port scanning class with Nmap-like features."""
    def __init__(self, targets: str, transport_layer: str = "tcp", ports: str = "80", 
                 timeout: float = 2.0, retries: int = 3, verbose: bool = False, 
                 timing_template: str = "T3"):
        super().__init__()
        
        self.Reporter = Report_Generator()
        self.targets = targets
        self.transport_layer = transport_layer.lower()
        self.ports = ports
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.timing_template = timing_template
        self.discovered_ports: List[Dict] = []
        self.queue = Queue()
        self.results: List[int] = []
        self.logfile = "scan_log.txt"
        self.lock = threading.Lock()


    def log(self, message: str) -> None:
        """Log messages to file and console if verbose."""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"{timestamp} - {message}"
        if self.verbose:
            print(log_entry)
        with open(self.logfile, 'a') as f:
            f.write(f"{log_entry}\n")


    def resolve_domain(self, target: str) -> List[str]:
        """Resolve domain name to IP addresses or validate IP."""
        try:
            ipaddress.ip_address(target)
            return [target]  # It's already an IP
        except ValueError:
            try:
                # Resolve domain to IP(s)
                ips = [addr[4][0] for addr in socket.getaddrinfo(target, None, socket.AF_INET)]
                self.log(f"Resolved {target} to {ips}")
                return ips
            except socket.gaierror as e:
                self.log(f"Failed to resolve domain {target} - {e}")
                return []


    def parse_ports(self) -> List[int]:
        """Parse port input into a list of integers based on user input."""
        ports_list = []
    
        input_ports = self.ports.lower()
    
        if input_ports == "all":
            ports_list = list(self.TCP_Ports.values()) + list(self.UDP_Ports.values())
        elif input_ports == "all_tcp_only":
            ports_list = list(self.TCP_Ports.values())
        elif input_ports == "all_udp_only":
            ports_list = list(self.UDP_Ports.values())
        elif input_ports == "all_common_ports":
            ports_list = list(self.common_ports.values())
        elif input_ports == "full_range":
            ports_list = list(range(1, 65536))
        elif input_ports == "well_known":
            ports_list = list(range(0, 1024))
        elif input_ports == "registered":
            ports_list = list(range(1024, 49152))
        elif input_ports in {"dynamic", "private"}:
            ports_list = list(range(49152, 65536))
        else:
            for port in self.ports.replace(" ", "").split(","):
                if "-" in port:
                    try:
                        start, end = map(int, port.split("-"))
                        ports_list.extend(range(start, end + 1))
                    except ValueError:
                        self.log(f"Invalid port range format: {port}")
                elif port.isdigit():
                    ports_list.append(int(port))
                elif port.lower() in self.TCP_Ports:
                    ports_list.append(self.TCP_Ports[port.lower()])
                elif port.lower() in self.UDP_Ports:
                    ports_list.append(self.UDP_Ports[port.lower()])
                else:
                    self.log(f"Unknown port alias: {port}")
    
        # Filter valid port range, remove duplicates, and sort
        return sorted(set(p for p in ports_list if 1 <= p <= 65535))


    def parse_http_headers(self, banner: str) -> str:
        """Parse and format key HTTP headers from a banner string."""
        lines = banner.split("\r\n")
        formatted = []
        for line in lines:
            if line.lower().startswith("http/") or any(h in line.lower() for h in [
                "server", "content-type", "location", "date", "cache-control", "expires"
            ]):
                formatted.append(line.strip())
        return "\n".join(formatted)


    def connect_scan(self, target: str, port: int) -> bool:
        """Perform a TCP connect scan."""
        sock_type = self.transport_mapping.get(self.transport_layer)
        if not sock_type:
            self.log(f"Invalid transport layer: {self.transport_layer}")
            return False
        for _ in range(self.retries):
            try:
                with socket.socket(socket.AF_INET, sock_type) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((target, port))
                    return result == 0
            except (socket.timeout, socket.error) as e:
                self.log(f"Connect scan error for {target}:{port} - {e}")
        return False


    def syn_scan(self, target: str, port: int) -> str:
        """Perform a TCP SYN scan (requires root privileges)."""
        try:
            src_port = random.randint(1024, 65535)
            pkt = scapy.IP(dst=target) / scapy.TCP(sport=src_port, dport=port, flags="S")
            response = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if response is None:
                return "filtered"
            elif response.haslayer(scapy.TCP):
                if response[scapy.TCP].flags == "SA":  # SYN-ACK
                    scapy.send(scapy.IP(dst=target) / scapy.TCP(sport=src_port, dport=port, flags="R"), verbose=False)
                    return "open"
                elif response[scapy.TCP].flags == "RA":  # RST-ACK
                    return "closed"
            return "filtered"
        except Exception as e:
            self.log(f"SYN scan error for {target}:{port} - {e}")
            return "error"
    
    
    def ack_scan(self, target: str, port: int) -> str:
        """Perform an ACK scan to detect filtered/unfiltered state."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="A")
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if resp is None:
                return "filtered"
            elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == "R":
                return "unfiltered"
            return "unknown"
        except Exception as e:
            self.log(f"ACK scan error for {target}:{port} - {e}")
            return "error"
    
    
    def window_scan(self, target: str, port: int) -> str:
        """Perform a Window scan based on TCP window size."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="A")
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if resp and resp.haslayer(scapy.TCP):
                window_size = resp[scapy.TCP].window
                if window_size > 0:
                    return "open"
                else:
                    return "closed"
            return "filtered"
        except Exception as e:
            self.log(f"Window scan error for {target}:{port} - {e}")
            return "error"
    
    
    def fin_scan(self, target: str, port: int) -> str:
        """Perform a FIN scan."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="F")
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if resp is None:
                return "open"
            elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == "R":
                return "closed"
            return "filtered"
        except Exception as e:
            self.log(f"FIN scan error for {target}:{port} - {e}")
            return "error"
    
    
    def xmas_scan(self, target: str, port: int) -> str:
        """Perform a Xmas scan (FIN+URG+PSH)."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="FUP")
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if resp is None:
                return "open"
            elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == "R":
                return "closed"
            return "filtered"
        except Exception as e:
            self.log(f"Xmas scan error for {target}:{port} - {e}")
            return "error"
    
    
    def null_scan(self, target: str, port: int) -> str:
        """Perform a NULL scan (no flags)."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(dport=port, flags=0)
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=False)
            if resp is None:
                return "open"
            elif resp.haslayer(scapy.TCP) and resp[scapy.TCP].flags == "R":
                return "closed"
            return "filtered"
        except Exception as e:
            self.log(f"NULL scan error for {target}:{port} - {e}")
            return "error"
    
        
    def banner_grabber(self, target: str, port: int) -> str:
        """Grab banner for TCP and selected UDP services."""
        try:
            # TCP banner grabbing
            if self.transport_layer == "tcp":
                if port == 443:
                    context = ssl._create_unverified_context()
                    with socket.create_connection((target, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % target.encode())
                            return ssock.recv(1024).decode(errors="ignore").strip()
                elif port == 80:
                    with socket.create_connection((target, port), timeout=self.timeout) as s:
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % target.encode())
                        return s.recv(1024).decode(errors="ignore").strip()
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.timeout)
                        s.connect((target, port))
                        s.sendall(b"\r\n")
                        return s.recv(1024).decode(errors="ignore").strip()
    
            # UDP banner grabbing (specific services only)
            elif self.transport_layer == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
    
                if port == 161:  # SNMP v1 request
                    # Simple SNMP GET request packet (community string: "public")
                    snmp_packet = bytes.fromhex("30 26 02 01 01 04 06 70 75 62 6c 69 63 a0 19 02 04 70 69 6e 67 02 01 00 02 01 00 30 0b 30 09 06 05 2b 06 01 02 01 05 00")
                    sock.sendto(snmp_packet, (target, port))
                    data, _ = sock.recvfrom(1024)
                    return data.decode(errors="ignore").strip()
    
                elif port == 123:  # NTP
                    ntp_data = b'\x1b' + 47 * b'\0'
                    sock.sendto(ntp_data, (target, port))
                    data, _ = sock.recvfrom(512)
                    return "NTP response received" if data else "No response"
    
                elif port == 53:  # DNS (send a dummy query)
                    dns_query = bytes.fromhex("aa aa 01 00 00 01 00 00 00 00 00 00 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01")
                    sock.sendto(dns_query, (target, port))
                    data, _ = sock.recvfrom(1024)
                    return "DNS response received" if data else "No response"
    
                else:
                    # Generic UDP probe
                    sock.sendto(b"\x00", (target, port))
                    data, _ = sock.recvfrom(512)
                    return data.decode(errors="ignore").strip()
    
        except Exception as e:
            self.log(f"UDP banner grab error for {target}:{port} - {e}")
            return "Unknown"
    
        

    def get_geolocation(self, ip: str) -> str:
        """Fetch geolocation for an IP."""
        try:
            if ipaddress.ip_address(ip).is_private:
                response = requests.get("https://api.ipify.org?format=json", timeout=5)
                ip = response.json().get("ip", ip)
            response = requests.get(f"{self.GEOIP}{ip}", timeout=5)
            data = response.json()
            return f"{data.get('city', 'Unknown')}, {data.get('regionName', 'Unknown')}, {data.get('country', 'Unknown')}"
        except Exception as e:
            self.log(f"Geolocation error for {ip} - {e}")
            return "Unknown"


    def get_ssl_certificate(self, target: str, port: int = 443) -> Dict:
        """Retrieve SSL certificate details."""
        try:
            context = ssl._create_unverified_context()  # Use unverified context to avoid verify failures
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    return {"issuer": cert.get("issuer", [])}
        except Exception as e:
            self.log(f"SSL cert error for {target}:{port} - {e}")
            return {"issuer": "Unknown"}



    def get_mac_address(self, target: str) -> str:
        """Get MAC address via ARP."""
        try:
            arp_request = scapy.ARP(pdst=target)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            return answered_list[0][1].hwsrc if answered_list else "Unknown"
        except Exception as e:
            self.log(f"MAC address error for {target} - {e}")
            return "Unknown"


    def os_detection(self, target: str) -> str:
        """Detect OS via TCP/IP fingerprinting."""
        try:
            pkt = scapy.IP(dst=target) / scapy.TCP(flags="S", options=[("MSS", 1460), ("WScale", 2)])
            response = scapy.sr1(pkt, timeout=2, verbose=False)
            if response and response.haslayer(scapy.TCP):
                ttl = response[scapy.IP].ttl
                window = response[scapy.TCP].window
                if ttl <= 64 and window > 0:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
            return "Unknown"
        except Exception as e:
            self.log(f"OS detection error for {target} - {e}")
            return "Unknown"


    def service_version(self, target: str, port: int) -> str:
        """Detect service and its version using banner grabbing."""
        banner = self.banner_grabber(target, port)
        parsed_banner = self.parse_http_headers(banner)
    
        try:
            service = socket.getservbyport(port)
        except Exception:
            service = "Unknown"
    
        version_info = parsed_banner if parsed_banner else banner
    
        if version_info.strip() == "" or version_info == "Unknown":
            return f"Service: {service}, Version: "
        return f"Service: {service}, Version: {version_info}"



    def discover_hosts(self, subnet: str) -> List[str]:
        """Perform host discovery via ARP."""
        try:
            arp_request = scapy.ARP(pdst=subnet)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            hosts = [received.psrc for sent, received in answered_list]
            self.log(f"Discovered hosts: {hosts}")
            return hosts
        except Exception as e:
            self.log(f"Host discovery error for {subnet} - {e}")
            return []


    def worker(self, target: str, scan_type: str) -> None:
        while not self.queue.empty():
            port = self.queue.get()
    
            if scan_type == "connect":
                result = self.connect_scan(target, port)
                state = "open" if result else "closed"
            elif scan_type == "syn":
                state = self.syn_scan(target, port)
            elif scan_type == "ack":
                state = self.ack_scan(target, port)
            elif scan_type == "window":
                state = self.window_scan(target, port)
            elif scan_type == "fin":
                state = self.fin_scan(target, port)
            elif scan_type == "xmas":
                state = self.xmas_scan(target, port)
            elif scan_type == "null":
                state = self.null_scan(target, port)
            else:
                self.log(f"Unknown scan type: {scan_type}")
                self.queue.task_done()
                continue
    
            with self.lock:
                if state == "open" and port not in self.results:
                    self.results.append(port)
                    self.log(f"{target}:{port} is open ({scan_type})")
                elif state == "closed":
                    self.log(f"{target}:{port} is closed ({scan_type})")
                elif state == "filtered":
                    self.log(f"{target}:{port} is filtered ({scan_type})")
                elif state == "unfiltered":
                    self.log(f"{target}:{port} is unfiltered ({scan_type})")
                else:
                    self.log(f"{target}:{port} scan returned {state} ({scan_type})")
            self.queue.task_done()




    def scan_target(self, target: str, scan_type: str = "syn") -> Optional[Dict]:
        """Scan a single target."""
        try:
            self.results = []
            ports_list = self.parse_ports()
            for port in ports_list:
                self.queue.put(port)

            delay, _, max_threads = self.set_timing()
            threads = []
            for _ in range(min(max_threads, len(ports_list))):
                t = threading.Thread(target=self.worker, args=(target, scan_type))
                t.start()
                threads.append(t)
                time.sleep(delay)

            for t in threads:
                t.join()

            host_info = {
                "IP": target,
                "MAC": self.get_mac_address(target),
                "Time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Transport": self.transport_layer,
                "OS": self.os_detection(target),
                "Geolocation": self.get_geolocation(target),
                "Ports": {}
            }
            for port in ports_list:
                if port in self.results:
                    state = "open"
                    service = self.service_version(target, port)
                else:
                    state = self.syn_scan(target, port) if scan_type == "syn" else ("closed" if not self.connect_scan(target, port) else "open")
                    service = "Unknown" if state != "open" else self.service_version(target, port)
                host_info["Ports"][port] = {"State": state, "Service": service}
            if scan_type == "syn" and 443 in self.results:
                host_info["SSL"] = self.get_ssl_certificate(target)
            return host_info
        except Exception as e:
            self.log(f"Scan error for {target} - {e}")
            return None



    def set_timing(self) -> Tuple[float, int, int]:
        """Set timing parameters like Nmap's -T options."""
        timing_options = {
            "T0": (0.5, 5, 10),  # Paranoid
            "T1": (0.3, 4, 15),  # Sneaky
            "T2": (0.2, 3, 20),  # Polite
            "T3": (0.1, 2, 30),  # Normal
            "T4": (0.05, 1, 50), # Aggressive
            "T5": (0.02, 1, 100) # Insane
        }
        return timing_options.get(self.timing_template, (0.1, 2, 30))


    def scan(self, save_to_file: bool = False, scan_type: str = "syn") -> None:
        """Perform the full scan."""
        target_list = []
        seen_ips = set()
    
        for target in self.targets.split(","):
            if "/" in target:
                hosts = self.discover_hosts(target)
            else:
                hosts = list(set(self.resolve_domain(target)))  
            target_list.extend(hosts)
    
        if not target_list:
            self.log("No valid targets resolved")
            return
    
        for ip in target_list:
            ip = ip.strip()
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            result = self.scan_target(ip, scan_type)
            if result:
                self.discovered_ports.append(result)
    
        if save_to_file and self.discovered_ports:
            self.Reporter.CSV_GenerateReport(Data=self.discovered_ports)
            self.Reporter.TXT_GenerateReport(Data=self.discovered_ports)
            self.Reporter.JSON_GenerateReport(Data=self.discovered_ports)
    
        if self.verbose and self.discovered_ports:
            print("\n\033[32m=== Final Scan Results ===\033[0m")
            for result in self.discovered_ports:
                print(f"\nHost: {result['IP']} ({result['Geolocation']})")
                print(f"MAC Address: {result['MAC']}")
                print(f"OS: {result['OS']}")
                print("\033[1mPORT     STATE     SERVICE\033[0m")
        
                # Port statistics
                open_count = closed_count = filtered_count = unfiltered_count = 0
                services = []
        
                for port, info in result["Ports"].items():
                    port_str = f"\033[36m{port:<8}\033[0m"
                    state = info["State"]
                    service = info["Service"]
                    services.append(service)
        
                    if state == "open":
                        open_count += 1
                        state_str = f"\033[32m{state:<8}\033[0m"
                    elif state == "closed":
                        closed_count += 1
                        state_str = f"\033[31m{state:<8}\033[0m"
                    elif state == "filtered":
                        filtered_count += 1
                        state_str = f"\033[33m{state:<8}\033[0m"
                    elif state == "unfiltered":
                        unfiltered_count += 1
                        state_str = f"\033[34m{state:<8}\033[0m"
                    else:
                        state_str = f"{state:<8}"
        
                    print(f"{port_str} {state_str} {service}")
        
                # SSL Info
                if "SSL" in result:
                    issuer = result.get("SSL", {}).get("issuer", [])
                    issuer_str = ", ".join(f"{x[0]}={x[1]}" for x in issuer) if isinstance(issuer, list) else "Unknown"
                    print(f"SSL Issuer: {issuer_str}")
        
                # Detection Summary
                print("\n\033[35m--- Detection Summary ---\033[0m")
                print(f"Total Ports Scanned: {len(result['Ports'])}")
                print(f"Open: \033[32m{open_count}\033[0m | Closed: \033[31m{closed_count}\033[0m | "
                      f"Filtered: \033[33m{filtered_count}\033[0m | Unfiltered: \033[34m{unfiltered_count}\033[0m")
                print(f"Unique Services: {len(set(services))}")
                print(f"Detected OS: {result['OS']}")
                print(f"Scan Timestamp: {result['Time']}")
        
        
        
        
        

class PortScannerEngine(PortScanner):
    """User interface for the port scanner."""
    def __init__(self):
        self.scanner = None

    def get_user_input(self, prompt: str, default: str) -> str:
        value = input(f"\n[\033[36m>\033[0m] {prompt} (default: {default}): ").strip()
        return value if value else default

    def to_bool(self, value: str) -> bool:
        true_values = {"true", "t", "yes", "y", "1"}
        false_values = {"false", "f", "no", "n", "0"}
        value = value.strip().lower()
        if value in true_values:
            return True
        elif value in false_values:
            return False
        else:
            print(f"[\033[33m!\033[0m] Unrecognized input '{value}', defaulting to False.")
            return False

    def read_targets_from_file(self, filepath: str) -> str:
        try:
            with open(filepath, 'r') as f:
                lines = [line.strip() for line in f if line.strip()]
                return ",".join(lines)
        except Exception as e:
            print(f"\033[31m[!] Failed to read from file: {filepath} - {e}\033[0m")
            return ""

    def run(self) -> None:
        print(PORTScannerLogo)
        while True:
            print("\n\033[35m=== Port Scanner Dashboard ===\033[0m")
            print("\033[36m1)\033[0m Scan Ports")
            print("\033[36m2)\033[0m Show Usage Examples")
            print("\033[36m3)\033[0m Exit")
            choice = input("\n[\033[36m>\033[0m] Enter your choice: ").strip().lower()

            if choice in {"3", "exit"}:
                print("\033[32m[✓] Goodbye!\033[0m")
                break

            elif choice == "1":
                targets = self.get_user_input("Targets (IP, domain, or 'file:filename.txt')", "192.168.1.1")
                if targets.startswith("file:"):
                    filepath = targets.split("file:")[-1]
                    targets = self.read_targets_from_file(filepath)
                    if not targets:
                        continue
                ports = self.get_user_input("Ports (e.g., 80,443, 1-100 or all_tcp_only/all_udp_only/all_common_ports/full_range/well_known/registered/dynamic)", "80,443")
                transport = self.get_user_input("Transport (tcp/udp/all)", "tcp")
                scan_type = self.get_user_input("Scan type (connect/syn/ack/window/fin/xmas/null/all)", "syn")
                timeout = float(self.get_user_input("Timeout (seconds)", "2"))
                retries = int(self.get_user_input("Retries", "3"))
                timing = self.get_user_input("Timing (T0-T5)", "T3")
                verbose_input = self.get_user_input("Verbose (True/False)", "True")
                save_input = self.get_user_input("Save report to file (True/False)", "False")

                verbose = self.to_bool(verbose_input)
                save_to_file = self.to_bool(save_input)

                scan_types = ["connect", "syn", "ack", "window", "fin", "xmas", "null"]
                transports = ["tcp", "udp"]

                selected_scan_types = scan_types if scan_type == "all" else [scan_type]
                selected_transports = transports if transport == "all" else [transport]

                for selected_transport in selected_transports:
                    for selected_scan in selected_scan_types:
                        print(f"\n\033[34m--- Scanning with transport: {selected_transport.upper()}, scan type: {selected_scan.upper()} ---\033[0m")
                        self.scanner = PortScanner(targets, selected_transport, ports, timeout, retries, verbose, timing)
                        self.scanner.scan(save_to_file=save_to_file, scan_type=selected_scan)

                        if save_to_file:
                            print("\033[32m[✓] Reports saved as CSV, TXT, and JSON.\033[0m")

            elif choice == "2":
                self.show_usage_examples()

            else:
                print(f"\033[31m[!] Invalid choice: {choice}\033[0m")


def main():
    try:
        engine = PortScannerEngine()
        engine.run()
        
    except KeyboardInterrupt:
        print("\n\033[32m[✓] Program terminated by user.\033[0m")
    except Exception as e:
        print(f"\033[31m[!] Critical Error: {e}\033[0m")



if __name__ == "__main__":
    main()
