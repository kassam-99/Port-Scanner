import datetime
import ipaddress
import os
import ssl
import subprocess
import uuid
import requests
import requests
import socket
import scapy.all as scapy
from multiprocessing import Pool, Manager, cpu_count
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
Version: 1.0, 28 May 2024               
This project is open source
For any information on editing         
the project, please refer to PortScanner.txt                                   
                                                                          

"""


class NetworkConfig:
    def __init__(self):
        
        self.GEOIP = "http://ip-api.com/json/"
        
        self.DiscoveredPort = []
        self.HostPort = {
            "No.": None,
            "IP": None,
            "MAC": None,
            "Time & Date" : None,
            "Transport Layer": None,
        }

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

    
    






class Port_Scanner(NetworkConfig):
    def __init__(self, targets=None, Transport_Layer=None, ports=None, time_out=2, retries=3, verbose=False):
        super().__init__()
        self.targets = targets
        self.Transport_Layer = Transport_Layer
        self.ports = ports
        self.time_out = time_out
        self.retries = retries
        self.verbose = verbose
        self.DiscoveredPort = []
        self.Reporter = Report_Generator()
        self.logfile = 'scan_log.txt'

    def log(self, message):
        if self.verbose == True:
            print(message)
        with open(self.logfile, 'a') as log_file:
            log_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
            

    def TargetSocketConn(self, Socket_Transport, Socket_target, Socket_port):
        for attempt in range(self.retries):
            try:
                with socket.socket(socket.AF_INET, Socket_Transport) as GoScan:
                    GoScan.settimeout(self.time_out)
                    result = GoScan.connect_ex((Socket_target, Socket_port))
                    if result == 0:
                        return result
            except socket.timeout:
                self.log(f"Timeout on attempt {attempt + 1} for {Socket_target}:{Socket_port}")
            except socket.error as e:
                self.log(f"Socket error on attempt {attempt + 1} for {Socket_target}:{Socket_port} - {e}")
        return result
    

    def banner_grabber(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.time_out)
                s.connect((target, port))
                if port == 80:
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                else:
                    s.sendall(b"\r\n")
                banner = s.recv(1024).decode().strip()
                return banner
        except socket.error as e:
            self.log(f"Error grabbing banner from {target}:{port} - {e}")
            return "Unknown"
        

    def get_geolocation(self, ip):
        try:
            private_ips = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '169.254.0.0/16',
                '127.0.0.0/8',
                '::1',
                'fe80::/10',
                'fc00::/7'
            ]
            for private_ip in private_ips:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(private_ip):
                    response = requests.get('https://api.ipify.org?format=json')
                    if response.status_code == 200:
                        public_ip_data = response.json()
                        public_ip = public_ip_data.get('ip', 'Unknown')
                        # Get geolocation of public IP
                        response = requests.get(f"{self.GEOIP}{public_ip}")
                        if response.status_code == 200:
                            data = response.json()
                            return f"{data['city']}, {data['regionName']}, {data['country']}"
                        else:
                            return "Unknown location"
                    else:
                        return "Unknown location"
            
            # If the provided IP is not private, proceed with fetching its geolocation
            response = requests.get(f"{self.GEOIP}{ip}")
            if response.status_code == 200:
                data = response.json()
                return f"{data['city']}, {data['regionName']}, {data['country']}"
            else:
                return "Unknown location"
        except Exception as e:
            self.log(f"Error fetching geolocation for {ip} - {e}")
            return "Unknown location"

        

    def get_ssl_certificate(self, target, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception as e:
            self.log(f"Error retrieving SSL certificate from {target}:{port} - {e}")
            return "Unknown certificate"
        

    def GetProtocol(self, dictionary, value):
        try:
            for key, val in dictionary.items():
                if val == value:
                    return key
            return "Unknown"
        except Exception as e:
            self.log(f"Error retrieving protocol - {e}")
            return "Unknown"
        

    def GetMacAddress(self, Target_IP):
        try:
            arp_request = scapy.ARP(pdst=Target_IP)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
            for sent, received in answered_list:
                return received.hwsrc
        except Exception as e:
            self.log(f"Error getting MAC address using scapy for {Target_IP} - {e}")
        try:
            arp_output = subprocess.check_output(["arp", "-n", Target_IP], encoding='utf-8')
            for line in arp_output.splitlines():
                if Target_IP in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        return parts[2]
        except Exception as e:
            self.log(f"Error getting MAC address using arp for {Target_IP} - {e}")
        return "Unknown"
    

    def Verbos_Process(self, Vtarget, Vresult, Vport, Vscan_type):
        try:
            if Vresult == 0:
                if Vscan_type == socket.SOCK_STREAM:
                    self.log(f"{Vtarget} - {self.GetProtocol(self.TCP_Ports, Vport)}:{Vport} is open.")
                elif Vscan_type == socket.SOCK_DGRAM:
                    self.log(f"{Vtarget} - {self.GetProtocol(self.UDP_Ports, Vport)}:{Vport} is open.")
                return Vport
            else:
                if Vscan_type == socket.SOCK_STREAM:
                    self.log(f"{Vtarget} - {self.GetProtocol(self.TCP_Ports, Vport)}:{Vport} is closed.")
                elif Vscan_type == socket.SOCK_DGRAM:
                    self.log(f"{Vtarget} - {self.GetProtocol(self.UDP_Ports, Vport)}:{Vport} is closed.")
                return None
        except Exception as e:
            self.log(f"Error processing verbose output for {Vtarget}:{Vport} - {e}")
            return None
        

    def OS_detection(self, target):
        try:
            ans, unans = scapy.sr(scapy.IP(dst=target) / scapy.TCP(flags="S"), timeout=2)
            for sent, received in ans:
                if received.haslayer(scapy.TCP) and received[scapy.TCP].flags == "SA":
                    ttl = received[scapy.IP].ttl
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Unknown"
            return "No response"
        except Exception as e:
            self.log(f"Error performing OS detection for {target} - {e}")
            return "Error"
        

    def Service_version(self, target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.time_out)
            s.connect((target, port))
            service = socket.getservbyport(port)
            banner = self.banner_grabber(target, port)
        except socket.timeout:
            self.log(f"Timeout occurred while connecting to {target}:{port}")
            banner = "Unknown"
        except socket.error as e:
            self.log(f"Socket error for {target}:{port} - {e}")
            banner = "Unknown"
        except Exception as e:
            self.log(f"Error performing service version detection for {target}:{port} - {e}")
            banner = "Unknown"
        finally:
            s.close()
        return f"Service: {service}, Banner: {banner}"
    
    
    def scan_target(self, target):
        filtered_ports = []
        try:
            scan_type = self.transport_mapping.get(self.Transport_Layer.lower())
            if scan_type is None:
                self.log("Invalid transport layer specified. Use 'TCP' or 'UDP'.")
                return None
            ports_list = self.ports.replace(" ", "").split(',')
            for port in ports_list:
                if '-' in port:
                    start, end = port.split('-')
                    if start.isdigit() and end.isdigit():
                        start_port = int(start)
                        end_port = int(end)
                        for port_int in range(start_port, end_port + 1):
                            if 1 <= port_int <= 65535:
                                result = self.TargetSocketConn(Socket_Transport=scan_type, Socket_target=target, Socket_port=port_int)
                                self.Verbos_Process(Vtarget=target, Vresult=result, Vport=port_int, Vscan_type=scan_type)
                                if result == 0:
                                    filtered_ports.append(port_int)
                elif port.isdigit():
                    port_int = int(port)
                    if 1 <= port_int <= 65535:
                        result = self.TargetSocketConn(Socket_Transport=scan_type, Socket_target=target, Socket_port=port_int)
                        self.Verbos_Process(Vtarget=target, Vresult=result, Vport=port_int, Vscan_type=scan_type)
                        if result == 0:
                            filtered_ports.append(port_int)
                elif (port.lower() in self.TCP_Ports) and (scan_type == socket.SOCK_STREAM):
                    result = self.TargetSocketConn(Socket_Transport=scan_type, Socket_target=target, Socket_port=self.TCP_Ports[port.lower()])
                    self.Verbos_Process(Vtarget=target, Vresult=result, Vport=self.TCP_Ports[port.lower()], Vscan_type=scan_type)
                    if result == 0:
                        filtered_ports.append(self.TCP_Ports[port.lower()])
                elif (port.lower() in self.UDP_Ports) and (scan_type == socket.SOCK_DGRAM):
                    result = self.TargetSocketConn(Socket_Transport=scan_type, Socket_target=target, Socket_port=self.UDP_Ports[port.lower()])
                    self.Verbos_Process(Vtarget=target, Vresult=result, Vport=self.UDP_Ports[port.lower()], Vscan_type=scan_type)
                    if result == 0:
                        filtered_ports.append(self.UDP_Ports[port.lower()])
                else:
                    self.log(f"Invalid port specified: {port}.")
                    continue
            self.HostPort = {
                "No.": str(uuid.uuid4()),
                "IP": target,
                "MAC": self.GetMacAddress(target),
                "Time & Date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Transport Layer": self.Transport_Layer.lower(),
            }
            for port in filtered_ports:
                if scan_type == socket.SOCK_STREAM:
                    port_name = self.GetProtocol(self.TCP_Ports, port)
                    self.HostPort[f"{port_name}:{port}"] = "Open"
                elif scan_type == socket.SOCK_DGRAM:
                    port_name = self.GetProtocol(self.UDP_Ports, port)
                    self.HostPort[f"{port_name}:{port}"] = "Open"
            return self.HostPort
        except Exception as e:
            self.log(f"Error scanning target {target} - {e}")
            return None
    

    def extended_scan_target(self, target):
        try:
            scan_results = self.scan_target(target)
            if scan_results:
                os_details = self.OS_detection(target)
                scan_results["OS Details"] = os_details
                service_versions = {}
                for port in scan_results.keys():
                    if isinstance(port, int):
                        service = self.Service_version(target, port)
                        service_versions[port] = service
                scan_results["Service Versions"] = service_versions
                geolocation = self.get_geolocation(target)
                scan_results["Geolocation"] = geolocation
                ssl_certificate = self.get_ssl_certificate(target)
                scan_results["SSL Certificate"] = ssl_certificate
            return scan_results
        except Exception as e:
            self.log(f"Error scanning target {target} - {e}")
            return None
        

    def Scanner(self, save_to_file=False):
        try:
            scan_type = self.transport_mapping.get(self.Transport_Layer.lower())
            if scan_type is None:
                raise ValueError("Invalid transport layer specified. Use 'TCP' or 'UDP'.")
            if self.ports:
                with Pool(processes=cpu_count()) as pool:
                    results = pool.map(self.extended_scan_target, self.targets.replace(" ", "").split(','))
                self.DiscoveredPort.extend(results)
            else:
                raise ValueError("No ports specified for scanning.")
            
            if save_to_file:
                if self.DiscoveredPort:
                    self.Reporter.CSV_GenerateReport(Data=self.DiscoveredPort)
                    self.Reporter.TXT_GenerateReport(Data=self.DiscoveredPort)
                    self.Reporter.JSON_GenerateReport(Data=self.DiscoveredPort)
                else:
                    self.log("No scan results to generate reports.")
        except socket.error as e:
            self.log(f"Socket error: {e}")
        except ValueError as ve:
            self.log(f"Value error: {ve}")
        except Exception as e:
            self.log(f"Unexpected error: {e}")
    









class PortScannerEngine(Port_Scanner):
    def __init__(self):
        super().__init__()
        
        self.MainMenu = {
            "Port Scanner" : self.ScannerOptions,
            "Help" : self.HelpOptions,
            "Exit" : lambda: os.abort()
        }
        

    def get_user_input(self, param_name, default_value=None):
        while True:
            try:
                user_input = input(f"[\033[36m>\u001b[0m] Enter value for {param_name} (default: {default_value}): ").strip()
                if not user_input:
                    return default_value
                elif isinstance(default_value, bool):
                    return user_input.lower() in ['true', 'yes', '1']
                elif isinstance(default_value, int):
                    return int(user_input)
                elif isinstance(default_value, float):
                    return float(user_input)
                else:
                    return user_input
            except ValueError:
                print("[\033[31m!\u001b[0m] Invalid input. Please enter a valid value.")


    def ScannerOptions(self, **kwargs):
        Dtargets = kwargs.get("targets", self.get_user_input("targets"))
        DTransport_Layer = kwargs.get("Transport_Layer", self.get_user_input("Transport_Layer"))
        Dports = kwargs.get("ports", self.get_user_input("ports"))
        Dtime_out = kwargs.get("time_out", self.get_user_input("time_out", 2))
        Dretries = kwargs.get("retries", self.get_user_input("retries", 3))
        Dverbose = kwargs.get("verbose", self.get_user_input("verbose", False))
        save_to_file = kwargs.get("save_to_file", self.get_user_input("save_to_file", False))
        
        Zscanner = Port_Scanner(
            targets=Dtargets, 
            Transport_Layer=DTransport_Layer, 
            ports=Dports, 
            time_out=Dtime_out, 
            retries=Dretries, 
            verbose=Dverbose)
        Zscanner.Scanner(save_to_file=save_to_file)
        

    def HelpOptions(self):
        with open("PortScanner.txt", "r") as HelpRead:
            print(HelpRead.read())
            

    def ViewFunc(self, option):
        if isinstance(option, str) and option.lower() == "all":
            print("==============================")
            for index, view in enumerate(self.MainMenu):
                print(f"\033[34m{index+1}\u001b[0m) {view}")
            print("==============================")
        
        elif isinstance(option, int):
            if 1 <= option <= len(self.MainMenu):
                key = list(self.MainMenu.keys())[option - 1]
                submenu = self.MainMenu[key]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[\033[36m>\u001b[0m] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {key}")
            else:
                print(f"[\033[31m!\u001b[0m] Please choose an option within the range 1 - {len(self.MainMenu)}")

        elif isinstance(option, str):
            option = option.capitalize()
            if option in self.MainMenu:
                submenu = self.MainMenu[option]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[\033[36m>\u001b[0m] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {submenu}")
            else:
                print(f"[\033[31m!\u001b[0m] Invalid option: {option}")
                

    def print_submenu(self, submenu):
        print("==============================")
        for idx, sub_key in enumerate(submenu):
            print(f"\033[34m{idx+1}\u001b[0m) {sub_key}")
        print("==============================")


    def handle_submenu(self, submenu, sub_option):
        if sub_option.isdigit():
            sub_option = int(sub_option)
            if 1 <= sub_option <= len(submenu):
                sub_key = list(submenu.keys())[sub_option - 1]
                submenu[sub_key]()
            else:
                print(f"[\033[31m!\u001b[0m] Please choose an option within the range 1 - {len(submenu)}")

        else:
            print(f"[\033[31m!\u001b[0m] Invalid option: {sub_option}")











def main():
    engine = PortScannerEngine()
    print(PORTScannerLogo)
    while True:
        engine.ViewFunc("all")
        try:
            option = input("\n[\033[36m>\u001b[0m] Enter your choice (or '\033[31mexit\u001b[0m' to quit): ").strip().lower()
            if option == 'exit':
                engine.MainMenu["Exit"]()
                break
            elif option.isdigit():
                engine.ViewFunc(int(option))
            else:
                engine.ViewFunc(option.capitalize())

        except ValueError:
            print("[\033[31m!\u001b[0m] Invalid input. Please enter a number or '\033[31mexit\u001b[0m' to quit.")
        except KeyError:
            print("[\033[31m!\u001b[0m] Invalid option. Please choose a valid option number or name.")
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] An unexpected error occurred: {e}")

            

if __name__ == "__main__":
    main()
    
    