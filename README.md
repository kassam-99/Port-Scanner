# Port-Scanner
Offers extensive network scanning capabilities.

PortScanner is a Python tool designed for network port scanning, information gathering, and reporting. It provides a comprehensive set of functionalities for scanning target hosts, detecting open ports, fetching banners, performing SSL certificate retrieval, and more.

## Key Features:

1. **Port Scanning:** Scan target hosts for open TCP and UDP ports using specified transport layers.
2. **Banner Grabbing:** Retrieve banners from open ports to gather information about services running on target hosts.
3. **Geolocation:** Fetch geolocation data for target IP addresses to determine their physical location.
4. **OS Detection:** Perform operating system detection on target hosts based on TTL values in received packets.
5. **Service Version Detection:** Identify service versions running on open ports to determine specific software and protocols.
6. **SSL Certificate Retrieval:** Fetch SSL certificates from target hosts to analyze their security configurations.
7. **Customizable Options:** Customize scanning parameters such as timeout, retries, verbosity, and saving scan results to files.



**Contributing:**

Contributions, bug reports, and feature requests are welcome! Feel free to fork the repository, make your changes, and submit a pull request.



### Getting Started

Clone the repository.
    
    git clone https://github.com/kassam-99/Port-Scanner.git


Install dependencies

    pip install -r requirements.txt


### Usage Examples

Launch a server:

    cd Port-Scanner

    python PortScanner.py
