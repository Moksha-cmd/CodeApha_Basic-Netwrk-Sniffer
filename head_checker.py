
# Define headers that should be present in secure responses
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Helps prevent XSS attacks",
    "Strict-Transport-Security": "Enforces secure (HTTPS) connections to the server",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "X-Frame-Options": "Prevents clickjacking",
    "X-XSS-Protection": "Enables XSS filtering",
    "Referrer-Policy": "Controls how much referrer information is shared",
    "Permissions-Policy": "Controls access to browser features"
}
import urllib.parse
import http.client
def check_security_headers(url):
    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or "/"

    if parsed_url.scheme == "https":
        conn = http.client.HTTPSConnection(host)
    else:
        conn = http.client.HTTPConnection(host)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        headers = dict(response.getheaders())

        print(f"\n[+] Checking security headers for: {url}")
        print(f"[*] HTTP Status: {response.status} {response.reason}\n")

        missing = []
        for header, purpose in RECOMMENDED_HEADERS.items():
            if header not in headers:
                missing.append((header, purpose))

        if missing:
            print("[-] Missing Security Headers:")
            for header, reason in missing:
                print(f"   • {header} — {reason}")
        else:
            print("[+] All recommended security headers are present.")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()

# Example usage
if __name__ == "__main__":
    test_url = input("Enter a URL (e.g., https://example.com): ")
    check_security_headers(test_url)
from scapy.all import *

def packet_callback(packet):
    """
    This function is called for every captured packet.
    It analyzes the packet and prints relevant information.
    """
    print("\n--- New Packet Captured ---")

    # Display Ethernet Layer information
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        print(f"Ethernet Layer:")
        print(f"  Source MAC: {eth_layer.src}")
        print(f"  Destination MAC: {eth_layer.dst}")
        print(f"  EtherType: {eth_layer.type} (0x{eth_layer.type:x})") # EtherType indicates the next protocol

    # Display IP Layer information
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"IP Layer:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto} ({IP_PROTOS.get(ip_layer.proto, 'Unknown')})") # IP_PROTOS maps protocol numbers to names
        print(f"  TTL: {ip_layer.ttl}")
        print(f"  Length: {ip_layer.len} bytes")

        # Display Transport Layer (TCP/UDP) information
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP Layer:")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
            print(f"  Flags: {tcp_layer.flags}")
            print(f"  Sequence Number: {tcp_layer.seq}")
            print(f"  Acknowledgement Number: {tcp_layer.ack}")
            print(f"  Window Size: {tcp_layer.window}")
            if tcp_layer.payload:
                print(f"  TCP Payload (Raw): {bytes(tcp_layer.payload)}")

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP Layer:")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")
            print(f"  Length: {udp_layer.len}")
            if udp_layer.payload:
                print(f"  UDP Payload (Raw): {bytes(udp_layer.payload)}")

        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"ICMP Layer:")
            print(f"  Type: {icmp_layer.type}")
            print(f"  Code: {icmp_layer.code}")
            if icmp_layer.payload:
                print(f"  ICMP Payload (Raw): {bytes(icmp_layer.payload)}")

    # Display Raw Data/Payload if present and not handled by other layers
    if packet.haslayer(Raw):
        raw_layer = packet.getlayer(Raw)
        print(f"Raw Data/Payload:")
        # Attempt to decode as ASCII, otherwise print hex
        try:
            print(f"  ASCII: {raw_layer.load.decode('ascii', errors='ignore')}")
        except:
            print(f"  Hex: {raw_layer.load.hex()}")
    elif packet.payload:
        # Catch any remaining payload not specifically handled
        # This can happen if the payload isn't a recognized Scapy layer (e.g., application layer data)
        if not (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)):
            print(f"Unhandled Payload (Raw): {bytes(packet.payload)}")

def start_sniffer(interface=None, count=0, packet_filter=""):
    """
    Starts the network sniffer.

    Args:
        interface (str, optional): The network interface to sniff on (e.g., "eth0", "Wi-Fi").
                                   If None, scapy tries to find a default.
        count (int, optional): Number of packets to capture. 0 means infinite.
        packet_filter (str, optional): BPF (Berkeley Packet Filter) string for filtering packets.
                                       e.g., "tcp port 80", "udp and host 192.168.1.1"
    """
    print(f"[*] Starting sniffer on interface: {interface if interface else 'default'}")
    print(f"[*] Capturing {count if count > 0 else 'infinite'} packets.")
    if packet_filter:
        print(f"[*] Applying filter: '{packet_filter}'")

    try:
        sniff(iface=interface, prn=packet_callback, count=count, filter=packet_filter, store=0)
    except Exception as e:
        print(f"Error starting sniffer: {e}")
        print("You might need to run this script with root/administrator privileges.")
        print("On Linux/macOS: sudo python your_script_name.py")
        print("On Windows: Run your command prompt/PowerShell as Administrator.")

if __name__ == "__main__":
    # Example usage:
    # To sniff on a specific interface, replace None with your interface name
    # e.g., start_sniffer(interface="eth0", count=10)
    # To sniff all traffic on default interface:
    # start_sniffer(count=20)
    # To sniff specific traffic (e.g., only HTTP traffic):
    # start_sniffer(packet_filter="tcp port 80 or tcp port 443", count=50)

    # You can list available interfaces using scapy's show_interfaces()
    # show_interfaces()

    # Sniff 10 packets on the default interface
    start_sniffer(count=50)

    # Example of sniffing HTTP/HTTPS traffic on a specific interface (uncomment and modify if needed)
    # print("\nStarting sniffer for HTTP/HTTPS traffic (5 packets)...")
    # start_sniffer(interface="Wi-Fi", count=5, packet_filter="tcp port 80 or tcp port 443")