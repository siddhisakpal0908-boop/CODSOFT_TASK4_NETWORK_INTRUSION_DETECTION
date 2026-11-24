
from scapy.all import IP, ICMP, TCP, Raw, wrpcap

packets = []

# 1. Generate 5 ICMP packets
for i in range(5):
    packet = (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / ICMP(type=8, code=0)
        / Raw(load=f"Test ping packet {i + 1}")
    )
    packets.append(packet)

# 2. Generate 5 TCP SYN packets
for port in [21, 22, 23, 80, 443]:
    packet = (
        IP(src="192.0.2.15", dst="198.51.100.20")
        / TCP(sport=50000, dport=port, flags="S")
    )
    packets.append(packet)

# 3. Generate a simulated HTTP GET request
http_request = (
    b"GET /admin HTTP/1.1\r\n"
    b"Host: example.test\r\n"
    b"User-Agent: NIDS-Test\r\n"
    b"Connection: close\r\n\r\n"
)

http_packet = (
    IP(src="192.0.2.25", dst="198.51.100.20")
    / TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=1000)
    / Raw(load=http_request)
)

packets.append(http_packet)

# Save all test packets
wrpcap("test_data/test_data.pcap", packets)

print("Test PCAP created successfully!")
print("ICMP packets: 5")
print("TCP SYN packets: 5")
print("HTTP test packets: 1")
print("Total packets:", len(packets))
