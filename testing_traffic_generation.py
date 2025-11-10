from scapy.all import *
import random
import time

# ICMPv6 type-to-name mapping
ICMPV6_TYPES = {
    128: "Echo request",
    129: "Echo reply",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbour solicitation",
    136: "Neighbour advertisement",
    1:   "Destination unreachable",
    3:   "Time exceeded",
    157: "Duplicate address detection"
}

# Packet size ranges (realistic, based on training dataset distribution)
PACKET_SIZE_RANGE = {
    128: (64, 1880),   # Echo request
    129: (64, 1280),   # Echo reply
    133: (64, 128),    # Router solicitation
    134: (120, 1900),  # Router advertisement
    135: (64, 1800),    # Neighbour solicitation
    136: (64, 1200),    # Neighbour advertisement
    1:   (100, 1500),  # Destination unreachable
    3:   (100, 1300),  # Time exceeded
    157: (64, 128)     # Duplicate address detection
}

def random_ipv6():
    return ':'.join(f"{random.randint(0, 0xffff):04x}" for _ in range(8))

def generate_icmpv6_packet(class_label):
    src_ip = random_ipv6()
    dst_ip = random.choice(["ff02::1", "ff02::2", random_ipv6()])

    # Select ICMPv6 type based on class
    if class_label == "Attack":
        icmp_type = random.choice([134, 135, 1, 3, 157])
    else:
        icmp_type = random.choice([128, 129, 133, 136])

    # Build ICMPv6 header
    if icmp_type == 128:
        icmp = ICMPv6EchoRequest()
    elif icmp_type == 129:
        icmp = ICMPv6EchoReply()
    elif icmp_type == 133:
        icmp = ICMPv6ND_RS()
    elif icmp_type == 134:
        icmp = ICMPv6ND_RA()
    elif icmp_type == 135:
        icmp = ICMPv6ND_NS()
    elif icmp_type == 136:
        icmp = ICMPv6ND_NA()
    elif icmp_type == 1:
        icmp = ICMPv6DestUnreach()
    elif icmp_type == 3:
        icmp = ICMPv6TimeExceeded()
    else:
        icmp = Raw(load="DAD packet")

    # ✅ Add random payload within training size distribution
    size_range = PACKET_SIZE_RANGE.get(icmp_type, (64, 512))
    payload_size = random.randint(*size_range)
    payload = Raw(load=bytes(random.getrandbits(8) for _ in range(payload_size)))

    pkt = IPv6(src=src_ip, dst=dst_ip, hlim=random.randint(30, 255)) / icmp / payload
    return pkt, class_label

def send_live_packets(num_packets=300, attack_ratio=0.5, delay_range=(0.01, 0.05)):
    print(f"[+] Sending {num_packets} ICMPv6 packets directly into network...")
    for _ in range(num_packets):
        class_label = "Attack" if random.random() < attack_ratio else "Normal"
        pkt, label = generate_icmpv6_packet(class_label)
        send(pkt, verbose=False)
        print(f"Sent: {label} -> {pkt.summary()}")
        time.sleep(random.uniform(*delay_range))  # Burst control

if __name__ == "__main__":
    send_live_packets(num_packets=50000, attack_ratio=0.7)
