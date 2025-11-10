from scapy.all import *
import random
import time
import os
import sys

# --- Optional for macOS ---
conf.use_pcap = True  # ensures Scapy uses libpcap backend when needed

# ICMPv6 type-to-name mapping (for reference)
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

# Packet size ranges for payload
PACKET_SIZE_RANGE = {
    128: (64, 1880),
    129: (64, 1280),
    133: (64, 128),
    134: (120, 1900),
    135: (64, 1800),
    136: (64, 1200),
    1:   (100, 1500),
    3:   (100, 1300),
    157: (64, 128)
}

def random_ipv6():
    return ':'.join(f"{random.randint(0, 0xffff):04x}" for _ in range(8))


def generate_icmpv6_packet(class_label, max_total_size=1232):
    src_ip = random_ipv6()
    dst_ip = random.choice(["ff02::1", "ff02::2", random_ipv6()])

    # Select ICMPv6 type
    if class_label == "Attack":
        icmp_type = random.choice([134, 135, 1, 3, 157])
    else:
        icmp_type = random.choice([128, 129, 133, 136])

    # Build ICMPv6 header
    if icmp_type == 128:
        icmp = ICMPv6EchoRequest(id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF))
    elif icmp_type == 129:
        icmp = ICMPv6EchoReply()
    elif icmp_type == 133:
        icmp = ICMPv6ND_RS()
    elif icmp_type == 134:
        icmp = ICMPv6ND_RA()
    elif icmp_type == 135:
        icmp = ICMPv6ND_NS(tgt=random_ipv6())
    elif icmp_type == 136:
        icmp = ICMPv6ND_NA(tgt=random_ipv6())
    elif icmp_type == 1:
        icmp = ICMPv6DestUnreach()
    elif icmp_type == 3:
        icmp = ICMPv6TimeExceeded()
    elif icmp_type == 157:
        icmp = ICMPv6ND_NS(tgt=random_ipv6())  # DAD-style NS
    else:
        raise ValueError(f"Unsupported ICMPv6 type: {icmp_type}")

    # Add "invoked packet" for error types
    if icmp_type in [1, 3]:
        invoked_payload_size = random.randint(64, min(512, max_total_size - 100))
        invoked = IPv6(src=random_ipv6(), dst=random_ipv6(), hlim=random.randint(30, 255)) / \
                  ICMPv6EchoRequest(id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF)) / \
                  Raw(load=os.urandom(invoked_payload_size))
        if len(invoked) > 1232:
            invoked = invoked[:1232]
        icmp /= invoked

    # Build IPv6 packet
    base_pkt = IPv6(src=src_ip, dst=dst_ip, hlim=random.randint(30, 255)) / icmp
    base_len = len(base_pkt)

    # Determine safe payload size
    max_additional = max(0, max_total_size - base_len)
    size_range = PACKET_SIZE_RANGE.get(icmp_type, (64, 512))
    desired_min = max(size_range[0], 0)
    desired_max = min(size_range[1], max_additional)
    payload_size = random.randint(desired_min, desired_max) if desired_max >= desired_min else 0

    if payload_size > 0:
        payload = Raw(load=os.urandom(payload_size))
        pkt = base_pkt / payload
    else:
        pkt = base_pkt

    # Final length cap
    if len(pkt) > max_total_size:
        pkt = pkt[:max_total_size]

    return pkt, class_label


def get_interface_mtu(iface=None):
    """Get the MTU of a network interface."""
    try:
        iface = iface or conf.iface
        return get_if_mtu(iface)
    except Exception:
        # Default IPv6 minimum MTU
        return 1280


def send_live_packets(num_packets=300, attack_ratio=0.5, delay_range=(0.01, 0.05), iface=None):
    mtu = get_interface_mtu(iface)
    safe_limit = min(1232, mtu - 48)  # safety margin

    print(f"[+] Sending {num_packets} ICMPv6 packets (max size {safe_limit} bytes, iface={iface or conf.iface})")

    for i in range(num_packets):
        class_label = "Attack" if random.random() < attack_ratio else "Normal"
        pkt, label = generate_icmpv6_packet(class_label, max_total_size=safe_limit)

        if len(pkt) > mtu:
            print(f"[!] Skipping {len(pkt)}-byte packet > MTU ({mtu})")
            continue

        try:
            send(pkt, iface=iface, verbose=False)
            print(f"[{i+1}/{num_packets}] Sent: {label} ({len(pkt)} bytes) -> {pkt.summary()}")
        except PermissionError:
            sys.exit("❌ Permission denied: run with sudo or grant CAP_NET_RAW,CAP_NET_ADMIN to your Python binary.")
        except OSError as e:
            if e.errno == 90:
                print(f"[!] Message too long ({len(pkt)} bytes) — skipped.")
                continue
            raise
        time.sleep(random.uniform(*delay_range))


if __name__ == "__main__":
    # Change iface if needed (e.g., "eth0" or "en0" on macOS)
    send_live_packets(num_packets=50000, attack_ratio=0.7, iface=None)
