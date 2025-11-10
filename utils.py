import pandas as pd
import re
import random
import numpy as np
import subprocess
import pyshark

# ---------------- Interface helpers (tshark -D) ---------------- #
def list_tshark_interfaces():
    """
    Returns a list of raw interface device strings from `tshark -D`, e.g.:
    ['\\Device\\NPF_{GUID}', '\\Device\\NPF_Loopback', ...]
    """
    try:
        out = subprocess.check_output(['tshark', '-D'], text=True, stderr=subprocess.STDOUT)
        devices = []
        for line in out.splitlines():
            # Example line: "1. \\Device\\NPF_{GUID} (Intel(R) Dual Band ...)"
            line = line.strip()
            if not line:
                continue
            if '. ' in line:
                _, rest = line.split('. ', 1)
                # rest like: "\\Device\\NPF_{GUID} (Friendly Name)"
                dev = rest.split(' (', 1)[0].strip()
                devices.append(dev)
        return devices
    except Exception as e:
        print(f"[!] tshark -D failed: {e}")
        return []


def choose_interface(prefer=('WiFi', 'Wireless', 'Ethernet')):
    """
    Pick a good capture interface from tshark -D list.
    Prefers device lines that contain any of the `prefer` keywords in their friendly name section,
    but since we only keep the device string, we fallback to:
    - first non-loopback device
    - otherwise first device
    """
    devices = list_tshark_interfaces()
    if not devices:
        return None
    # avoid loopback
    non_loop = [d for d in devices if 'Loopback' not in d and 'NPF_Loopback' not in d]
    return (non_loop[0] if non_loop else devices[0])


# ---------------- PACKET CAPTURE (PyShark) ---------------- #
def capture_packets(packet_count=10, iface=None):
    """
    Capture packets using PyShark and return as DataFrame.
    Extracts fields: Time, Source, Destination, Protocol, Length, ICMPv6 type, ICMPv6 checksum
    """
    if iface is None:
        iface = choose_interface()

    if not iface:
        print("[!] No interface available for capture")
        return pd.DataFrame(columns=["Time","Source","Destination","Protocol","Length","ICMPv6 type","ICMPv6 checksum"])

    rows = []
    try:
        cap = pyshark.LiveCapture(interface=iface)  # add display_filter="icmpv6" if you only want ICMPv6
        for i, pkt in enumerate(cap.sniff_continuously(packet_count=packet_count)):
            try:
                ts = float(pkt.sniff_timestamp) if hasattr(pkt, 'sniff_timestamp') else None

                # IP addresses
                src = getattr(getattr(pkt, 'ip', None), 'src', None)
                dst = getattr(getattr(pkt, 'ip', None), 'dst', None)
                if src is None or dst is None:
                    src = getattr(getattr(pkt, 'ipv6', None), 'src', src)
                    dst = getattr(getattr(pkt, 'ipv6', None), 'dst', dst)

                # Protocol
                proto = getattr(pkt, 'transport_layer', None)
                if proto is None:
                    # fallback to highest layer (e.g. ICMPv6)
                    proto = getattr(pkt, 'highest_layer', 'Other')
                # normalize ICMPv6
                if str(proto).upper().startswith('ICMPV6') or str(getattr(pkt, 'highest_layer', '')).upper() == 'ICMPV6':
                    proto = 'ICMPv6'

                # Length (frame length)
                length = None
                try:
                    length = int(getattr(getattr(pkt, 'frame_info', None), 'len', 0))
                except Exception:
                    pass
                if length is None or length == 0:
                    try:
                        length = int(getattr(pkt, 'length', 0))
                    except Exception:
                        length = 0

                # ICMPv6 fields
                icmp6_type = getattr(getattr(pkt, 'icmpv6', None), 'type', 0) or 0
                icmp6_cksum = getattr(getattr(pkt, 'icmpv6', None), 'checksum', 0) or 0

                rows.append([
                    ts, src or 'Unknown', dst or 'Unknown',
                    str(proto) if proto else 'Other', length,
                    str(icmp6_type), str(icmp6_cksum)
                ])
            except Exception as e:
                print(f"[!] Packet parse error: {e}")
                continue
    except Exception as e:
        print(f"[!] LiveCapture failed: {e}")

    return pd.DataFrame(rows, columns=[
        "Time","Source","Destination","Protocol","Length","ICMPv6 type","ICMPv6 checksum"
    ])


# ---------------- PREPROCESSING ---------------- #
def preprocess_data(df):
    """
    Basic cleaning to match your training preprocessing.
    Assumes input columns: Time, Source, Destination, Protocol, Length, ICMPv6 type, ICMPv6 checksum
    """
    df = df.copy()
    # Drop missing rows
    df = df.dropna(how='any')

    # Time numeric
    if 'Time' in df.columns:
        df['Time'] = pd.to_numeric(df['Time'], errors='coerce').fillna(0)

    # Length numeric
    if 'Length' in df.columns:
        df['Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)

    # ICMPv6 fields numeric
    if 'ICMPv6 type' in df.columns:
        df['ICMPv6 type'] = pd.to_numeric(df['ICMPv6 type'], errors='coerce').fillna(0)

    if 'ICMPv6 checksum' in df.columns:
        # Handle hex like '0x1a2b' or decimal strings
        def to_ck(x):
            try:
                s = str(x)
                if s.startswith('0x') or s.startswith('0X'):
                    return int(s, 16)
                return int(float(s))
            except Exception:
                return 0
        df['ICMPv6 checksum'] = df['ICMPv6 checksum'].apply(to_ck)

    # Fill any absolutely required columns that might be missing
    for c in ["Time","Source","Destination","Protocol","Length","ICMPv6 type","ICMPv6 checksum"]:
        if c not in df.columns:
            df[c] = 0

    return df


# ---------------- FEATURE ENGINEERING ---------------- #
def ip_to_segments(ip):
    """Split IPv6/IPv4 into 8 numeric segments for ML"""
    if not isinstance(ip, str):
        return [0] * 8

    if ":" in ip:  # IPv6
        parts = re.split(":", ip)
        parts = [int(p, 16) if p else 0 for p in parts]
    else:  # IPv4
        parts = ip.split(".")
        parts = [int(p) for p in parts if p.isdigit()]

    while len(parts) < 8:
        parts.append(0)
    return parts[:8]


def feature_engineer(df, le_protocol, le_icmp_type):
    """
    Apply feature transformations: encoders, IP segmentation
    """
    df = df.copy()

    # Encode Protocol
    if 'Protocol' in df.columns:
        df['Protocol'] = df['Protocol'].astype(str)
        # map unseen to first known class (or random choice) — consistent with your old logic
        df['Protocol'] = [p if p in le_protocol.classes_ else le_protocol.classes_[0] for p in df['Protocol']]
        df['Protocol'] = le_protocol.transform(df['Protocol'])

    # Encode ICMPv6 type
    if 'ICMPv6 type' in df.columns:
        df['ICMPv6 type'] = df['ICMPv6 type'].astype(str)
        df['ICMPv6 type'] = [t if t in le_icmp_type.classes_ else le_icmp_type.classes_[0] for t in df['ICMPv6 type']]
        df['ICMPv6 type'] = le_icmp_type.transform(df['ICMPv6 type'])

    # IP Segments
    if 'Source' in df.columns:
        src_segs = df['Source'].apply(ip_to_segments)
        for i in range(8):
            df[f'Source_seg_{i}'] = src_segs.apply(lambda x: x[i])

    if 'Destination' in df.columns:
        dst_segs = df['Destination'].apply(ip_to_segments)
        for i in range(8):
            df[f'Destination_seg_{i}'] = dst_segs.apply(lambda x: x[i])

    return df