import pandas as pd
from collections import deque
from utils import preprocess_data, feature_engineer
from sklearn.preprocessing import LabelEncoder

# Dummy encoders (replace with your saved LabelEncoders when using trained model)
le_protocol = LabelEncoder()
le_protocol.fit(["ICMPv6", "TCP", "UDP", "Other"])

le_icmp_type = LabelEncoder()
le_icmp_type.fit([
    "Echo request", "Destination unreachable", "Router advertisement",
    "Time exceeded", "Neighbour solicitation", "Echo reply", ""
])

# Rolling buffer to keep last N packets for continuous graph
MAX_BUFFER = 1000
packet_buffer = deque(maxlen=MAX_BUFFER)


def compute_tick_features(pyshark_packets):
    """
    Generate ML-ready features from PyShark packets.
    Keeps a rolling buffer of packets instead of resetting every batch.
    Returns:
      - feats (dict with PPS, bytes for dashboard)
      - df_features (DataFrame ready for ML model)
    """
    total_bytes = 0

    for p in pyshark_packets:
        try:
            ts = float(p.sniff_timestamp)
            src = getattr(getattr(p, 'ip', None), 'src', None)
            dst = getattr(getattr(p, 'ip', None), 'dst', None)

            if src is None or dst is None:  # fallback to IPv6
                src = getattr(getattr(p, 'ipv6', None), 'src', src)
                dst = getattr(getattr(p, 'ipv6', None), 'dst', dst)

            proto = getattr(p, 'transport_layer', None)
            if proto is None:
                proto = getattr(p, 'highest_layer', 'Other')

            # Only keep ICMPv6 packets (your ML model is for ICMPv6 traffic)
            if str(proto).upper() != "ICMPV6" and str(getattr(p, 'highest_layer', '')).upper() != "ICMPV6":
                continue

            length = int(getattr(getattr(p, 'frame_info', None), 'len', 0) or 0)
            icmp_type = getattr(getattr(p, 'icmpv6', None), 'type', "")
            checksum = getattr(getattr(p, 'icmpv6', None), 'checksum', 0)

            packet_buffer.append([
                ts, src or "Unknown", dst or "Unknown", "ICMPv6", length, str(icmp_type), str(checksum)
            ])
            total_bytes += length

        except Exception:
            continue

    # Convert rolling buffer to DataFrame
    df_raw = pd.DataFrame(list(packet_buffer), columns=[
        "Time", "Source", "Destination", "Protocol", "Length", "ICMPv6 type", "ICMPv6 checksum"
    ])

    df_features = pd.DataFrame()
    if not df_raw.empty:
        df_clean = preprocess_data(df_raw)
        df_features = feature_engineer(df_clean, le_protocol, le_icmp_type)

    feats = {
        "pps": len(packet_buffer),     # packets currently in rolling buffer
        "bytes": total_bytes,          # total bytes this tick
        "df_features": df_features     # ML-ready features
    }
    return feats
