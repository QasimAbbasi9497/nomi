from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
from utils import preprocess_data, feature_engineer, list_tshark_interfaces
import threading
import time
import os
import subprocess
import shutil
import asyncio
import pyshark
import platform

app = Flask(__name__)

# ---------------- LOAD MODEL + ENCODERS ---------------- #
model = joblib.load('model/gradient_boosting_classifier.pkl')
scaler = joblib.load('model/scaler.pkl')
le_protocol = joblib.load('model/le_protocol.pkl')
le_icmp_type = joblib.load('model/le_icmp_type.pkl')

TRAINING_FEATURES = list(model.feature_names_in_)
NUMERIC_FEATURES = ['Time', 'Length', 'ICMPv6 checksum'] + \
                   [f'Source_seg_{i}' for i in range(8)] + \
                   [f'Destination_seg_{i}' for i in range(8)]

live_buffer = []  # store latest predictions
capture_start_time = None

# ---------------- TSHARK PATH FIX (Windows) ---------------- #
def _ensure_tshark_on_path():
    if shutil.which("tshark"):
        return
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for exe in candidates:
        if os.path.exists(exe):
            os.environ["PATH"] = os.path.dirname(exe) + os.pathsep + os.environ.get("PATH", "")
            return
    print("[!] tshark.exe not found – please install Wireshark and ensure tshark is on PATH.")

# ---------------- INTERFACE ---------------- #
def list_tshark_interfaces_with_name():
    try:
        out = subprocess.check_output(['tshark', '-D'], text=True, stderr=subprocess.STDOUT)
        devices = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            if '. ' in line:
                _, rest = line.split('. ', 1)
                if ' (' in rest:
                    dev, name = rest.split(' (', 1)
                    name = name.rstrip(')')
                    devices.append((dev.strip(), name.strip()))
        return devices
    except Exception as e:
        print(f"[!] tshark -D failed: {e}")
        return []

def choose_interface(prefer=('WiFi', 'Wireless')):
    devices = list_tshark_interfaces()
    if not devices:
        return None
    for d in devices:
        for keyword in prefer:
            if keyword.lower() in d.lower():
                return d
    non_loop = [d for d in devices if 'Loopback' not in d and 'NPF_Loopback' not in d]
    return non_loop[0] if non_loop else devices[0]

def get_interface():
    # On Linux, prefer special 'any' device to capture across all interfaces
    try:
        if platform.system().lower() == "linux":
            out = subprocess.check_output(['tshark', '-D'], text=True, stderr=subprocess.STDOUT)
            if any(line.strip().endswith(" (Pseudo-device that captures on all interfaces)") or
                   line.strip().split('. ', 1)[-1].startswith("any")
                   for line in out.splitlines() if line.strip()):
                print("[INFO] Using 'any' interface on Linux")
                return "any"
    except Exception as e:
        print(f"[WARN] Could not check for 'any' interface: {e}")

    devices = list_tshark_interfaces_with_name()
    for dev, name in devices:
        if "loopback" in name.lower():
            print(f"[INFO] Using Loopback interface: {dev} ({name})")
            return dev
    for dev, name in devices:
        if "wifi" in name.lower():
            print(f"[INFO] Using WiFi interface: {dev} ({name})")
            return dev
    if devices:
        print(f"[INFO] Using fallback interface: {devices[0][0]} ({devices[0][1]})")
        return devices[0][0]
    print("[WARN] No capture interface found via tshark -D; live capture will not start.")
    return None

# ---------------- PACKET → ROW ---------------- #
def _packet_to_row(pkt):
    try:
        global capture_start_time
        t_abs = float(getattr(pkt.frame_info, 'time_epoch', time.time()))
        if capture_start_time is not None:
            t = t_abs - capture_start_time
        else:
            t = 0.0

        # Source & Destination (IPv6 only since training was ICMPv6)
        src = getattr(pkt.ipv6, "src", "Unknown") if hasattr(pkt, "ipv6") else "Unknown"
        dst = getattr(pkt.ipv6, "dst", "Unknown") if hasattr(pkt, "ipv6") else "Unknown"

        # Protocol (forced to ICMPv6, since training only used ICMPv6)
        proto = "ICMPv6"

        # Frame length
        try:
            length = int(pkt.length)
        except Exception:
            try:
                length = int(pkt.frame_info.len)
            except Exception:
                length = 0

        # Default ICMPv6 fields
        icmp6_type_name = "Other"
        icmp6_type_code = 9   # 👈 instead of -1, use a fixed "Other" class
        icmp6_cksum = 0

        if hasattr(pkt, "icmpv6"):
            icmp6_type_val = getattr(pkt.icmpv6, "type", None) or \
                             getattr(pkt.icmpv6, "type_value", None) or \
                             getattr(pkt.icmpv6, "icmpv6type", None)

            if icmp6_type_val is not None:
                icmp6_type_val = str(icmp6_type_val)

                # ✅ Mapping exactly matches training labels
                icmp_map = {
                    "128": ("Echo request", 3),
                    "129": ("Echo reply", 2),
                    "134": ("Router advertisement", 6),
                    "135": ("Neighbour solicitation", 5),
                    "136": ("Neighbour advertisement", 4),
                    "133": ("Router solicitation", 7),
                    "1":   ("Destination unreachable", 0),
                    "3":   ("Time exceeded", 8),
                    "157": ("Duplicate address detection", 1)
                }

                if icmp6_type_val in icmp_map:
                    icmp6_type_name, icmp6_type_code = icmp_map[icmp6_type_val]
                else:
                    # unseen type → fallback
                    icmp6_type_name = f"Other({icmp6_type_val})"
                    icmp6_type_code = 9  # keep ML consistent

            # Parse checksum (if available)
            cksum_val = getattr(pkt.icmpv6, "checksum", None)
            try:
                icmp6_cksum = int(cksum_val, 16) if cksum_val else 0
            except Exception:
                icmp6_cksum = 0

            print(f"[DEBUG] Parsed ICMPv6 type={icmp6_type_name} (code={icmp6_type_code})")

        return {
            "Time": float(t),
            "Source": src,
            "Destination": dst,
            "Protocol": proto,
            "Length": int(length),
            "Type": icmp6_type_name,         # 👈 human-readable for GUI
            "ICMPv6 type": icmp6_type_code,  # 👈 numeric for ML
            "ICMPv6 checksum": icmp6_cksum
        }
    except Exception as e:
        print(f"[ERROR] in _packet_to_row: {e}")
        return None

# ---------------- PREDICT + STORE ---------------- #
def _predict_and_store(rows):
    if not rows:
        return
    try:
        df_raw = pd.DataFrame(rows)

        # ✅ Keep a copy of "Type" (human-readable)
        df_types = df_raw[["Type"]].copy()

        # ML pipeline
        df_clean = preprocess_data(df_raw)
        df_feat = feature_engineer(df_clean, le_protocol, le_icmp_type)
        print("[DEBUG] Unique ICMPv6 types in this batch:", df_clean["ICMPv6 type"].unique().tolist())

        df_feat = df_feat.reindex(columns=TRAINING_FEATURES, fill_value=0)
        df_feat[NUMERIC_FEATURES] = scaler.transform(df_feat[NUMERIC_FEATURES])
        preds = model.predict(df_feat)

        # ✅ Reattach "Type" for GUI
        df_out = df_clean.copy()
        df_out["Type"] = df_types["Type"]  
        df_out["Prediction"] = preds
        df_out["Prediction"] = df_out["Prediction"].map({1: "Normal", 0: "Attack"})

        for rec in df_out.to_dict(orient="records"):
            live_buffer.append(rec)
        if len(live_buffer) > 1000000:
            del live_buffer[:-10000]
    except Exception as e:
        print(f"[!] Error in _predict_and_store: {e}")


# ---------------- BACKGROUND CAPTURE ---------------- #
_stop_capture = False  

def stop_live_capture():
    global _stop_capture
    _stop_capture = True

def live_traffic_worker(interface):
    global _stop_capture, capture_start_time
    _stop_capture = False
    capture_start_time = time.time()   # <-- set base time
    _ensure_tshark_on_path()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print(f"📡 Starting fresh capture on interface: {interface}")
    capture = pyshark.LiveCapture(interface=interface, display_filter="icmpv6")
    capture.sniff(timeout=0.1)
    batch = []
    last_flush_time = time.time()
    flush_interval_seconds = 1.0
    try:
        for packet in capture.sniff_continuously():
            if _stop_capture:
                print("🛑 Stopping capture...")
                break
            row = _packet_to_row(packet)
            if row:
                batch.append(row)
            now = time.time()
            if len(batch) >= 10 or (now - last_flush_time) >= flush_interval_seconds:
                _predict_and_store(batch)
                batch = []
                last_flush_time = now
    except Exception as e:
        print(f"⚠️ Capture error: {e}")
    finally:
        if batch:
            _predict_and_store(batch)
        capture.close()
        print("✅ Capture closed, ready for restart.")

# ---------------- HYBRID ADDITION: Traffic Generator ---------------- #
def generate_test_icmpv6(loopback_ip="::1", count=50):
    """
    Generate ICMPv6 echo requests for testing hybrid mode.
    Requires scapy.
    """
    try:
        from scapy.all import IPv6, ICMPv6EchoRequest, send
        print(f"[GEN] Sending {count} ICMPv6 packets to {loopback_ip}")
        for i in range(count):
            pkt = IPv6(dst=loopback_ip)/ICMPv6EchoRequest()
            send(pkt, verbose=False)
        print("[GEN] Done sending ICMPv6 test traffic.")
    except Exception as e:
        print(f"[!] Packet generation failed: {e}")

# ---------------- ROUTES ---------------- #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return 'No file uploaded', 400
    file = request.files['file']
    if not file.filename.endswith('.csv'):
        return 'Unsupported file format', 400
    df = pd.read_csv(file)
    df_clean = preprocess_data(df)
    df_feat = feature_engineer(df_clean, le_protocol, le_icmp_type)
    df_feat = df_feat.reindex(columns=TRAINING_FEATURES, fill_value=0)
    df_feat[NUMERIC_FEATURES] = scaler.transform(df_feat[NUMERIC_FEATURES])
    preds = model.predict(df_feat)
    df_clean['Prediction'] = preds
    df_clean['Prediction'] = df_clean['Prediction'].map({1: 'Normal', 0: 'Attack'})
    return jsonify(df_clean.to_dict(orient='records'))

@app.route('/live')
def live_data():
    print(f"[DEBUG] Returning {len(live_buffer)} records from live_buffer")
    if live_buffer:
        return jsonify(live_buffer[-1000000:])
    # Always return valid JSON to avoid client 'Failed to fetch' on empty buffer
    return jsonify([])

# ---------------- MAIN ---------------- #
if __name__ == '__main__':
    iface_env = os.environ.get("CAPTURE_INTERFACE")
    if iface_env:
        print(f"[INFO] Using interface from CAPTURE_INTERFACE={iface_env}")
        iface = iface_env
    else:
        iface = get_interface()
    if iface is not None:
        threading.Thread(target=live_traffic_worker, args=(iface,), daemon=True).start()
    else:
        print("⚠️ Live monitoring disabled: no valid interface. Ensure tshark is installed and you have permissions.")
    app.run(debug=True)
