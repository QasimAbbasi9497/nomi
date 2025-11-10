# DDOS Attack Detection GUI

Live ICMPv6 monitoring and anomaly detection dashboard backed by a Gradient Boosting classifier. The app lets you upload CSV captures for offline analysis or start a live feed that classifies packets in real time.

---

## 1. Prerequisites

- Python 3.11+
- `pip` for dependency installation
- Trained model artefacts in `model/` (already expected in this repo)
- `tshark` (Wireshark CLI) installed and working without elevated privileges
- Optional: `scapy` for generating synthetic ICMPv6 traffic (`testing_traffic_generation.py`)

Install Python dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Live Capture Setup

The web UI starts a `pyshark.LiveCapture` session on launch. Make sure `tshark -D` succeeds **without** `sudo` before running the app.

### macOS (primary deployment environment)

1. Install Wireshark CLI via Homebrew:

   ```bash
   brew install wireshark
   ```

   (When prompted during install, allow the installer to place the `ChmodBPF` launch daemon so permissions are managed automatically.)

2. Ensure BPF device access:

   ```bash
   sudo /opt/homebrew/opt/wireshark/libexec/ChmodBPF/install-chmodbpf.sh
   sudo /opt/homebrew/opt/wireshark/libexec/ChmodBPF/launch_chmodbpf start
   ```

   On Intel Macs installed via Homebrew, the path is typically `/usr/local/opt/wireshark/libexec/ChmodBPF/…`. Adjust if Homebrew is in a non-standard location.

3. Add your user to the `access_bpf` group (if it exists):

   ```bash
   sudo dseditgroup -o create access_bpf || true
   sudo dseditgroup -o edit -a "$(whoami)" -t user access_bpf
   ```

4. Log out and back in so group membership takes effect.

5. Verify:

   ```bash
   tshark -D
   ```

   You should see the interface list without errors.

6. (Optional) To send packets with Scapy without `sudo`, allow Python to access raw sockets:

   ```bash
   sudo /usr/sbin/DevToolsSecurity --enable  # macOS Developer Mode (optional)
   sudo codesign --force --deep --sign - $(which python3)
   ```

   Alternatively, run `python testing_traffic_generation.py` with `sudo` when generating traffic.

### Linux (reference script)

Use the helper script (modified from your earlier setup) to configure Wireshark permissions:

```bash
#!/usr/bin/env bash
set -euo pipefail

if ! command -v tshark >/dev/null; then
  echo "[INFO] Install Wireshark CLI first (pacman -S wireshark-cli | apt install wireshark)."
fi

if ! getent group wireshark >/dev/null; then
  sudo groupadd wireshark
fi

if ! id -nG "$USER" | grep -qw wireshark; then
  sudo usermod -aG wireshark "$USER"
fi

DUMPCAP=$(command -v dumpcap || true)
if [ -z "$DUMPCAP" ]; then
  echo "[ERROR] dumpcap not found"; exit 1
fi

sudo chgrp wireshark "$DUMPCAP"
sudo chmod 750 "$DUMPCAP"
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "$DUMPCAP"

echo "[Done] Log out/in, then run 'tshark -D' to confirm."
```

Log out/in after running the script, then confirm `tshark -D` lists interfaces. For Scapy packet generation without sudo, grant capabilities to Python:

```bash
sudo setcap 'CAP_NET_RAW+eip' "$(readlink -f "$(which python3)")"
```

---

## 3. Running the App

```bash
source .venv/bin/activate
python app.py
```

On macOS/Linux the server defaults to the loopback or `any` capture device. To override, export `CAPTURE_INTERFACE`:

```bash
CAPTURE_INTERFACE=eth0 python app.py
```

Once running, open `http://127.0.0.1:5000` in a browser:

- **Upload CSV**: run inference on a saved capture.
- **Start Live Monitoring**: see live predictions from the chosen interface.

---

## 4. Generating Test Traffic

### ICMPv6 ping

```bash
ping -6 ::1
```

Traffic should appear immediately under “Traffic Analysis”. Stop the ping and the dashboard will stop incrementing after the next refresh (flush happens roughly every second).

### Scapy generator

```bash
python testing_traffic_generation.py
```

Use `sudo` if needed or pass `iface` explicitly:

```bash
sudo python testing_traffic_generation.py  # or
python testing_traffic_generation.py en0
```

---

## 5. Troubleshooting

- **No interfaces listed**: run `tshark -D` manually; re-run the platform-specific permission steps.
- **Live view stays empty**: ensure `tshark` is configured, the chosen interface actually sees ICMPv6 traffic, and IPv6 is enabled on your network.
- **Scapy packets missing**: specify an interface in `send_live_packets(..., iface="en0")` or run with elevated privileges.
- **Permission denied**: double-check group membership and capabilities (Linux) or the BPF helper (macOS).

Once the prerequisites are satisfied, the dashboard should mirror real ICMPv6 traffic in near real time. Let the team know if you need platform-specific adjustments beyond these steps.

