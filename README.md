# PCAP Analyzer

A Python toolkit for analyzing network packet captures (`.pcap` files) — a
Tkinter GUI dashboard plus a set of focused CLI tools. Works with captures
from Meraki, tcpdump, Wireshark, or any standard libpcap-format source.

## Install

One-liner (macOS/Linux): installs Python and git if missing, clones this
repo, sets up a virtual environment, and launches the GUI.

```bash
curl -fsSL https://raw.githubusercontent.com/ghostinator/pcap-analyzer/main/install.sh | bash
```

Or manually:

```bash
git clone https://github.com/ghostinator/pcap-analyzer.git
cd pcap-analyzer
./setup.sh          # sets up venv + dependencies
./setup.sh --run    # ...or set up and launch the GUI in one step
```

**Windows:** run the above inside WSL, or manually: install Python 3.9+ from
[python.org](https://www.python.org/downloads/) (includes tkinter), then

```powershell
git clone https://github.com/ghostinator/pcap-analyzer.git
cd pcap-analyzer
python -m venv venv
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python pcap_analyzer_gui.py
```

## GUI Dashboard

```bash
venv/bin/python pcap_analyzer_gui.py
```

Load a `.pcap` file and get a dashboard with protocol breakdown, traffic
timeline, retransmission/RTT metrics, and tabs for Packets, TCP Analysis,
Errors, HTTP, DNS, Hosts, Wireless, Performance, Traffic Patterns, and
Security.

### Labeling hosts

The Hosts tab labels IPs with a hostname when it can find one, so you can
see *who* is talking instead of just IP addresses:

1. Copy `devices.example.csv` to `devices.csv` and fill in your own
   hostname/MAC/IP mappings (either column works alone per row):
   ```
   Hostname,MAC Address,IP Address
   CoreSwitch,aa:bb:cc:dd:ee:01,10.0.0.1
   ```
2. `devices.csv` next to the script is loaded automatically on startup, or
   load any CSV manually via **Load Device List (CSV)...** in the app.
3. Internal IPs are matched by IP first, then by the MAC address observed
   for that IP via ARP in the capture. External IPs with no match get an
   automatic reverse DNS lookup.

`devices.csv` is gitignored — your real device list stays local.

## CLI Tools

| Tool | Description | Use Case |
|------|-------------|----------|
| `pcap_info.py` | File summary & protocol stats | Quick overview of capture |
| `tcp_streams.py` | TCP stream identification & analysis | Connection troubleshooting |
| `http_analysis.py` | HTTP request/response extraction | Web app debugging |
| `dns_analysis.py` | DNS query/response analysis | Name resolution issues |
| `errors.py` | Network error detection | Retransmissions, RSTs, etc. |
| `filter.py` | Packet filtering & extraction | Isolate specific traffic |
| `stream_reassemble.py` | TCP stream reassembly | View actual data transferred |
| `wireless_analysis.py` | 802.11 client/signal analysis | Wi-Fi troubleshooting |
| `batch_analysis.py` | Run analysis across multiple captures | Bulk processing |

Use them directly, or via the wrapper script:

```bash
./pcap-tools.sh info capture.pcap
./pcap-tools.sh http capture.pcap --filter api.example.com
./pcap-tools.sh errors capture.pcap
./pcap-tools.sh help   # full list
```

### Quick Start Examples

```bash
# Overview of a capture
python tools/pcap_info.py capture.pcap

# TCP streams - list, then drill into one
python tools/tcp_streams.py capture.pcap
python tools/tcp_streams.py capture.pcap --stream 5
python tools/tcp_streams.py capture.pcap --filter "192.168.1.1:443"

# HTTP traffic, filtered by domain
python tools/http_analysis.py capture.pcap --filter "api.example.com"

# DNS lookups for a specific domain
python tools/dns_analysis.py capture.pcap --filter "example.com"

# Network errors: retransmissions, dup ACKs, out-of-order, zero-window, RSTs
python tools/errors.py capture.pcap

# Extract traffic to a new pcap
python tools/filter.py input.pcap https_only.pcap --dst-port 443
python tools/filter.py input.pcap filtered.pcap --src-ip 10.0.0.1 --port 80

# Reassemble a TCP stream's actual transferred data
python tools/stream_reassemble.py capture.pcap --ip 192.168.1.50
```

## Troubleshooting Workflow

**Slow web page loading:** `pcap_info.py` (traffic volume/duration) →
`dns_analysis.py` (resolution time) → `tcp_streams.py` (connection delays) →
`errors.py` (retransmissions/RSTs)

**Intermittent connection drops:** `errors.py` (RSTs/retransmissions) →
`tcp_streams.py --stream N` (the failing stream) → `filter.py` (isolate the
affected host)

**API call failures:** `http_analysis.py --filter "api.domain.com"` →
`stream_reassemble.py --ip <server-ip>` → `errors.py`

## Adding New Tools

1. Create a Python script in `tools/`.
2. Import scapy modules as needed.
3. Follow the pattern of existing tools (CLI args, error handling).
4. Update this README.
