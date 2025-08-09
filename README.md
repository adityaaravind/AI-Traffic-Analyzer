# ai-traffic-analyzer-mini

A minimal AI-powered network traffic analyzer.

## Features
- Capture packets (live via `pyshark`/tshark) or read from a `.pcap` file.
- Extract basic metrics: packet/byte totals, protocol counts, top IPs & ports, TCP flags.
- Send a structured summary to the OpenAI API for anomaly detection & pattern description.
- Generate a dark-themed HTML report.

## Requirements
- Python **3.9+**
- Tshark installed (for live capture via pyshark)
- Dependencies (see `requirements.txt`):
  - `pyshark`
  - `jinja2`
  - `requests`
  - `python-dotenv`

## Quick Start (no Docker)

1. **Install system dependency**

   On Debian/Ubuntu:
   ```bash
   sudo apt-get update && sudo apt-get install -y tshark
   ```

   On macOS (Homebrew):
   ```bash
   brew install wireshark
   ```

   > Live capture may require privileges. On Linux, you may allow non-root capture by running `sudo dpkg-reconfigure wireshark-common && sudo usermod -a -G wireshark $USER` then re-login.

2. **Create & activate a virtualenv (recommended)**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Create a `.env` file** in the project root (next to `src/`):
   ```env
   OPENAI_API_KEY=sk-...
   OPENAI_MODEL=gpt-4o-mini
   ```

4. **Run (from project root)**

   - **Offline (pcap file):**
     ```bash
     python -m src.main --pcap path/to/file.pcap --out report.html
     ```

   - **Live capture for N seconds on interface `eth0`:**
     ```bash
     python -m src.main --duration 15 --iface eth0 --filter "tcp or udp or icmp" --out report.html
     ```

   If no API key is set, the tool prints `AI disabled` and generates the report without the AI section.

## Docker

This repo includes a `Dockerfile` that installs tshark and runs the analyzer.

> **Note:** To capture live traffic from the host, you typically need:
> - `--net=host` (on Linux) so the container can see host interfaces
> - `--cap-add=NET_ADMIN --cap-add=NET_RAW` to allow capture
> - An interface name that exists in the container's network namespace (with `--net=host`, host names are visible)

### Build
```bash
docker build -t ai-traffic-analyzer-mini:latest .
```

### Run (offline PCAP)
```bash
docker run --rm -v $(pwd):/app ai-traffic-analyzer-mini:latest \
  python -m src.main --pcap ./samples/example.pcap --out report.html
```

### Run (live capture)
```bash
docker run --rm --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v $(pwd):/app --env-file ./.env ai-traffic-analyzer-mini:latest \
  python -m src.main --duration 10 --iface eth0 --filter "tcp or udp or icmp" --out report.html
```

- Place your `.env` file in the **project root** and pass it with `--env-file ./.env` as shown above.

## Outputs
- `report.html` — a self-contained dark-themed HTML report with:
  - Traffic overview stats
  - Protocol breakdown
  - Top talkers & ports
  - TCP flags
  - AI summary & tags

## Notes
- `pyshark` requires tshark underneath. Offline PCAP analysis works without extra privileges.
- Live capture requires privileges/capabilities as noted.
- The OpenAI model defaults to `gpt-4o-mini` if `OPENAI_MODEL` is not set.
- The AI output is parsed heuristically. It expects a "Summary" section (3–6 bullet points) and a "Tags" line (comma-separated).

## License
MIT
