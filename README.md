# NetScan

Local ARP-based network scanner CLI managed with uv. It discovers devices on your LAN and reports their IP, MAC, and hostname when available.

## Prerequisites

- Python 3.9+
- [uv](https://github.com/astral-sh/uv) installed (e.g., `curl -Ls https://astral.sh/uv/install.sh | sh`)
- Permission to send ARP packets (run with sudo or grant CAP_NET_RAW to your Python binary)

## Setup

```bash
# Install dependencies and create the uv-managed environment
uv sync

# (Optional) include dev extras for tests
uv sync --extra dev
```

## Usage

```bash
# Scan the default network inferred from your default gateway
uv run netscan

# Scan a specific CIDR and interface
uv run netscan --cidr 192.168.1.0/24 --interface eth0

# On Windows, interface names may be truncated (e.g., "Intel(R) Wi-Fi 6_");
# the scanner will match substrings, so --interface "Wi-Fi" works.

# Disable the Windows ping/ARP-cache fallback if you only want raw ARP results
uv run netscan --cidr 192.168.1.0/24 --interface "Wi-Fi" --no-ping-fallback

# List interfaces and their IPv4 addresses
uv run netscan interfaces

# You can also call the explicit subcommand form if you prefer
uv run netscan scan --cidr 192.168.1.0/24 --interface eth0
```

The tool performs an ARP sweep, so it only discovers devices on the local broadcast domain.

On Windows Wi-Fi, some drivers block raw ARP. If ARP returns only your host, the tool falls back to a quick ICMP ping sweep and then reads the OS ARP cache to list peers on the same subnet.

## Testing

```bash
uv run pytest
```

## Notes

- ARP scans are limited to IPv4 on the local network.
- Hostname resolution uses reverse DNS; many devices may not return a hostname.
- Default gateway detection reads /proc/net/route (Linux). On other OSes, pass --interface/--cidr explicitly.
