You’re hitting two separate issues: (1) uv is seeing the wrong venv, and (2) scapy needs raw-socket privileges.

Use the right venv with uv: activate the project venv, then ask uv to use it: source .venv/bin/activate then uv run --active netscan (the --active flag makes uv honor the currently activated .venv instead of the stale VIRTUAL_ENV=/home/stephen/projects/scan/.venv).
Permissions for ARP/pcap: scapy’s srp needs CAP_NET_RAW (and often CAP_NET_ADMIN) or root. Easiest: run with sudo while preserving PATH so uv is found: sudo env "PATH=$PATH" uv run --active netscan.
If you prefer non-root, grant capabilities to the venv Python:
sudo setcap cap_net_raw,cap_net_admin+eip "$(realpath .venv/bin/python3.13)"
Then run as your user: uv run --active netscan.
If you ever reinstall the venv, you’ll need to re-run the setcap.

#6 was used to assign privileges to python3.13.