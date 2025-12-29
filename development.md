    sudo env "PATH=$PATH" uv run netscan --cidr 172.25.112.0/24 --timeout 1 --retry 0 

If you prefer non-root, grant capabilities to the venv Python:
sudo setcap cap_net_raw,cap_net_admin+eip "$(realpath .venv/bin/python3.13)"

    uv run netscan --cidr 172.25.112.0/24 --timeout 1 --retry 0 

If you ever reinstall the venv, you’ll need to re-run the setcap.

