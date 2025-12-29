import asyncio
import types

import pytest

from netscan.network import (
    NetworkDetectionError,
    _parse_arp_cache,
    get_network_cidr,
    list_interfaces,
    resolve_hostname,
)
import netscan.network as network


def test_get_network_cidr_unknown_interface():
    with pytest.raises(NetworkDetectionError):
        get_network_cidr("fake0")


def test_resolve_hostname_loopback():
    # Hostname lookup for loopback should either resolve or return None without raising.
    result = resolve_hostname("127.0.0.1")
    assert result is None or isinstance(result, str)


def test_list_interfaces(monkeypatch):
    addr_ipv4 = types.SimpleNamespace(family=2, address="192.168.1.10", netmask="255.255.255.0")
    addr_ipv6 = types.SimpleNamespace(family=23, address="fe80::1", netmask=None)

    def fake_net_if_addrs():
        return {
            "Ethernet": [addr_ipv4, addr_ipv6],
            "Loopback": [types.SimpleNamespace(family=2, address="127.0.0.1", netmask="255.0.0.0")],
        }

    monkeypatch.setattr("psutil.net_if_addrs", fake_net_if_addrs)

    interfaces = list_interfaces()
    names = {iface.name for iface in interfaces}
    assert "Ethernet" in names and "Loopback" in names
    ethernet = next(iface for iface in interfaces if iface.name == "Ethernet")
    assert ethernet.ipv4 == ["192.168.1.10"]


def test_scan_network_resolves_interface(monkeypatch):
    calls = {}

    class DummyIfaces:
        def __init__(self):
            self.values_data = [
                types.SimpleNamespace(name="Intel(R) Wi-Fi 6_", dev="NPF_{wifi}"),
                types.SimpleNamespace(name="Loopback", dev="lo0"),
            ]

        def dev_from_name(self, name):
            if name == "NPF_{wifi}":
                return "NPF_{wifi}"
            raise KeyError

        def values(self):
            return self.values_data

        def reload(self):
            return self

        def register_provider(self, provider):
            pass

    # isolate conf and srp changes
    monkeypatch.setattr(network.conf, "use_pcap", False)
    monkeypatch.setattr(network.conf, "ifaces", DummyIfaces())
    monkeypatch.setattr(network.platform, "system", lambda: "Windows")

    def fake_srp(packet, timeout, retry, iface):  # noqa: ARG001
        calls["iface"] = iface
        return [], []

    monkeypatch.setattr(network, "srp", fake_srp)

    asyncio.run(network.scan_network("192.168.1.0/24", interface="Wi-Fi", timeout=1, retry=0, use_ping_fallback=False))

    assert network.conf.use_pcap is True
    assert calls["iface"] == "NPF_{wifi}"


def test_parse_arp_cache_filters_network(monkeypatch):
    sample = """
Interface: 192.168.1.184 --- 0x15
  Internet Address      Physical Address      Type
  192.168.1.1           78-67-0e-f6-64-df     dynamic
  192.168.1.200         01-00-5e-00-00-fc     static
  10.0.0.5              00-11-22-33-44-55     dynamic
"""

    def fake_check_output(cmd, text, encoding, errors):  # noqa: ARG001
        return sample

    monkeypatch.setattr(network.subprocess, "check_output", fake_check_output)

    network_obj = network.ipaddress.ip_network("192.168.1.0/24")
    devices = asyncio.run(_parse_arp_cache(network_obj))

    assert [str(d.ip) for d in devices] == ["192.168.1.1"]
    assert devices[0].mac == "78:67:0e:f6:64:df"


def test_scan_network_can_disable_fallback(monkeypatch):
    calls = {"fallback": 0}

    def fake_srp(packet, timeout, retry, iface):  # noqa: ARG001
        return [], []

    async def fake_fallback(*args, **kwargs):  # noqa: ARG001
        calls["fallback"] += 1
        return []

    monkeypatch.setattr(network, "srp", fake_srp)
    monkeypatch.setattr(network, "_fallback_scan_via_arp_cache", fake_fallback)

    devices = asyncio.run(network.scan_network("192.168.1.0/30", use_ping_fallback=False))
    assert devices == []
    assert calls["fallback"] == 0
