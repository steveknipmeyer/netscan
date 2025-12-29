from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Optional

import psutil
from scapy.all import ARP, Ether, conf, srp


@dataclass
class Device:
    ip: ipaddress.IPv4Address
    mac: str
    hostname: Optional[str] = None


class NetworkDetectionError(RuntimeError):
    pass


def get_network_cidr(interface: Optional[str] = None) -> str:
    """Derive the local IPv4 network CIDR from the default gateway interface."""
    if interface is None:
        interface = _default_gateway_interface()

    ip_str, netmask = _interface_ipv4(interface)
    network = ipaddress.IPv4Network(f"{ip_str}/{netmask}", strict=False)
    return str(network)


def _default_gateway_interface() -> str:
    """Read the default gateway interface from /proc/net/route (Linux only)."""
    try:
        with open("/proc/net/route", "r", encoding="ascii") as route_file:
            next(route_file)  # skip header
            for line in route_file:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                iface, destination_hex, _gateway_hex, flags_hex = parts[0], parts[1], parts[2], parts[3]
                if destination_hex != "00000000":
                    continue  # not default route
                flags = int(flags_hex, 16)
                if flags & 2:  # RTF_GATEWAY
                    return iface
    except FileNotFoundError as exc:
        raise NetworkDetectionError("/proc/net/route not found; cannot detect default gateway") from exc

    raise NetworkDetectionError("No default IPv4 gateway found")


def _interface_ipv4(interface: str) -> tuple[str, str]:
    addrs = psutil.net_if_addrs().get(interface)
    if not addrs:
        raise NetworkDetectionError(f"Interface {interface} not found")

    for addr in addrs:
        if addr.family == socket.AF_INET:
            if not addr.address or not addr.netmask:
                raise NetworkDetectionError(f"Interface {interface} is missing IPv4 details")
            return addr.address, addr.netmask

    raise NetworkDetectionError(f"No IPv4 address found on interface {interface}")


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except socket.herror:
        return None


def scan_network(cidr: str, interface: Optional[str] = None, timeout: float = 2.0, retry: int = 1) -> List[Device]:
    """Perform an ARP sweep over the provided IPv4 CIDR block."""
    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, retry=retry, iface=interface)

    devices: List[Device] = []
    for _, reply in answered:
        ip_addr = ipaddress.IPv4Address(reply.psrc)
        mac_addr = reply.hwsrc
        hostname = resolve_hostname(reply.psrc)
        devices.append(Device(ip=ip_addr, mac=mac_addr, hostname=hostname))

    devices.sort(key=lambda device: int(device.ip))
    return devices
