from __future__ import annotations

import asyncio
import ipaddress
import platform
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import psutil
from scapy.all import ARP, Ether, conf, srp


@dataclass
class Device:
    ip: ipaddress.IPv4Address
    mac: str
    hostname: Optional[str] = None


@dataclass
class InterfaceInfo:
    name: str
    ipv4: List[str]


class NetworkDetectionError(RuntimeError):
    pass


def get_network_cidr(interface: Optional[str] = None) -> str:
    """Derive the local IPv4 network CIDR from the default interface."""
    if interface is None:
        interface = _default_interface()

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


def _default_interface() -> str:
    """Pick a reasonable default interface across platforms."""
    try:
        return _default_gateway_interface()
    except NetworkDetectionError:
        pass

    local_ip = _default_interface_ip()
    return _find_interface_by_ip(local_ip)


def _default_interface_ip() -> str:
    """Discover the local IPv4 used for outbound traffic without sending packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError as exc:
        raise NetworkDetectionError("Could not detect local interface IP; pass --interface or --cidr explicitly") from exc


def _find_interface_by_ip(target_ip: str) -> str:
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == target_ip:
                return name
    raise NetworkDetectionError("Could not map detected IP to a local interface; pass --interface or --cidr explicitly")


def _resolve_iface_name(interface: Optional[str]) -> Optional[str]:
    """Resolve a user-friendly interface string to a scapy iface name/dev.

    On Windows, scapy ifaces are often truncated (e.g., "Intel(R) Wi-Fi 6_").
    We attempt exact match, then substring match, and return the dev/name scapy expects.
    """

    if interface is None:
        return None

    try:
        return conf.ifaces.dev_from_name(interface)
    except (KeyError, ValueError):
        pass

    lowered = interface.lower()
    for iface in conf.ifaces.values():
        if iface.name and lowered in iface.name.lower():
            # prefer dev if present; fall back to name
            return getattr(iface, "dev", None) or iface.name

    return interface


def list_interfaces() -> List[InterfaceInfo]:
    interfaces: List[InterfaceInfo] = []
    for name, addrs in psutil.net_if_addrs().items():
        ipv4_addrs: List[str] = []
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address:
                ipv4_addrs.append(addr.address)
        interfaces.append(InterfaceInfo(name=name, ipv4=ipv4_addrs))
    return interfaces


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


def scan_network(
    cidr: str,
    interface: Optional[str] = None,
    timeout: float = 2.0,
    retry: int = 1,
    use_ping_fallback: bool = True,
) -> List[Device]:
    """Perform an ARP sweep over the provided IPv4 CIDR block.

    On Windows Wi-Fi, some drivers block raw ARP; when enabled, a ping sweep + ARP cache parse is used as a fallback.
    """
    conf.verb = 0
    conf.use_pcap = platform.system() == "Windows"  # keep pcap on Windows; raw sockets are smoother elsewhere
    resolved_iface = _resolve_iface_name(interface)

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, retry=retry, iface=resolved_iface)

    devices: List[Device] = []
    for _, reply in answered:
        ip_addr = ipaddress.IPv4Address(reply.psrc)
        mac_addr = reply.hwsrc
        hostname = resolve_hostname(reply.psrc)
        devices.append(Device(ip=ip_addr, mac=mac_addr, hostname=hostname))

    if use_ping_fallback and len(devices) <= 1:
        # Some Windows Wi-Fi drivers block raw L2. Fall back: ping sweep + parse arp cache.
        fallback = _fallback_scan_via_arp_cache(cidr, timeout_ms=int(timeout * 1000))
        devices.extend([d for d in fallback if d.ip not in {dev.ip for dev in devices}])

    devices.sort(key=lambda device: int(device.ip))
    return devices


def _fallback_scan_via_arp_cache(cidr: str, timeout_ms: int = 500, max_concurrency: int = 64) -> List[Device]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    async def ping(ip: str) -> None:
        # Windows ping: -n 1 (one echo), -w timeout in ms
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout_ms),
            ip,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await proc.communicate()

    async def runner() -> None:
        sem = asyncio.Semaphore(max_concurrency)

        async def guarded(ip: str) -> None:
            async with sem:
                await ping(ip)

        await asyncio.gather(*(guarded(ip) for ip in hosts))

    try:
        asyncio.run(runner())
    except RuntimeError:
        # If already in an event loop, skip ping fan-out.
        pass

    return _parse_arp_cache(network)


def _parse_arp_cache(network: ipaddress.IPv4Network) -> List[Device]:
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, encoding="ascii", errors="ignore")
    except (FileNotFoundError, subprocess.SubprocessError):
        return []

    devices: List[Device] = []
    seen_ips: set[ipaddress.IPv4Address] = set()

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_str = parts[0]
        mac = parts[1] if len(parts) > 1 else None
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            continue

        if ip_obj not in network:
            continue
        if mac is None:
            continue
        if mac.startswith("ff-ff-ff") or mac.startswith("01-00-5e"):
            continue

        mac_norm = mac.replace("-", ":").lower()
        if mac_norm.startswith("ff:ff:ff"):
            continue
        if mac_norm.startswith("01:00:5e") or mac_norm.startswith("33:33"):
            continue

        if ip_obj in seen_ips:
            continue
        seen_ips.add(ip_obj)
        devices.append(Device(ip=ip_obj, mac=mac_norm, hostname=resolve_hostname(ip_str)))

    return devices
