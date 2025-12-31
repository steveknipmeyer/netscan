from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

import psutil
try:
    from manuf import manuf
except ImportError:  # pragma: no cover - dependency declared but guard for resilience
    manuf = None
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


@dataclass
class Device:
    ip: ipaddress.IPv4Address
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None


@dataclass
class InterfaceInfo:
    name: str
    ipv4: List[str]


class NetworkDetectionError(RuntimeError):
    pass


_vendor_parser: Optional["manuf.MacParser"] = None
_vendor_cache: dict[str, Optional[str]] = {}


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
    conf.use_pcap = True  # needed on Windows for layer-2 sends
    resolved_iface = _resolve_iface_name(interface)

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(packet, timeout=timeout, retry=retry, iface=resolved_iface)

    devices: List[Device] = []
    for _, reply in answered:
        ip_addr = ipaddress.IPv4Address(reply.psrc)
        mac_addr = reply.hwsrc
        devices.append(Device(ip=ip_addr, mac=mac_addr, hostname=None))

    if use_ping_fallback and len(devices) <= 1:
        # Some Windows Wi-Fi drivers block raw L2. Fall back: ping sweep + parse arp cache.
        fallback = _fallback_scan_via_arp_cache(cidr, timeout_ms=int(timeout * 1000))
        devices.extend([d for d in fallback if d.ip not in {dev.ip for dev in devices}])

    _resolve_hostnames(devices)
    _resolve_vendors(devices)
    devices.sort(key=lambda device: int(device.ip))
    return devices


def _resolve_hostnames(devices: List[Device]) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_device = {executor.submit(resolve_hostname, str(d.ip)): d for d in devices}
        for future in concurrent.futures.as_completed(future_to_device):
            device = future_to_device[future]
            try:
                device.hostname = future.result()
            except Exception:
                pass


def _get_vendor_parser() -> Optional["manuf.MacParser"]:
    global _vendor_parser
    if manuf is None:
        return None
    if _vendor_parser is None:
        _vendor_parser = manuf.MacParser()
    return _vendor_parser


def lookup_vendor(mac: str) -> Optional[str]:
    normalized = mac.replace("-", ":").lower()
    if normalized in _vendor_cache:
        return _vendor_cache[normalized]

    parser = _get_vendor_parser()
    if parser is None:
        _vendor_cache[normalized] = None
        return None

    try:
        vendor = parser.get_manuf(normalized) or parser.get_comment(normalized)
    except Exception:
        vendor = None

    cleaned = vendor.strip() if vendor else None
    _vendor_cache[normalized] = cleaned or None
    return _vendor_cache[normalized]


def _resolve_vendors(devices: List[Device]) -> None:
    for device in devices:
        device.vendor = lookup_vendor(device.mac)


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
        devices.append(Device(ip=ip_obj, mac=mac_norm, hostname=None))

    return devices
