from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .network import NetworkDetectionError, get_network_cidr, list_interfaces, scan_network

app = typer.Typer(help="Scan your local network and list discovered devices.")
console = Console()


def _run_scan(cidr: Optional[str], interface: Optional[str], timeout: float, retry: int, use_ping_fallback: bool) -> None:
    try:
        target_cidr = cidr or get_network_cidr(interface)
    except NetworkDetectionError as exc:
        console.print(f"[red]Network detection failed:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(f"Scanning {target_cidr}...")
    devices = scan_network(
        target_cidr,
        interface=interface,
        timeout=timeout,
        retry=retry,
        use_ping_fallback=use_ping_fallback,
    )

    if not devices:
        console.print("No devices responded.")
        raise typer.Exit(code=0)

    table = Table(title=f"Devices on {target_cidr}")
    table.add_column("IP", justify="left")
    table.add_column("MAC", justify="left")
    table.add_column("Hostname", justify="left")

    for device in devices:
        style = "red" if not device.hostname else None
        table.add_row(str(device.ip), device.mac, device.hostname or "", style=style)

    console.print(table)


@app.command()
def interfaces() -> None:
    """List detected interfaces and their IPv4 addresses."""
    table = Table(title="Interfaces")
    table.add_column("Name", justify="left")
    table.add_column("IPv4", justify="left")

    for iface in list_interfaces():
        ipv4_display = ", ".join(iface.ipv4) if iface.ipv4 else "-"
        table.add_row(iface.name, ipv4_display)

    console.print(table)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    cidr: Optional[str] = typer.Option(None, "--cidr", "-c", help="CIDR to scan, e.g., 192.168.1.0/24"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Interface to use for ARP requests"),
    timeout: float = typer.Option(2.0, help="Seconds to wait for replies"),
    retry: int = typer.Option(1, help="Retry count for ARP requests"),
    use_ping_fallback: bool = typer.Option(
        True,
        "--ping-fallback/--no-ping-fallback",
        help="If ARP returns nothing, try an ICMP sweep then read the ARP cache (helps on some Windows Wi-Fi drivers)",
    ),
) -> None:
    if ctx.invoked_subcommand is None:
        _run_scan(cidr, interface, timeout, retry, use_ping_fallback)


@app.command()
def scan(
    cidr: Optional[str] = typer.Option(None, "--cidr", "-c", help="CIDR to scan, e.g., 192.168.1.0/24"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Interface to use for ARP requests"),
    timeout: float = typer.Option(2.0, help="Seconds to wait for replies"),
    retry: int = typer.Option(1, help="Retry count for ARP requests"),
    use_ping_fallback: bool = typer.Option(
        True,
        "--ping-fallback/--no-ping-fallback",
        help="If ARP returns nothing, try an ICMP sweep then read the ARP cache (helps on some Windows Wi-Fi drivers)",
    ),
) -> None:
    _run_scan(cidr, interface, timeout, retry, use_ping_fallback)


if __name__ == "__main__":
    app()
