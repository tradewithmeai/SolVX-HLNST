"""Device management CLI commands."""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional

from solvx_net.core.database import get_db
from solvx_net.core.models import Device, TrustLevel, Flow
from solvx_net.core.logging import get_logger
from solvx_net.fingerprinting.resolver import DeviceResolver
from solvx_net.fingerprinting.fingerprinter import DeviceFingerprinter

logger = get_logger(__name__)
console = Console()

device_app = typer.Typer(help="Device inventory management commands")


@device_app.command("list")
def device_list(
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of devices to show"),
    trust_level: Optional[str] = typer.Option(None, "--trust", help="Filter by trust level"),
):
    """List discovered devices."""
    try:
        with get_db() as db:
            query = db.query(Device).order_by(Device.last_seen.desc())

            if trust_level:
                query = query.filter(Device.trust_level == trust_level)

            devices = query.limit(limit).all()

            if not devices:
                console.print("[yellow]No devices found. Import a PCAP file first.[/yellow]")
                return

            table = Table(title=f"Discovered Devices (showing {len(devices)})")
            table.add_column("ID", style="cyan")
            table.add_column("MAC Address", style="white")
            table.add_column("IP Addresses", style="magenta")
            table.add_column("Vendor", style="green")
            table.add_column("OS", style="blue")
            table.add_column("Trust", style="yellow")
            table.add_column("Last Seen", style="white")

            for device in devices:
                ips = ", ".join(device.ip_addresses[:3]) if device.ip_addresses else "N/A"
                if len(device.ip_addresses) > 3:
                    ips += f" (+{len(device.ip_addresses) - 3})"

                table.add_row(
                    str(device.id),
                    device.mac_address,
                    ips,
                    device.vendor or "Unknown",
                    device.os_guess or "Unknown",
                    device.trust_level.value,
                    device.last_seen.strftime("%Y-%m-%d %H:%M"),
                )

            console.print(table)
            console.print(f"\nTotal devices: [cyan]{len(devices)}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to list devices: {e}")
        logger.error(f"Failed to list devices: {e}", exc_info=True)
        raise typer.Exit(1)


@device_app.command("info")
def device_info(
    device_id: int = typer.Argument(..., help="Device ID"),
):
    """Show detailed information about a device."""
    try:
        with get_db() as db:
            device = db.query(Device).filter(Device.id == device_id).first()

            if not device:
                console.print(f"[bold red]✗[/bold red] Device not found: {device_id}")
                raise typer.Exit(1)

            console.print(f"\n[bold]Device #{device.id}[/bold]")
            console.print(f"  MAC Address: [cyan]{device.mac_address}[/cyan]")
            console.print(f"  Vendor: [cyan]{device.vendor or 'Unknown'}[/cyan]")
            console.print(f"  OS Guess: [cyan]{device.os_guess or 'Unknown'}[/cyan]")
            console.print(f"  Trust Level: [cyan]{device.trust_level.value}[/cyan]")

            if device.hostname:
                console.print(f"  Hostname: [cyan]{device.hostname}[/cyan]")

            if device.ip_addresses:
                console.print(f"  IP Addresses:")
                for ip in device.ip_addresses:
                    console.print(f"    • {ip}")

            if device.tags:
                console.print(f"  Tags: {', '.join(device.tags)}")

            console.print(f"\n  First Seen: [cyan]{device.first_seen}[/cyan]")
            console.print(f"  Last Seen: [cyan]{device.last_seen}[/cyan]")

            # Get flow statistics
            flows_src = db.query(Flow).filter(Flow.src_device_id == device_id).count()
            flows_dst = db.query(Flow).filter(Flow.dst_device_id == device_id).count()

            console.print(f"\n[bold]Traffic Statistics:[/bold]")
            console.print(f"  Flows as source: [cyan]{flows_src}[/cyan]")
            console.print(f"  Flows as destination: [cyan]{flows_dst}[/cyan]")
            console.print(f"  Total flows: [cyan]{flows_src + flows_dst}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get device info: {e}")
        logger.error(f"Failed to get device info: {e}", exc_info=True)
        raise typer.Exit(1)


@device_app.command("trust")
def device_trust(
    device_id: int = typer.Argument(..., help="Device ID"),
    level: str = typer.Argument(..., help="Trust level (trusted/guest/unknown/blocked)"),
):
    """Set device trust level."""
    try:
        trust_level = TrustLevel(level.lower())
    except ValueError:
        console.print(f"[bold red]✗[/bold red] Invalid trust level: {level}")
        console.print("Valid levels: trusted, guest, unknown, blocked")
        raise typer.Exit(1)

    try:
        with get_db() as db:
            device = db.query(Device).filter(Device.id == device_id).first()

            if not device:
                console.print(f"[bold red]✗[/bold red] Device not found: {device_id}")
                raise typer.Exit(1)

            device.trust_level = trust_level
            db.commit()

            console.print(
                f"[bold green]✓[/bold green] Set device {device_id} "
                f"trust level to [cyan]{level}[/cyan]"
            )

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to update trust level: {e}")
        raise typer.Exit(1)


@device_app.command("tag")
def device_tag(
    device_id: int = typer.Argument(..., help="Device ID"),
    tag: str = typer.Argument(..., help="Tag to add"),
    remove: bool = typer.Option(False, "--remove", "-r", help="Remove tag instead of adding"),
):
    """Add or remove tags from a device."""
    try:
        with get_db() as db:
            resolver = DeviceResolver(db)

            if remove:
                resolver.remove_device_tag(device_id, tag)
                console.print(
                    f"[bold green]✓[/bold green] Removed tag '[cyan]{tag}[/cyan]' "
                    f"from device {device_id}"
                )
            else:
                resolver.add_device_tag(device_id, tag)
                console.print(
                    f"[bold green]✓[/bold green] Added tag '[cyan]{tag}[/cyan]' "
                    f"to device {device_id}"
                )

            db.commit()

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to update tags: {e}")
        raise typer.Exit(1)


@device_app.command("fingerprint")
def device_fingerprint(
    device_id: Optional[int] = typer.Option(None, "--device", "-d", help="Device ID (or all)"),
):
    """Fingerprint devices to identify type and OS."""
    try:
        with get_db() as db:
            fingerprinter = DeviceFingerprinter(db)

            if device_id:
                # Fingerprint specific device
                device = db.query(Device).filter(Device.id == device_id).first()
                if not device:
                    console.print(f"[bold red]✗[/bold red] Device not found: {device_id}")
                    raise typer.Exit(1)

                console.print(f"Fingerprinting device {device_id}...")
                result = fingerprinter.fingerprint_device(device)
                db.commit()

                console.print(f"\n[bold green]✓[/bold green] Fingerprinting complete:")
                console.print(f"  Device Type: [cyan]{result['device_type']}[/cyan]")
                console.print(f"  OS: [cyan]{result['os_guess'] or 'Unknown'}[/cyan]")
                console.print(f"  Vendor: [cyan]{result['vendor'] or 'Unknown'}[/cyan]")
                console.print(f"  Confidence: [cyan]{result['confidence']}[/cyan]")
                if result.get("tags"):
                    console.print(f"  Tags: {', '.join(result['tags'])}")

            else:
                # Fingerprint all devices
                console.print("Fingerprinting all devices...")
                results = fingerprinter.fingerprint_all_devices()

                console.print(f"\n[bold green]✓[/bold green] Fingerprinted {len(results)} devices")

                # Summary table
                table = Table(title="Fingerprinting Results")
                table.add_column("Device ID", style="cyan")
                table.add_column("Type", style="green")
                table.add_column("OS", style="blue")
                table.add_column("Confidence", style="yellow")

                for result in results[:20]:  # Show first 20
                    table.add_row(
                        str(result["device_id"]),
                        result["device_type"],
                        result["os_guess"] or "Unknown",
                        result["confidence"],
                    )

                console.print(table)
                if len(results) > 20:
                    console.print(f"\n... and {len(results) - 20} more devices")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Fingerprinting failed: {e}")
        logger.error(f"Fingerprinting failed: {e}", exc_info=True)
        raise typer.Exit(1)


@device_app.command("delete")
def device_delete(
    device_id: int = typer.Argument(..., help="Device ID to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete a device from inventory."""
    if not confirm:
        confirmed = typer.confirm(
            f"⚠️  Delete device #{device_id}?",
            default=False,
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit(0)

    try:
        with get_db() as db:
            device = db.query(Device).filter(Device.id == device_id).first()

            if not device:
                console.print(f"[bold red]✗[/bold red] Device not found: {device_id}")
                raise typer.Exit(1)

            db.delete(device)
            db.commit()

            console.print(f"[bold green]✓[/bold green] Deleted device #{device_id}")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to delete device: {e}")
        raise typer.Exit(1)
