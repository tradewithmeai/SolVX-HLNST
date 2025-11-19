"""PCAP-related CLI commands."""

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from pathlib import Path
from typing import Optional

from solvx_net.core.database import get_db
from solvx_net.core.models import Capture, Flow
from solvx_net.core.logging import get_logger
from solvx_net.pcap.importer import import_pcap_file

logger = get_logger(__name__)
console = Console()

pcap_app = typer.Typer(help="PCAP file management commands")


@pcap_app.command("import")
def pcap_import(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP file"),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Notes about this capture"),
):
    """Import a PCAP file into the database."""
    if not pcap_path.exists():
        console.print(f"[bold red]✗[/bold red] File not found: {pcap_path}")
        raise typer.Exit(1)

    console.print(f"[bold]Importing PCAP file:[/bold] {pcap_path}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Processing...", total=None)

            result = import_pcap_file(pcap_path, notes=notes)

            progress.update(task, completed=True)

        if result["success"]:
            console.print("\n[bold green]✓[/bold green] Import successful!")
            console.print(f"  Capture ID: [cyan]{result['capture_id']}[/cyan]")
            console.print(f"  Packets: [cyan]{result['num_packets']}[/cyan]")
            console.print(f"  Flows: [cyan]{result['num_flows']}[/cyan]")
            console.print(f"  Duration: [cyan]{result['duration_seconds']:.2f}s[/cyan]")
        else:
            console.print(f"[bold red]✗[/bold red] Import failed: {result.get('error')}")
            raise typer.Exit(1)

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Import failed: {e}")
        logger.error(f"PCAP import failed: {e}", exc_info=True)
        raise typer.Exit(1)


@pcap_app.command("list")
def pcap_list(
    limit: int = typer.Option(20, "--limit", "-l", help="Maximum number of captures to show"),
):
    """List imported PCAP captures."""
    try:
        with get_db() as db:
            captures = db.query(Capture).order_by(Capture.created_at.desc()).limit(limit).all()

            if not captures:
                console.print("[yellow]No captures found. Import a PCAP file first.[/yellow]")
                return

            table = Table(title=f"PCAP Captures (showing last {limit})")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Source", style="white")
            table.add_column("Packets", justify="right", style="green")
            table.add_column("Flows", justify="right", style="green")
            table.add_column("Start Time", style="blue")

            for capture in captures:
                table.add_row(
                    str(capture.id),
                    capture.type.value,
                    capture.source[-50:] if len(capture.source) > 50 else capture.source,
                    str(capture.num_packets),
                    str(capture.num_flows),
                    capture.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                )

            console.print(table)

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to list captures: {e}")
        raise typer.Exit(1)


@pcap_app.command("info")
def pcap_info(
    capture_id: int = typer.Argument(..., help="Capture ID"),
):
    """Show detailed information about a capture."""
    try:
        with get_db() as db:
            capture = db.query(Capture).filter(Capture.id == capture_id).first()

            if not capture:
                console.print(f"[bold red]✗[/bold red] Capture not found: {capture_id}")
                raise typer.Exit(1)

            console.print(f"\n[bold]Capture #{capture.id}[/bold]")
            console.print(f"  Type: [cyan]{capture.type.value}[/cyan]")
            console.print(f"  Source: [cyan]{capture.source}[/cyan]")
            console.print(f"  Packets: [cyan]{capture.num_packets}[/cyan]")
            console.print(f"  Flows: [cyan]{capture.num_flows}[/cyan]")
            console.print(f"  Start: [cyan]{capture.start_time}[/cyan]")
            console.print(f"  End: [cyan]{capture.end_time}[/cyan]")

            duration = (capture.end_time - capture.start_time).total_seconds()
            console.print(f"  Duration: [cyan]{duration:.2f}s[/cyan]")

            if capture.notes:
                console.print(f"  Notes: [cyan]{capture.notes}[/cyan]")

            # Get flow statistics
            flows = db.query(Flow).filter(Flow.capture_id == capture_id).all()

            if flows:
                console.print(f"\n[bold]Flow Statistics:[/bold]")

                # Protocol breakdown
                protocols = {}
                for flow in flows:
                    protocols[flow.protocol] = protocols.get(flow.protocol, 0) + 1

                console.print("  Protocols:")
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    console.print(f"    {proto}: [cyan]{count}[/cyan]")

                # Top talkers
                talkers = {}
                for flow in flows:
                    talkers[flow.src_ip] = talkers.get(flow.src_ip, 0) + flow.packet_count

                console.print("\n  Top 5 Source IPs:")
                for ip, count in sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:5]:
                    console.print(f"    {ip}: [cyan]{count}[/cyan] packets")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get capture info: {e}")
        logger.error(f"Failed to get capture info: {e}", exc_info=True)
        raise typer.Exit(1)


@pcap_app.command("delete")
def pcap_delete(
    capture_id: int = typer.Argument(..., help="Capture ID to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete a capture and its flows."""
    if not confirm:
        confirmed = typer.confirm(
            f"⚠️  Delete capture #{capture_id} and all its flows?",
            default=False,
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit(0)

    try:
        with get_db() as db:
            capture = db.query(Capture).filter(Capture.id == capture_id).first()

            if not capture:
                console.print(f"[bold red]✗[/bold red] Capture not found: {capture_id}")
                raise typer.Exit(1)

            db.delete(capture)
            db.commit()

            console.print(f"[bold green]✓[/bold green] Deleted capture #{capture_id}")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to delete capture: {e}")
        raise typer.Exit(1)
