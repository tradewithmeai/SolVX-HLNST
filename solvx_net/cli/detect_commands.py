"""Detection engine CLI commands."""

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

from solvx_net.core.database import get_db
from solvx_net.core.logging import get_logger
from solvx_net.detections.base import DetectionEngine
from solvx_net.detections.rogue_device import RogueDeviceDetector
from solvx_net.detections.arp_spoof import ARPSpoofDetector
from solvx_net.detections.dns_leak import DNSLeakDetector

logger = get_logger(__name__)
console = Console()

detect_app = typer.Typer(help="Detection engine commands")


@detect_app.command("run")
def detect_run(
    detector: Optional[str] = typer.Option(
        None,
        "--detector",
        "-d",
        help="Run specific detector (rogue/arp/dns), or all if not specified",
    ),
):
    """Run detection engines to find security issues."""
    try:
        with get_db() as db:
            engine = DetectionEngine(db)

            # Register detectors
            engine.register_detector(RogueDeviceDetector(db))
            engine.register_detector(ARPSpoofDetector(db))
            engine.register_detector(DNSLeakDetector(db))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Running detections...", total=None)

                if detector:
                    # Run specific detector
                    alerts = engine.run_detector_by_name(detector)
                else:
                    # Run all detectors
                    alerts = engine.run_all()

                progress.update(task, completed=True)

            if alerts:
                console.print(f"\n[bold yellow]⚠️  Found {len(alerts)} security issues:[/bold yellow]\n")

                for alert in alerts:
                    severity_color = {
                        "critical": "bold red",
                        "high": "red",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(alert.severity.value, "white")

                    console.print(f"  [{severity_color}]●[/{severity_color}] {alert.title}")
                    console.print(f"    {alert.description[:100]}...")
                    console.print(f"    [dim]Alert #{alert.id} | Score: {alert.score}/100[/dim]\n")

                console.print(f"Use [cyan]solvx alerts list[/cyan] to view all alerts")
                console.print(f"Use [cyan]solvx alerts info <id>[/cyan] for details")
            else:
                console.print("[bold green]✓[/bold green] No security issues detected")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Detection failed: {e}")
        logger.error(f"Detection failed: {e}", exc_info=True)
        raise typer.Exit(1)


@detect_app.command("list")
def detect_list():
    """List available detection engines."""
    console.print("[bold]Available Detection Engines:[/bold]\n")

    detectors = [
        {
            "name": "Rogue Device Detector",
            "id": "rogue",
            "description": "Detects unauthorized or suspicious devices on the network",
            "checks": [
                "Blocked devices appearing on network",
                "Unknown devices with high activity",
                "New devices in trusted IP ranges",
                "Port scanning from unknown vendors",
            ],
        },
        {
            "name": "ARP Spoof Detector",
            "id": "arp",
            "description": "Detects ARP spoofing and potential MITM attacks",
            "checks": [
                "IP-MAC conflicts",
                "Gateway MAC address changes",
                "Excessive ARP replies",
                "Multiple IPs claimed by same MAC",
            ],
        },
        {
            "name": "DNS Leak Detector",
            "id": "dns",
            "description": "Detects DNS leaks and unauthorized DNS queries",
            "checks": [
                "Queries to unauthorized DNS servers",
                "Use of public DNS when not allowed",
                "Excessive DNS queries (tunneling)",
                "Unknown DNS servers",
            ],
        },
    ]

    for det in detectors:
        console.print(f"[cyan]{det['name']}[/cyan] (ID: [bold]{det['id']}[/bold])")
        console.print(f"  {det['description']}")
        console.print(f"  Checks:")
        for check in det['checks']:
            console.print(f"    • {check}")
        console.print()

    console.print("[dim]Run with:[/dim] [cyan]solvx detect run[/cyan] (all) or [cyan]solvx detect run --detector <id>[/cyan]")


@detect_app.command("status")
def detect_status():
    """Show detection engine status and recent alerts."""
    try:
        with get_db() as db:
            from solvx_net.core.models import Alert, AlertStatus
            from datetime import datetime, timedelta

            # Get alert statistics
            recent_time = datetime.utcnow() - timedelta(hours=24)

            total_alerts = db.query(Alert).count()
            recent_alerts = db.query(Alert).filter(Alert.created_at > recent_time).count()
            open_alerts = db.query(Alert).filter(Alert.status == AlertStatus.OPEN).count()
            critical_alerts = db.query(Alert).filter(
                Alert.severity == "critical",
                Alert.status == AlertStatus.OPEN,
            ).count()

            console.print("[bold]Detection Engine Status:[/bold]\n")
            console.print(f"  Total Alerts: [cyan]{total_alerts}[/cyan]")
            console.print(f"  Recent (24h): [cyan]{recent_alerts}[/cyan]")
            console.print(f"  Open: [yellow]{open_alerts}[/yellow]")
            console.print(f"  Critical Open: [red]{critical_alerts}[/red]")

            if critical_alerts > 0:
                console.print(f"\n[bold red]⚠️  {critical_alerts} critical alerts require attention![/bold red]")
                console.print("Use [cyan]solvx alerts list --severity critical --status open[/cyan] to view")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get status: {e}")
        raise typer.Exit(1)
