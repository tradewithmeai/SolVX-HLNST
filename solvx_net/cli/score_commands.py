"""Threat scoring CLI commands."""

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional

from solvx_net.core.database import get_db
from solvx_net.core.logging import get_logger
from solvx_net.analysis.scoring import ThreatScorer

logger = get_logger(__name__)
console = Console()

score_app = typer.Typer(help="Threat scoring commands")


@score_app.command("calculate")
def score_calculate(
    device_id: Optional[int] = typer.Option(None, "--device", "-d", help="Score specific device"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save scores to database"),
):
    """Calculate threat scores for devices."""
    try:
        with get_db() as db:
            scorer = ThreatScorer(db)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Calculating threat scores...", total=None)

                if device_id:
                    # Score specific device
                    score_data = scorer.score_device(device_id)
                    scores = [score_data]
                else:
                    # Score all devices
                    scores = scorer.score_all_devices()

                if save:
                    count = scorer.save_scores()

                progress.update(task, completed=True)

            # Display results
            console.print(f"\n[bold]Threat Score Results:[/bold]\n")

            table = Table()
            table.add_column("Device", style="cyan")
            table.add_column("Score", style="white")
            table.add_column("Risk", style="red")
            table.add_column("Alerts", style="yellow")
            table.add_column("Trust", style="blue")

            for score_data in sorted(scores, key=lambda x: x["score"], reverse=True)[:20]:
                # Color code risk level
                risk = score_data["risk_level"]
                risk_str = {
                    "safe": "[green]safe[/green]",
                    "low": "[blue]low[/blue]",
                    "medium": "[yellow]medium[/yellow]",
                    "high": "[red]high[/red]",
                }.get(risk, risk)

                # Color code score
                score_val = score_data["score"]
                if score_val >= 75:
                    score_str = f"[bold red]{score_val}[/bold red]"
                elif score_val >= 50:
                    score_str = f"[yellow]{score_val}[/yellow]"
                elif score_val >= 20:
                    score_str = f"[blue]{score_val}[/blue]"
                else:
                    score_str = f"[green]{score_val}[/green]"

                table.add_row(
                    f"#{score_data['device_id']}",
                    score_str,
                    risk_str,
                    str(score_data["alert_count"]),
                    score_data["trust_level"],
                )

            console.print(table)

            if len(scores) > 20:
                console.print(f"\n[dim]... and {len(scores) - 20} more devices[/dim]")

            if save:
                console.print(f"\n[bold green]✓[/bold green] Scores saved to database")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Scoring failed: {e}")
        logger.error(f"Scoring failed: {e}", exc_info=True)
        raise typer.Exit(1)


@score_app.command("network")
def score_network():
    """Show overall network health score."""
    try:
        with get_db() as db:
            scorer = ThreatScorer(db)
            health = scorer.calculate_network_health()

            console.print("\n[bold]Network Health Report:[/bold]\n")

            # Color code health status
            status = health["health_status"]
            status_str = {
                "excellent": "[bold green]EXCELLENT[/bold green]",
                "good": "[green]GOOD[/green]",
                "fair": "[yellow]FAIR[/yellow]",
                "poor": "[red]POOR[/red]",
                "critical": "[bold red]CRITICAL[/bold red]",
            }.get(status, status.upper())

            console.print(f"  Health Status: {status_str}")

            # Color code network score
            score = health["network_score"]
            if score < 20:
                score_str = f"[bold green]{score}[/bold green]"
            elif score < 50:
                score_str = f"[green]{score}[/green]"
            elif score < 75:
                score_str = f"[yellow]{score}[/yellow]"
            else:
                score_str = f"[bold red]{score}[/bold red]"

            console.print(f"  Network Score: {score_str}/100")

            console.print(f"\n[bold]Device Risk Distribution:[/bold]")
            console.print(f"  [green]●[/green] Safe: {health['safe_devices']}")
            console.print(f"  [blue]●[/blue] Low Risk: {health['low_risk_devices']}")
            console.print(f"  [yellow]●[/yellow] Medium Risk: {health['medium_risk_devices']}")
            console.print(f"  [red]●[/red] High Risk: {health['high_risk_devices']}")
            console.print(f"  Total Devices: [cyan]{health['total_devices']}[/cyan]")

            console.print(f"\n[bold]Alert Statistics (24h):[/bold]")
            console.print(f"  Total Alerts: [cyan]{health['total_alerts_24h']}[/cyan]")
            console.print(f"  Critical Open: [red]{health['critical_open_alerts']}[/red]")

            if health["critical_open_alerts"] > 0:
                console.print(f"\n[bold red]⚠️  {health['critical_open_alerts']} critical alerts require immediate attention![/bold red]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get network health: {e}")
        raise typer.Exit(1)


@score_app.command("history")
def score_history(
    device_id: Optional[int] = typer.Option(None, "--device", "-d", help="Device ID (network-wide if not specified)"),
    days: int = typer.Option(7, "--days", help="Number of days of history"),
):
    """Show threat score history."""
    try:
        with get_db() as db:
            scorer = ThreatScorer(db)
            history = scorer.get_score_history(device_id=device_id, days=days)

            if not history:
                console.print("[yellow]No score history found[/yellow]")
                return

            title = f"Score History (Last {days} days)"
            if device_id:
                title += f" - Device #{device_id}"
            else:
                title += " - Network-Wide"

            console.print(f"\n[bold]{title}:[/bold]\n")

            table = Table()
            table.add_column("Date/Time", style="cyan")
            table.add_column("Score", style="white")
            table.add_column("Change", style="yellow")

            prev_score = None
            for entry in history[-20:]:  # Last 20 entries
                score = entry["score"]

                # Calculate change
                change_str = ""
                if prev_score is not None:
                    change = score - prev_score
                    if change > 0:
                        change_str = f"[red]+{change:.1f}[/red]"
                    elif change < 0:
                        change_str = f"[green]{change:.1f}[/green]"
                    else:
                        change_str = "—"

                # Color code score
                if score >= 75:
                    score_str = f"[bold red]{score:.1f}[/bold red]"
                elif score >= 50:
                    score_str = f"[yellow]{score:.1f}[/yellow]"
                elif score >= 20:
                    score_str = f"[blue]{score:.1f}[/blue]"
                else:
                    score_str = f"[green]{score:.1f}[/green]"

                table.add_row(
                    entry["timestamp"][:19],  # Trim to datetime
                    score_str,
                    change_str,
                )

                prev_score = score

            console.print(table)

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get score history: {e}")
        raise typer.Exit(1)


@score_app.command("top")
def score_top(
    count: int = typer.Option(10, "--count", "-n", help="Number of devices to show"),
):
    """Show top threat devices."""
    try:
        with get_db() as db:
            scorer = ThreatScorer(db)
            scores = scorer.score_all_devices()

            # Sort by score descending
            top_devices = sorted(scores, key=lambda x: x["score"], reverse=True)[:count]

            console.print(f"\n[bold]Top {count} Threat Devices:[/bold]\n")

            for i, score_data in enumerate(top_devices, 1):
                device_id = score_data["device_id"]
                score = score_data["score"]
                risk = score_data["risk_level"]

                # Get device info
                from solvx_net.core.models import Device
                device = db.query(Device).filter(Device.id == device_id).first()

                console.print(f"[bold]{i}. Device #{device_id}[/bold]")
                if device:
                    console.print(f"   MAC: {device.mac_address} | Vendor: {device.vendor or 'Unknown'}")
                console.print(f"   Score: [red]{score}[/red] | Risk: [red]{risk.upper()}[/red] | Alerts: {score_data['alert_count']}")

                if score_data["breakdown"]:
                    console.print(f"   Threats: {', '.join(score_data['breakdown'].keys())}")

                console.print()

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get top threats: {e}")
        raise typer.Exit(1)
