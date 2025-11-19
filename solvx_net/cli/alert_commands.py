"""Alert management CLI commands."""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional

from solvx_net.core.database import get_db
from solvx_net.core.models import Alert, AlertStatus, AlertSeverity, AlertType
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)
console = Console()

alert_app = typer.Typer(help="Alert management commands")


@alert_app.command("list")
def alert_list(
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of alerts to show"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status (open/acknowledged/resolved)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity (low/medium/high/critical)"),
    alert_type: Optional[str] = typer.Option(None, "--type", help="Filter by alert type"),
):
    """List security alerts."""
    try:
        with get_db() as db:
            query = db.query(Alert).order_by(Alert.created_at.desc())

            if status:
                query = query.filter(Alert.status == AlertStatus(status.lower()))
            if severity:
                query = query.filter(Alert.severity == AlertSeverity(severity.lower()))
            if alert_type:
                query = query.filter(Alert.alert_type == AlertType(alert_type.upper()))

            alerts = query.limit(limit).all()

            if not alerts:
                console.print("[yellow]No alerts found.[/yellow]")
                return

            table = Table(title=f"Security Alerts (showing {len(alerts)})")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Severity", style="red")
            table.add_column("Title", style="white")
            table.add_column("Device", style="blue")
            table.add_column("Status", style="green")
            table.add_column("Created", style="white")

            for alert in alerts:
                device_str = f"#{alert.device_id}" if alert.device_id else "N/A"

                # Color code severity
                severity_str = alert.severity.value
                if alert.severity == AlertSeverity.CRITICAL:
                    severity_str = f"[bold red]{severity_str}[/bold red]"
                elif alert.severity == AlertSeverity.HIGH:
                    severity_str = f"[red]{severity_str}[/red]"
                elif alert.severity == AlertSeverity.MEDIUM:
                    severity_str = f"[yellow]{severity_str}[/yellow]"

                table.add_row(
                    str(alert.id),
                    alert.alert_type.value,
                    severity_str,
                    alert.title[:50] + "..." if len(alert.title) > 50 else alert.title,
                    device_str,
                    alert.status.value,
                    alert.created_at.strftime("%Y-%m-%d %H:%M"),
                )

            console.print(table)

            # Summary statistics
            total = len(alerts)
            open_count = sum(1 for a in alerts if a.status == AlertStatus.OPEN)
            critical_count = sum(1 for a in alerts if a.severity == AlertSeverity.CRITICAL)

            console.print(f"\nTotal: [cyan]{total}[/cyan] | "
                         f"Open: [yellow]{open_count}[/yellow] | "
                         f"Critical: [red]{critical_count}[/red]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to list alerts: {e}")
        logger.error(f"Failed to list alerts: {e}", exc_info=True)
        raise typer.Exit(1)


@alert_app.command("info")
def alert_info(
    alert_id: int = typer.Argument(..., help="Alert ID"),
):
    """Show detailed information about an alert."""
    try:
        with get_db() as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()

            if not alert:
                console.print(f"[bold red]✗[/bold red] Alert not found: {alert_id}")
                raise typer.Exit(1)

            console.print(f"\n[bold]Alert #{alert.id}[/bold]")
            console.print(f"  Type: [cyan]{alert.alert_type.value}[/cyan]")
            console.print(f"  Severity: [red]{alert.severity.value}[/red]")
            console.print(f"  Status: [cyan]{alert.status.value}[/cyan]")
            console.print(f"  Score: [cyan]{alert.score}/100[/cyan]")

            if alert.device_id:
                console.print(f"  Device: [cyan]#{alert.device_id}[/cyan]")

            console.print(f"\n  [bold]Title:[/bold] {alert.title}")
            console.print(f"\n  [bold]Description:[/bold]\n  {alert.description}")

            console.print(f"\n  Created: [cyan]{alert.created_at}[/cyan]")
            console.print(f"  Updated: [cyan]{alert.updated_at}[/cyan]")

            if alert.evidence:
                console.print(f"\n  [bold]Evidence:[/bold]")
                for key, value in alert.evidence.items():
                    console.print(f"    {key}: [cyan]{value}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to get alert info: {e}")
        logger.error(f"Failed to get alert info: {e}", exc_info=True)
        raise typer.Exit(1)


@alert_app.command("acknowledge")
def alert_acknowledge(
    alert_id: int = typer.Argument(..., help="Alert ID to acknowledge"),
):
    """Acknowledge an alert."""
    try:
        with get_db() as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()

            if not alert:
                console.print(f"[bold red]✗[/bold red] Alert not found: {alert_id}")
                raise typer.Exit(1)

            alert.status = AlertStatus.ACKNOWLEDGED
            db.commit()

            console.print(f"[bold green]✓[/bold green] Alert {alert_id} acknowledged")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to acknowledge alert: {e}")
        raise typer.Exit(1)


@alert_app.command("resolve")
def alert_resolve(
    alert_id: int = typer.Argument(..., help="Alert ID to resolve"),
):
    """Mark an alert as resolved."""
    try:
        with get_db() as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()

            if not alert:
                console.print(f"[bold red]✗[/bold red] Alert not found: {alert_id}")
                raise typer.Exit(1)

            alert.status = AlertStatus.RESOLVED
            db.commit()

            console.print(f"[bold green]✓[/bold green] Alert {alert_id} resolved")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to resolve alert: {e}")
        raise typer.Exit(1)


@alert_app.command("delete")
def alert_delete(
    alert_id: int = typer.Argument(..., help="Alert ID to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete an alert."""
    if not confirm:
        confirmed = typer.confirm(
            f"⚠️  Delete alert #{alert_id}?",
            default=False,
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit(0)

    try:
        with get_db() as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()

            if not alert:
                console.print(f"[bold red]✗[/bold red] Alert not found: {alert_id}")
                raise typer.Exit(1)

            db.delete(alert)
            db.commit()

            console.print(f"[bold green]✓[/bold green] Deleted alert #{alert_id}")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to delete alert: {e}")
        raise typer.Exit(1)


@alert_app.command("clear")
def alert_clear(
    status: str = typer.Option("resolved", "--status", help="Clear alerts with this status"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Clear resolved or acknowledged alerts."""
    if not confirm:
        confirmed = typer.confirm(
            f"⚠️  Clear all {status} alerts?",
            default=False,
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit(0)

    try:
        with get_db() as db:
            status_enum = AlertStatus(status.lower())
            alerts = db.query(Alert).filter(Alert.status == status_enum).all()

            count = len(alerts)
            for alert in alerts:
                db.delete(alert)

            db.commit()

            console.print(f"[bold green]✓[/bold green] Cleared {count} {status} alerts")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to clear alerts: {e}")
        raise typer.Exit(1)
