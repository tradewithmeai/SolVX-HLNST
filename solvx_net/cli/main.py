"""Main CLI entry point for SolVX."""

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
import json

from solvx_net import __version__
from solvx_net.core.config import get_config
from solvx_net.core.logging import setup_logging, get_logger
from solvx_net.core.database import init_database, create_tables, drop_tables
from solvx_net.cli.pcap_commands import pcap_app
from solvx_net.cli.device_commands import device_app
from solvx_net.cli.alert_commands import alert_app
from solvx_net.cli.detect_commands import detect_app
from solvx_net.cli.score_commands import score_app
from solvx_net.cli.api_commands import api_app

app = typer.Typer(
    name="solvx",
    help="SolVX Home Lab Network & Security Toolkit",
    add_completion=False,
)
console = Console()

# Add subcommands
app.add_typer(pcap_app, name="pcap")
app.add_typer(device_app, name="devices")
app.add_typer(alert_app, name="alerts")
app.add_typer(detect_app, name="detect")
app.add_typer(score_app, name="score")
app.add_typer(api_app, name="api")


@app.callback()
def main_callback(
    log_level: str = typer.Option(
        None,
        "--log-level",
        "-l",
        help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    ),
):
    """Initialize application."""
    config = get_config()
    level = log_level or config.log_level
    setup_logging(level=level, log_dir=config.log_dir)


@app.command()
def version():
    """Show version information."""
    console.print(f"[bold green]SolVX Network Security Toolkit[/bold green]")
    console.print(f"Version: [cyan]{__version__}[/cyan]")


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    key: str = typer.Option(None, "--get", help="Get specific config value"),
):
    """Manage configuration."""
    cfg = get_config()

    if key:
        # Navigate nested config
        parts = key.split(".")
        value = cfg
        try:
            for part in parts:
                value = getattr(value, part)
            console.print(f"{key}: [cyan]{value}[/cyan]")
        except AttributeError:
            console.print(f"[red]Config key not found: {key}[/red]")
            raise typer.Exit(1)
    elif show:
        # Show full config
        console.print("[bold]Configuration:[/bold]")
        config_dict = {
            "app_name": cfg.app_name,
            "log_level": cfg.log_level,
            "log_dir": str(cfg.log_dir),
            "data_dir": str(cfg.data_dir),
            "database": {
                "url": cfg.database.url,
                "echo": cfg.database.echo,
            },
            "capture": {
                "interface": cfg.capture.interface,
                "pcap_dir": str(cfg.capture.pcap_dir),
            },
            "api": {
                "host": cfg.api.host,
                "port": cfg.api.port,
            },
        }
        console.print_json(json.dumps(config_dict, indent=2))
    else:
        console.print("Use --show to display configuration or --get KEY to get specific value")


# Database commands
db_app = typer.Typer(help="Database management commands")
app.add_typer(db_app, name="db")


@db_app.command("init")
def db_init(
    force: bool = typer.Option(False, "--force", help="Drop existing tables first"),
):
    """Initialize database schema."""
    logger = get_logger(__name__)
    config = get_config()

    console.print("[bold]Initializing database...[/bold]")

    try:
        init_database()

        if force:
            console.print("[yellow]Dropping existing tables...[/yellow]")
            drop_tables()

        console.print("[cyan]Creating tables...[/cyan]")
        create_tables()

        console.print("[bold green]✓[/bold green] Database initialized successfully")
        console.print(f"Database URL: [cyan]{config.database.url}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Database initialization failed: {e}")
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        raise typer.Exit(1)


@db_app.command("drop")
def db_drop(
    confirm: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt",
    ),
):
    """Drop all database tables (destructive!)."""
    if not confirm:
        confirmed = typer.confirm(
            "⚠️  This will DELETE ALL DATA. Are you sure?",
            default=False,
        )
        if not confirmed:
            console.print("Cancelled.")
            raise typer.Exit(0)

    try:
        init_database()
        console.print("[yellow]Dropping all tables...[/yellow]")
        drop_tables()
        console.print("[bold green]✓[/bold green] All tables dropped")
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to drop tables: {e}")
        raise typer.Exit(1)


@db_app.command("status")
def db_status():
    """Show database status."""
    from sqlalchemy import inspect

    config = get_config()
    console.print("[bold]Database Status:[/bold]")
    console.print(f"URL: [cyan]{config.database.url}[/cyan]")

    try:
        init_database()
        from solvx_net.core.database import get_engine

        engine = get_engine()
        inspector = inspect(engine)
        tables = inspector.get_table_names()

        if tables:
            console.print(f"\n[bold]Tables ({len(tables)}):[/bold]")
            for table in sorted(tables):
                console.print(f"  • {table}")
        else:
            console.print("\n[yellow]No tables found. Run 'solvx db init' to create schema.[/yellow]")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Failed to connect to database: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
