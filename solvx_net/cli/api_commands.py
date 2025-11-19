"""API server CLI commands."""

import typer
from rich.console import Console

from solvx_net.core.config import get_config
from solvx_net.core.logging import get_logger

logger = get_logger(__name__)
console = Console()

api_app = typer.Typer(help="API server commands")


@api_app.command("start")
def api_start(
    host: str = typer.Option(None, "--host", help="Host to bind to"),
    port: int = typer.Option(None, "--port", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload"),
):
    """Start the FastAPI server."""
    import uvicorn

    config = get_config()

    # Use provided values or fall back to config
    host = host or config.api.host
    port = port or config.api.port

    console.print(f"[bold green]Starting SolVX API server...[/bold green]")
    console.print(f"  Host: [cyan]{host}[/cyan]")
    console.print(f"  Port: [cyan]{port}[/cyan]")
    console.print(f"  API docs: [cyan]http://{host}:{port}/docs[/cyan]")
    console.print(f"\nPress [bold]Ctrl+C[/bold] to stop\n")

    try:
        uvicorn.run(
            "solvx_net.api.server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info",
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")
