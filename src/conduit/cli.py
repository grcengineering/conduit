"""CONDUIT CLI tool"""

import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command()
def transform(document: str) -> None:
    """Transform vendor document to CONDUIT evidence format"""
    console.print("[yellow]Phase 3: CLI not yet implemented[/yellow]")
    raise typer.Exit(1)


@app.command()
def validate(evidence: str) -> None:
    """Validate CONDUIT evidence package"""
    console.print("[yellow]Phase 3: CLI not yet implemented[/yellow]")
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
