"""CONDUIT CLI tool"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from conduit.transformer import text_to_bcpdr, text_to_vulnerability, text_to_sso_mfa
from conduit.models.evidence_007_bcpdr import BCPDREvidence
from conduit.models.evidence_004_vulnerability import VulnerabilityEvidence
from conduit.models.evidence_023_sso_mfa import SSOMMFAEvidence

app = typer.Typer()
console = Console()


@app.command()
def extract(
    vendor: str = typer.Option(..., "--vendor", "-v", help="Vendor name"),
    evidence_type: str = typer.Option(..., "--type", "-t", help="Evidence type: bcpdr, vulnerability, sso_mfa"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Input file path (if not using stdin)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (default: stdout)"),
    expensive: bool = typer.Option(False, "--expensive", help="Use expensive Sonnet model instead of cheap Haiku"),
) -> None:
    """
    Extract evidence from text and validate against CONDUIT schema.

    Examples:
        # From stdin
        echo "BCP/DR test on 2025-08-15..." | conduit extract -v "Acme Corp" -t bcpdr

        # From file
        conduit extract -v "Acme Corp" -t bcpdr -f trust_center.txt

        # Save to file
        conduit extract -v "Acme Corp" -t bcpdr -f input.txt -o evidence.json
    """
    try:
        # Read input text
        if file:
            if not file.exists():
                console.print(f"[red]Error: File not found: {file}[/red]")
                raise typer.Exit(1)
            text = file.read_text()
            console.print(f"[blue]Reading from file: {file}[/blue]")
        else:
            # Read from stdin
            if sys.stdin.isatty():
                console.print("[yellow]No input file specified. Reading from stdin...[/yellow]")
                console.print("[dim]Paste your text and press Ctrl+D when done:[/dim]")
            text = sys.stdin.read()

        if not text.strip():
            console.print("[red]Error: No input text provided[/red]")
            raise typer.Exit(1)

        # Select extraction function
        extractors = {
            "bcpdr": (text_to_bcpdr, BCPDREvidence, "BCP/DR Testing"),
            "vulnerability": (text_to_vulnerability, VulnerabilityEvidence, "Vulnerability Management"),
            "sso_mfa": (text_to_sso_mfa, SSOMMFAEvidence, "SSO/MFA Requirements"),
        }

        if evidence_type not in extractors:
            console.print(f"[red]Error: Unknown evidence type '{evidence_type}'[/red]")
            console.print(f"[yellow]Valid types: {', '.join(extractors.keys())}[/yellow]")
            raise typer.Exit(1)

        extractor_func, evidence_class, evidence_name = extractors[evidence_type]

        # Extract with Claude
        console.print(f"\n[blue]Extracting {evidence_name} evidence...[/blue]")
        console.print(f"[dim]Model: {'Claude Sonnet (expensive)' if expensive else 'Claude Haiku (cheap)'}[/dim]")

        data = extractor_func(text, vendor, use_expensive_model=expensive)

        # Validate with Pydantic
        console.print("[blue]Validating with Pydantic schema...[/blue]")
        evidence = evidence_class.model_validate(data)

        # Display results
        console.print(Panel.fit(
            f"[green]✓ Valid {evidence_name} evidence created![/green]",
            border_style="green"
        ))

        # Compliance summary table
        table = Table(title="Compliance Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("Vendor", str(evidence.vendor_name))
        table.add_row("Evidence Type", str(evidence.evidence_type))
        table.add_row("Evidence Date", str(evidence.evidence_date))
        table.add_row("Compliance %", f"{evidence.get_compliance_percentage():.1f}%")
        table.add_row("Status", str(evidence.get_compliance_status()))
        table.add_row("Requirements Passed", f"{evidence.get_passed_requirements()}/{evidence.get_total_requirements()}")
        table.add_row("Extraction Confidence", f"{evidence.extraction_confidence:.2f}")

        console.print(table)

        # Output JSON
        output_json = evidence.model_dump_json(indent=2)

        if output:
            output.write_text(output_json)
            console.print(f"\n[green]✓ Evidence saved to: {output}[/green]")
        else:
            console.print("\n[blue]JSON Output:[/blue]")
            console.print(output_json)

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise typer.Exit(1)


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
