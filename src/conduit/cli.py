"""CONDUIT CLI tool"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from conduit.transformer import (
    text_to_bcpdr,
    text_to_vulnerability,
    text_to_sso_mfa,
    text_to_encryption_at_rest,
    text_to_encryption_in_transit,
    text_to_incident_response,
    text_to_logging_config,
    text_to_production_access,
    text_to_backup_configuration,
    text_to_access_reviews,
    text_to_security_alerts,
    text_to_data_mapping,
    text_to_architecture,
    text_to_admin_2fa,
    text_to_code_review,
    text_to_patch_management,
    text_to_security_testing,
    text_to_network_acls,
    text_to_change_management,
    text_to_sla,
    text_to_data_retention,
    text_to_insurance,
    text_to_audit_rights,
    text_to_ai_governance,
)
from conduit.models.evidence_007_bcpdr import BCPDREvidence
from conduit.models.evidence_004_vulnerability import VulnerabilityEvidence
from conduit.models.evidence_023_sso_mfa import SSOMMFAEvidence
from conduit.models.evidence_012_encryption_at_rest import EncryptionAtRestEvidence
from conduit.models.evidence_013_encryption_in_transit import EncryptionInTransitEvidence
from conduit.models.evidence_005_incident_response import IncidentResponseEvidence
from conduit.models.evidence_014_logging_config import LoggingConfigEvidence
from conduit.models.evidence_009_production_access import ProductionAccessEvidence
from conduit.models.evidence_006_backup_configuration import BackupConfiguration
from conduit.models.evidence_008_access_reviews import AccessReviewsEvidence
from conduit.models.evidence_015_security_alerts import SecurityAlertsEvidence
from conduit.models.evidence_002_data_mapping import DataMappingEvidence
from conduit.models.evidence_001_architecture import ArchitectureEvidence
from conduit.models.evidence_011_admin_2fa import Admin2FAEvidence
from conduit.models.evidence_017_code_review import CodeReviewEvidence
from conduit.models.evidence_003_patch_management import PatchManagementEvidence
from conduit.models.evidence_018_security_testing import SecurityTestingEvidence
from conduit.models.evidence_010_network_acls import NetworkACLEvidence
from conduit.models.evidence_016_change_management import ChangeManagementEvidence
from conduit.models.evidence_019_sla import ServiceLevelAgreementEvidence
from conduit.models.evidence_020_data_retention import DataRetentionEvidence
from conduit.models.evidence_021_insurance import InsuranceCoverageEvidence
from conduit.models.evidence_022_audit_rights import RightToAuditEvidence
from conduit.models.evidence_024_ai_governance import AIGovernanceEvidence
from conduit.pdf_processor import pdf_to_text, get_pdf_metadata

app = typer.Typer()
console = Console()


@app.command()
def extract(
    vendor: str = typer.Option(..., "--vendor", "-v", help="Vendor name"),
    evidence_type: str = typer.Option(..., "--type", "-t", help="Evidence type: bcpdr, vulnerability, sso_mfa, encryption_at_rest, encryption_in_transit, incident_response, logging_config, production_access, backup_configuration, access_reviews, security_alerts, data_mapping, architecture, admin_2fa, code_review, patch_management, security_testing, network_acls, change_management, sla, data_retention, insurance, audit_rights, ai_governance"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Input file path (if not using stdin)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (default: stdout)"),
    expensive: bool = typer.Option(False, "--expensive", help="Use expensive Sonnet model instead of cheap Haiku"),
) -> None:
    """
    Extract evidence from text and validate against CONDUIT schema.

    Examples:
        # From stdin
        echo "BCP/DR test on 2025-08-15..." | conduit extract -v "Acme Corp" -t bcpdr

        # From text file
        conduit extract -v "Acme Corp" -t bcpdr -f trust_center.txt

        # From PDF (SOC 2 report)
        conduit extract -v "Island" -t bcpdr -f "Island SOC2 2025.pdf"

        # Save to file
        conduit extract -v "Acme Corp" -t bcpdr -f input.txt -o evidence.json
    """
    try:
        # Read input text
        if file:
            if not file.exists():
                console.print(f"[red]Error: File not found: {file}[/red]")
                raise typer.Exit(1)

            # Check if file is PDF
            if file.suffix.lower() == '.pdf':
                console.print(f"[blue]Reading PDF file: {file}[/blue]")

                # Get PDF metadata
                metadata = get_pdf_metadata(file)
                console.print(f"[dim]PDF Info: {metadata['page_count']} pages, {metadata['file_size_mb']:.1f}MB[/dim]")

                # Extract text from PDF
                console.print("[blue]Extracting text from PDF using PyMuPDF4LLM...[/blue]")
                text = pdf_to_text(file)
                console.print(f"[green]✓ Extracted {len(text)} characters[/green]")
            else:
                # Regular text file
                text = file.read_text()
                console.print(f"[blue]Reading text file: {file}[/blue]")
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
            # Batch 1: Core security controls (8 types)
            "bcpdr": (text_to_bcpdr, BCPDREvidence, "BCP/DR Testing"),
            "vulnerability": (text_to_vulnerability, VulnerabilityEvidence, "Vulnerability Management"),
            "sso_mfa": (text_to_sso_mfa, SSOMMFAEvidence, "SSO/MFA Requirements"),
            "encryption_at_rest": (text_to_encryption_at_rest, EncryptionAtRestEvidence, "Encryption at Rest"),
            "encryption_in_transit": (text_to_encryption_in_transit, EncryptionInTransitEvidence, "Encryption in Transit"),
            "incident_response": (text_to_incident_response, IncidentResponseEvidence, "Incident Response"),
            "logging_config": (text_to_logging_config, LoggingConfigEvidence, "Logging Configuration"),
            "production_access": (text_to_production_access, ProductionAccessEvidence, "Production Access Controls"),
            # Batch 2: Data, access & infrastructure (5 types)
            "backup_configuration": (text_to_backup_configuration, BackupConfiguration, "Backup Configuration"),
            "access_reviews": (text_to_access_reviews, AccessReviewsEvidence, "Access Reviews"),
            "security_alerts": (text_to_security_alerts, SecurityAlertsEvidence, "Security Alerts"),
            "data_mapping": (text_to_data_mapping, DataMappingEvidence, "Data Mapping & Subprocessors"),
            "architecture": (text_to_architecture, ArchitectureEvidence, "Architecture & Segmentation"),
            # Batch 3: Technical access & change controls (6 types)
            "admin_2fa": (text_to_admin_2fa, Admin2FAEvidence, "Admin 2FA"),
            "code_review": (text_to_code_review, CodeReviewEvidence, "Code Review"),
            "patch_management": (text_to_patch_management, PatchManagementEvidence, "Patch Management"),
            "security_testing": (text_to_security_testing, SecurityTestingEvidence, "Security Testing (SAST/DAST/SCA)"),
            "network_acls": (text_to_network_acls, NetworkACLEvidence, "Network ACLs"),
            "change_management": (text_to_change_management, ChangeManagementEvidence, "Change Management"),
            # Batch 4: Contracts & infrastructure (4 types)
            "sla": (text_to_sla, ServiceLevelAgreementEvidence, "Service Level Agreements"),
            "data_retention": (text_to_data_retention, DataRetentionEvidence, "Data Retention & Deletion"),
            "insurance": (text_to_insurance, InsuranceCoverageEvidence, "Insurance Coverage"),
            "audit_rights": (text_to_audit_rights, RightToAuditEvidence, "Right to Audit"),
            # Batch 5: AI governance (1 type)
            "ai_governance": (text_to_ai_governance, AIGovernanceEvidence, "AI/ML Security Controls"),
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
