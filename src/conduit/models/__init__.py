"""
CONDUIT Evidence Models

This package contains Pydantic models for all 24 ASSURE evidence types.
Each evidence type is defined in a separate file for clear organization.

Usage:
    from conduit.models import BCPDREvidence, VulnerabilityEvidence

    evidence = BCPDREvidence(
        vendor_name="Acme Corp",
        evidence_date="2025-10-16",
        test_date="2025-01-15",
        test_result="pass",
        extraction_confidence=0.95
    )

    if evidence.is_compliant():
        print("Evidence meets ASSURE requirements")
"""

from .base import BaseEvidence

# Phase 1: 3 starter evidence types
# TODO: Import evidence_007_bcpdr (Step 4)
# TODO: Import evidence_023_sso_mfa (Step 5)
# TODO: Import evidence_004_vulnerability (Step 6)

__all__ = [
    "BaseEvidence",
    # Phase 1 models will be added here
]
