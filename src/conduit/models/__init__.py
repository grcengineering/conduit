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
from .evidence_004_vulnerability import (
    BugBountyProgram,
    PenetrationTest,
    VulnerabilityEvidence,
    VulnerabilityScan,
)
from .evidence_007_bcpdr import (
    BCPDREvidence,
    BCPDRFinding,
    TestResult,
    TestType,
)
from .evidence_023_sso_mfa import (
    MFAType,
    SSOMMFAEvidence,
    SSOProtocol,
)

# Phase 1: 3 starter evidence types complete!
# Phase 4: Remaining 21 evidence types

__all__ = [
    "BaseEvidence",
    "BugBountyProgram",
    "PenetrationTest",
    "VulnerabilityEvidence",
    "VulnerabilityScan",
    "BCPDREvidence",
    "BCPDRFinding",
    "TestResult",
    "TestType",
    "MFAType",
    "SSOMMFAEvidence",
    "SSOProtocol",
]
