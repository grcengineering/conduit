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

# Batch 1 Evidence Types (8 types - COMPLETE)
from .evidence_004_vulnerability import (
    BugBountyProgram,
    PenetrationTest,
    VulnerabilityEvidence,
    VulnerabilityScan,
)
from .evidence_005_incident_response import IncidentResponseEvidence
from .evidence_007_bcpdr import (
    BCPDREvidence,
    BCPDRFinding,
    TestResult,
    TestType,
)
from .evidence_009_production_access import ProductionAccessEvidence
from .evidence_012_encryption_at_rest import EncryptionAtRestEvidence
from .evidence_013_encryption_in_transit import EncryptionInTransitEvidence
from .evidence_014_logging_config import LoggingConfigEvidence
from .evidence_023_sso_mfa import (
    MFAType,
    SSOMMFAEvidence,
    SSOProtocol,
)

# Batch 2 Evidence Types (5 types - COMPLETE)
from .evidence_001_architecture import ArchitectureEvidence
from .evidence_002_data_mapping import DataMappingEvidence
from .evidence_006_backup_configuration import BackupConfiguration
from .evidence_008_access_reviews import AccessReviewsEvidence
from .evidence_015_security_alerts import SecurityAlertsEvidence

# Batch 3 Evidence Types (6 types - COMPLETE)
from .evidence_003_patch_management import PatchManagementEvidence
from .evidence_010_network_acls import NetworkACLEvidence
from .evidence_011_admin_2fa import Admin2FAEvidence
from .evidence_016_change_management import ChangeManagementEvidence
from .evidence_017_code_review import CodeReviewEvidence
from .evidence_018_security_testing import SecurityTestingEvidence

# Batch 4 Evidence Types (4 types - COMPLETE)
from .evidence_019_sla import ServiceLevelAgreementEvidence
from .evidence_020_data_retention import DataRetentionEvidence
from .evidence_021_insurance import InsuranceCoverageEvidence
from .evidence_022_audit_rights import RightToAuditEvidence

# Batch 5 Evidence Types (1 type - COMPLETE)
from .evidence_024_ai_governance import AIGovernanceEvidence

# Implementation Progress: 24/24 evidence types complete (100%)

__all__ = [
    # Base
    "BaseEvidence",
    # Batch 1 (8 types)
    "BugBountyProgram",
    "PenetrationTest",
    "VulnerabilityEvidence",
    "VulnerabilityScan",
    "IncidentResponseEvidence",
    "BCPDREvidence",
    "BCPDRFinding",
    "TestResult",
    "TestType",
    "ProductionAccessEvidence",
    "EncryptionAtRestEvidence",
    "EncryptionInTransitEvidence",
    "LoggingConfigEvidence",
    "MFAType",
    "SSOMMFAEvidence",
    "SSOProtocol",
    # Batch 2 (5 types)
    "ArchitectureEvidence",
    "DataMappingEvidence",
    "BackupConfiguration",
    "AccessReviewsEvidence",
    "SecurityAlertsEvidence",
    # Batch 3 (6 types)
    "PatchManagementEvidence",
    "NetworkACLEvidence",
    "Admin2FAEvidence",
    "ChangeManagementEvidence",
    "CodeReviewEvidence",
    "SecurityTestingEvidence",
    # Batch 4 (4 types)
    "ServiceLevelAgreementEvidence",
    "DataRetentionEvidence",
    "InsuranceCoverageEvidence",
    "RightToAuditEvidence",
    # Batch 5 (1 type)
    "AIGovernanceEvidence",
]
