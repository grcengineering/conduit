"""
Evidence Type #2: Data Mapping & Subprocessors

ASSURE Requirement:
Vendors must maintain comprehensive data mapping documentation showing what customer
data is collected, where it's stored, how it's processed, and which third parties
(subprocessors) have access. This is critical for GDPR compliance and data flow analysis.

This evidence type captures:
- Data mapping attestation/documentation
- List of subprocessors with roles and data access
- Data categories and sensitivity levels
- Geographic storage locations
- Software Bill of Materials (SBOM) for supply chain visibility
"""

from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator, HttpUrl

from .base import BaseEvidence


class DataCategory(str, Enum):
    """Categories of data processed by vendor"""
    PERSONAL_IDENTIFIABLE_INFO = "pii"  # Names, emails, addresses
    FINANCIAL_DATA = "financial"  # Payment info, bank details
    HEALTH_DATA = "health"  # PHI/medical records
    AUTHENTICATION_CREDENTIALS = "credentials"  # Passwords, API keys
    USAGE_TELEMETRY = "telemetry"  # Analytics, logs
    CUSTOMER_CONTENT = "customer_content"  # Files, documents uploaded by users
    METADATA = "metadata"  # Non-sensitive operational data
    PUBLICLY_AVAILABLE = "public"  # Public information


class DataSensitivity(str, Enum):
    """Data sensitivity classification"""
    HIGHLY_SENSITIVE = "highly_sensitive"  # PII, financial, health
    SENSITIVE = "sensitive"  # Internal business data
    INTERNAL = "internal"  # Non-public but not sensitive
    PUBLIC = "public"  # Publicly available


class GeographicRegion(str, Enum):
    """Where data is stored geographically"""
    US = "us"
    EU = "eu"
    UK = "uk"
    APAC = "apac"  # Asia-Pacific
    CANADA = "canada"
    AUSTRALIA = "australia"
    MULTI_REGION = "multi_region"  # Data replicated across multiple regions
    GLOBAL = "global"  # No specific region restriction


class SubprocessorRole(str, Enum):
    """Role of third-party subprocessor"""
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"  # AWS, Azure, GCP
    DATABASE_HOSTING = "database_hosting"  # Managed database services
    CDN = "cdn"  # Content delivery network
    ANALYTICS = "analytics"  # Analytics/monitoring tools
    CUSTOMER_SUPPORT = "customer_support"  # Support ticketing systems
    EMAIL_DELIVERY = "email_delivery"  # Transactional email services
    PAYMENT_PROCESSING = "payment_processing"  # Payment gateways
    AUTHENTICATION = "authentication"  # SSO/auth providers
    BACKUP_STORAGE = "backup_storage"  # Backup/archival services
    SECURITY_SCANNING = "security_scanning"  # Vulnerability scanners


class Subprocessor(BaseEvidence):
    """A third-party subprocessor that has access to customer data"""

    name: str = Field(
        description="Name of the subprocessor organization",
        min_length=2,
        max_length=200
    )

    role: SubprocessorRole = Field(
        description="What service this subprocessor provides"
    )

    data_categories: List[DataCategory] = Field(
        description="What categories of data this subprocessor can access",
        min_length=1
    )

    geographic_location: GeographicRegion = Field(
        description="Where this subprocessor stores/processes data"
    )

    contract_in_place: bool = Field(
        description="Whether a data processing agreement (DPA) is in place"
    )

    soc2_certified: bool = Field(
        default=False,
        description="Whether this subprocessor has SOC 2 Type II certification"
    )

    url: Optional[HttpUrl] = Field(
        default=None,
        description="Website URL for the subprocessor"
    )


class DataFlow(BaseEvidence):
    """A documented data flow showing what data goes where"""

    data_category: DataCategory = Field(
        description="Type of data in this flow"
    )

    sensitivity: DataSensitivity = Field(
        description="Sensitivity level of this data"
    )

    source_system: str = Field(
        description="Where the data originates (e.g., 'User registration form', 'Payment API')",
        min_length=2,
        max_length=200
    )

    storage_location: str = Field(
        description="Where the data is stored (e.g., 'AWS RDS us-east-1', 'Azure Blob Storage EU')",
        min_length=2,
        max_length=200
    )

    geographic_region: GeographicRegion = Field(
        description="Geographic region where data is stored"
    )

    retention_period_days: Optional[int] = Field(
        default=None,
        description="How long this data is retained (in days, None = indefinite)",
        ge=1
    )

    encrypted_at_rest: bool = Field(
        description="Whether this data is encrypted at rest"
    )

    encrypted_in_transit: bool = Field(
        description="Whether this data is encrypted in transit"
    )


class DataMappingEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Data Mapping & Subprocessors

    ASSURE requires:
    1. Comprehensive data mapping documentation
    2. All subprocessors identified and listed
    3. Data Processing Agreements (DPAs) with all subprocessors
    4. Geographic data storage locations documented
    5. Data retention periods defined
    6. Software Bill of Materials (SBOM) available
    """

    evidence_type: str = Field(
        default="assure_002_data_mapping",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Data mapping attestation
    data_mapping_last_updated: date = Field(
        description="When the data mapping documentation was last updated"
    )

    data_mapping_document_exists: bool = Field(
        description="Whether a comprehensive data mapping document exists"
    )

    data_mapping_reviewed_by_legal: bool = Field(
        default=False,
        description="Whether legal/privacy team has reviewed data mapping"
    )

    # Data flows
    data_flows: List[DataFlow] = Field(
        description="Documented data flows showing what data goes where",
        min_length=1
    )

    # Subprocessors
    subprocessors: List[Subprocessor] = Field(
        description="List of third-party subprocessors with data access",
        min_length=1
    )

    subprocessor_list_publicly_available: bool = Field(
        default=False,
        description="Whether subprocessor list is published publicly (transparency)"
    )

    customer_notification_on_changes: bool = Field(
        default=False,
        description="Whether customers are notified when subprocessors change"
    )

    # GDPR/Privacy compliance
    gdpr_article_28_compliance: bool = Field(
        default=False,
        description="Whether vendor complies with GDPR Article 28 (processor requirements)"
    )

    data_subject_rights_supported: bool = Field(
        default=True,
        description="Whether vendor supports data subject rights (access, deletion, portability)"
    )

    # Software Bill of Materials (SBOM)
    sbom_available: bool = Field(
        default=False,
        description="Whether a Software Bill of Materials (SBOM) is available"
    )

    sbom_format: Optional[str] = Field(
        default=None,
        description="Format of SBOM (e.g., 'SPDX', 'CycloneDX', 'SWID')",
        max_length=50
    )

    sbom_last_updated: Optional[date] = Field(
        default=None,
        description="When the SBOM was last updated"
    )

    @field_validator("data_mapping_last_updated")
    @classmethod
    def validate_mapping_recency(cls, v: date) -> date:
        """Data mapping should be updated at least annually"""
        from datetime import datetime, timedelta

        days_since_update = (datetime.now().date() - v).days

        if days_since_update > 365:
            raise ValueError(
                f"Data mapping was last updated {days_since_update} days ago (on {v}). "
                f"ASSURE requires data mapping to be reviewed and updated at least annually."
            )

        return v

    @field_validator("subprocessors")
    @classmethod
    def validate_subprocessor_contracts(cls, v: List[Subprocessor]) -> List[Subprocessor]:
        """All subprocessors must have DPAs in place"""
        missing_contracts = [sp for sp in v if not sp.contract_in_place]

        if missing_contracts:
            names = [sp.name for sp in missing_contracts]
            raise ValueError(
                f"The following subprocessors do not have Data Processing Agreements: {', '.join(names)}. "
                f"ASSURE requires DPAs with all subprocessors that access customer data."
            )

        return v

    @field_validator("data_flows")
    @classmethod
    def validate_sensitive_data_encrypted(cls, v: List[DataFlow]) -> List[DataFlow]:
        """Sensitive data must be encrypted at rest and in transit"""
        unencrypted_at_rest = [
            df for df in v
            if df.sensitivity in [DataSensitivity.HIGHLY_SENSITIVE, DataSensitivity.SENSITIVE]
            and not df.encrypted_at_rest
        ]

        if unencrypted_at_rest:
            categories = [df.data_category.value for df in unencrypted_at_rest]
            raise ValueError(
                f"The following sensitive data types are not encrypted at rest: {', '.join(categories)}. "
                f"ASSURE requires encryption for all sensitive customer data."
            )

        unencrypted_in_transit = [
            df for df in v
            if df.sensitivity in [DataSensitivity.HIGHLY_SENSITIVE, DataSensitivity.SENSITIVE]
            and not df.encrypted_in_transit
        ]

        if unencrypted_in_transit:
            categories = [df.data_category.value for df in unencrypted_in_transit]
            raise ValueError(
                f"The following sensitive data types are not encrypted in transit: {', '.join(categories)}. "
                f"ASSURE requires TLS/encryption for all sensitive data transmission."
            )

        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for data mapping.

        ASSURE requirements:
        1. Data mapping document exists
        2. Data mapping updated within last year
        3. Legal/privacy review completed
        4. All data flows documented
        5. All subprocessors identified
        6. DPAs in place with all subprocessors
        7. Subprocessor list publicly available (transparency)
        8. GDPR Article 28 compliance
        9. Data subject rights supported
        10. SBOM available (supply chain security)

        Total: 10 requirements
        """
        return 10

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        from datetime import datetime, timedelta

        # Requirement 1: Data mapping document exists
        if self.data_mapping_document_exists:
            passed += 1

        # Requirement 2: Data mapping updated within last year
        days_since_update = (datetime.now().date() - self.data_mapping_last_updated).days
        if days_since_update <= 365:
            passed += 1

        # Requirement 3: Legal/privacy review completed
        if self.data_mapping_reviewed_by_legal:
            passed += 1

        # Requirement 4: All data flows documented (at least 1 flow documented)
        if len(self.data_flows) > 0:
            passed += 1

        # Requirement 5: All subprocessors identified (at least 1 subprocessor documented)
        if len(self.subprocessors) > 0:
            passed += 1

        # Requirement 6: DPAs in place with all subprocessors
        if all(sp.contract_in_place for sp in self.subprocessors):
            passed += 1

        # Requirement 7: Subprocessor list publicly available
        if self.subprocessor_list_publicly_available:
            passed += 1

        # Requirement 8: GDPR Article 28 compliance
        if self.gdpr_article_28_compliance:
            passed += 1

        # Requirement 9: Data subject rights supported
        if self.data_subject_rights_supported:
            passed += 1

        # Requirement 10: SBOM available
        if self.sbom_available:
            passed += 1

        return passed
