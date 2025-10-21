"""Evidence Type #20: Data Retention & Deletion"""
from enum import Enum
from typing import Optional, List
from pydantic import Field, field_validator
from .base import BaseEvidence


class DataCategory(str, Enum):
    """Categories of data subject to retention policies"""
    CUSTOMER_DATA = "customer_data"  # Customer information
    TRANSACTION_DATA = "transaction_data"  # Transaction records
    LOG_DATA = "log_data"  # System logs
    BACKUP_DATA = "backup_data"  # Backup copies
    METADATA = "metadata"  # System metadata
    ANALYTICS_DATA = "analytics_data"  # Analytics/metrics
    ALL_DATA = "all_data"  # Covers all data types


class DeletionMethod(str, Enum):
    """Methods for data deletion"""
    SECURE_DELETION = "secure_deletion"  # Secure overwrite
    CRYPTO_ERASURE = "crypto_erasure"  # Cryptographic key destruction
    PHYSICAL_DESTRUCTION = "physical_destruction"  # Physical media destruction
    LOGICAL_DELETION = "logical_deletion"  # Standard deletion
    ANONYMIZATION = "anonymization"  # Data anonymization


class DataRetentionEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Data Retention & Deletion

    ASSURE requires:
    1. Documented data retention policy exists
    2. Retention periods defined by data category
    3. Deletion process documented for end-of-retention
    4. Customer data deletion on request (within 30 days)
    5. Deletion method secure (not just logical deletion)
    6. Deletion verification/certification available
    7. Backup data included in deletion process
    8. GDPR/CCPA compliance for data subject rights
    """

    evidence_type: str = Field(
        default="assure_020_data_retention",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Retention policy
    retention_policy_documented: bool = Field(
        description="Whether a formal data retention policy is documented"
    )

    retention_policy_location: Optional[str] = Field(
        default=None,
        description="Where retention policy is documented (e.g., 'DPA Exhibit B', 'Privacy Policy')",
        max_length=200
    )

    retention_policy_last_updated: Optional[str] = Field(
        default=None,
        description="Date retention policy was last updated (YYYY-MM-DD or YYYY-MM)",
        max_length=50
    )

    # Retention periods
    retention_periods_defined: bool = Field(
        description="Whether specific retention periods are defined for different data types"
    )

    default_retention_period_days: Optional[int] = Field(
        default=None,
        description="Default retention period in days",
        ge=1,
        le=7300  # Max 20 years
    )

    customer_data_retention_days: Optional[int] = Field(
        default=None,
        description="Retention period for customer/personal data (in days)",
        ge=1,
        le=7300
    )

    log_data_retention_days: Optional[int] = Field(
        default=None,
        description="Retention period for log data (in days)",
        ge=1,
        le=730  # Max 2 years typical
    )

    backup_data_retention_days: Optional[int] = Field(
        default=None,
        description="Retention period for backup data (in days)",
        ge=1,
        le=2555  # Max 7 years
    )

    # Deletion process
    deletion_process_documented: bool = Field(
        description="Whether data deletion process is documented"
    )

    deletion_on_request_supported: bool = Field(
        description="Whether customer can request data deletion"
    )

    deletion_request_timeframe_days: Optional[int] = Field(
        default=None,
        description="Timeframe to complete deletion after request (in days)",
        ge=1,
        le=90
    )

    deletion_method: Optional[DeletionMethod] = Field(
        default=None,
        description="Method used for data deletion"
    )

    # Deletion verification
    deletion_verification_available: bool = Field(
        default=False,
        description="Whether vendor provides deletion verification/certification"
    )

    deletion_certificate_provided: bool = Field(
        default=False,
        description="Whether vendor provides written deletion certificate"
    )

    # Backup inclusion
    backups_included_in_deletion: bool = Field(
        description="Whether deletion process includes backup copies"
    )

    backup_deletion_timeframe_days: Optional[int] = Field(
        default=None,
        description="Maximum time to delete data from backups (in days)",
        ge=1,
        le=180
    )

    # Compliance
    gdpr_compliant: bool = Field(
        default=False,
        description="Whether retention/deletion practices are GDPR compliant"
    )

    ccpa_compliant: bool = Field(
        default=False,
        description="Whether retention/deletion practices are CCPA compliant"
    )

    data_subject_rights_supported: List[str] = Field(
        default_factory=list,
        description="Data subject rights supported (e.g., 'right_to_erasure', 'right_to_access')"
    )

    @field_validator("retention_policy_documented")
    @classmethod
    def validate_policy_exists(cls, v: bool) -> bool:
        """ASSURE requires documented retention policy"""
        if not v:
            raise ValueError(
                "No documented data retention policy found. "
                "ASSURE requires formal retention policies."
            )
        return v

    @field_validator("deletion_request_timeframe_days")
    @classmethod
    def validate_deletion_timeframe(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE requires deletion within 30 days"""
        if v is not None and v > 30:
            raise ValueError(
                f"Data deletion takes {v} days. "
                f"ASSURE requires customer data deletion within 30 days of request."
            )
        return v

    @field_validator("deletion_method")
    @classmethod
    def validate_secure_deletion(cls, v: Optional[DeletionMethod]) -> Optional[DeletionMethod]:
        """ASSURE requires secure deletion (not just logical)"""
        if v == DeletionMethod.LOGICAL_DELETION:
            raise ValueError(
                "Deletion method is logical deletion only. "
                "ASSURE requires secure deletion (secure overwrite, crypto erasure, or physical destruction)."
            )
        return v

    def get_total_requirements(self) -> int:
        """Total number of ASSURE requirements for data retention evidence"""
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many requirements are met"""
        passed = 0

        # 1. Documented retention policy exists
        if self.retention_policy_documented:
            passed += 1

        # 2. Retention periods defined by category
        if self.retention_periods_defined:
            passed += 1

        # 3. Deletion process documented
        if self.deletion_process_documented:
            passed += 1

        # 4. Deletion on request within 30 days
        if self.deletion_on_request_supported and self.deletion_request_timeframe_days and self.deletion_request_timeframe_days <= 30:
            passed += 1

        # 5. Secure deletion method
        if self.deletion_method and self.deletion_method != DeletionMethod.LOGICAL_DELETION:
            passed += 1

        # 6. Deletion verification available
        if self.deletion_verification_available or self.deletion_certificate_provided:
            passed += 1

        # 7. Backups included in deletion
        if self.backups_included_in_deletion:
            passed += 1

        # 8. GDPR/CCPA compliance
        if self.gdpr_compliant or self.ccpa_compliant:
            passed += 1

        return passed
