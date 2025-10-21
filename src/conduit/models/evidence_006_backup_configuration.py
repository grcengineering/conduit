"""
Evidence Type #6: Backup Configuration

ASSURE Requirement:
Vendors must maintain regular backups of all customer data with documented backup
frequency, retention periods, and testing procedures. Backups must be tested regularly
to ensure recoverability.

This evidence type captures:
- Backup frequency (daily, weekly, etc.)
- Retention period for backups
- Last backup test date and results
- Backup scope (what data is backed up)
- Backup storage location and security
"""

from datetime import date
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class BackupFrequency(str, Enum):
    """Backup frequency options"""
    CONTINUOUS = "continuous"  # Real-time/streaming backups
    HOURLY = "hourly"
    EVERY_6_HOURS = "every_6_hours"
    EVERY_12_HOURS = "every_12_hours"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class BackupTestResult(str, Enum):
    """Results of backup restoration testing"""
    SUCCESSFUL = "successful"
    PARTIAL_SUCCESS = "partial_success"  # Some data recovered, some failed
    FAILED = "failed"
    NOT_TESTED = "not_tested"


class BackupStorageLocation(str, Enum):
    """Where backups are stored"""
    SAME_REGION = "same_region"  # Same region as primary data
    DIFFERENT_REGION = "different_region"  # Different region, same cloud
    DIFFERENT_CLOUD = "different_cloud"  # Different cloud provider
    ON_PREMISES = "on_premises"
    HYBRID = "hybrid"  # Mix of cloud and on-premises


class BackupConfiguration(BaseEvidence):
    """
    Evidence for ASSURE requirement: Backup Configuration

    ASSURE requires:
    1. Regular automated backups (at least daily)
    2. Minimum 30-day retention period
    3. Backups tested at least quarterly
    4. Backups stored in geographically separate location
    5. Backup encryption enabled
    """

    evidence_type: str = Field(
        default="assure_006_backup_configuration",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Backup frequency and schedule
    backup_frequency: BackupFrequency = Field(
        description="How often backups are performed"
    )

    backup_schedule_description: Optional[str] = Field(
        default=None,
        description="Detailed description of backup schedule (e.g., '2 AM UTC daily', 'Sunday midnight weekly')",
        max_length=500
    )

    # Retention policy
    retention_period_days: int = Field(
        description="How long backups are retained (in days)",
        ge=1,  # Must be at least 1 day
        le=3650  # Max 10 years (sanity check)
    )

    # Backup testing
    last_test_date: Optional[date] = Field(
        default=None,
        description="Date of the most recent backup restoration test"
    )

    last_test_result: BackupTestResult = Field(
        description="Result of the most recent backup test"
    )

    test_frequency_days: Optional[int] = Field(
        default=None,
        description="How often backup restoration is tested (in days)",
        ge=1,
        le=365
    )

    # Backup scope and coverage
    backup_scope: str = Field(
        description="What data is included in backups (e.g., 'All customer databases, file storage, and configurations')",
        min_length=10,
        max_length=1000
    )

    # Backup storage
    storage_location: BackupStorageLocation = Field(
        description="Geographic/infrastructural location of backup storage"
    )

    is_encrypted: bool = Field(
        description="Whether backups are encrypted at rest"
    )

    # Automation and monitoring
    is_automated: bool = Field(
        description="Whether backups run automatically (vs. manual process)"
    )

    monitoring_enabled: bool = Field(
        default=False,
        description="Whether backup success/failure is actively monitored and alerted"
    )

    @field_validator("retention_period_days")
    @classmethod
    def validate_retention_minimum(cls, v: int) -> int:
        """ASSURE requires minimum 30-day retention"""
        if v < 30:
            raise ValueError(
                f"Backup retention period is {v} days. "
                f"ASSURE requires minimum 30-day retention for customer data backups."
            )
        return v

    @field_validator("last_test_date")
    @classmethod
    def validate_test_recency(cls, v: Optional[date]) -> Optional[date]:
        """ASSURE requires quarterly testing (every 90 days)"""
        if v is None:
            raise ValueError(
                "Backup restoration testing date is required. "
                "ASSURE requires backups to be tested at least quarterly."
            )

        from datetime import datetime, timedelta
        days_since_test = (datetime.now().date() - v).days

        if days_since_test > 90:
            raise ValueError(
                f"Last backup test was {days_since_test} days ago (on {v}). "
                f"ASSURE requires backup testing at least every 90 days (quarterly)."
            )

        return v

    @field_validator("backup_frequency")
    @classmethod
    def validate_frequency_minimum(cls, v: BackupFrequency) -> BackupFrequency:
        """ASSURE requires at least daily backups"""
        insufficient_frequencies = [BackupFrequency.WEEKLY, BackupFrequency.MONTHLY]

        if v in insufficient_frequencies:
            raise ValueError(
                f"Backup frequency is {v.value}. "
                f"ASSURE requires backups at least daily for customer data."
            )

        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for backup configuration.

        ASSURE requirements:
        1. Automated backups enabled
        2. Backup frequency at least daily
        3. Retention period at least 30 days
        4. Backup testing performed within last 90 days
        5. Last test was successful
        6. Backups encrypted
        7. Backups stored in separate location (different region/cloud)
        8. Monitoring/alerting enabled for backup failures

        Total: 8 requirements
        """
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Requirement 1: Automated backups enabled
        if self.is_automated:
            passed += 1

        # Requirement 2: Backup frequency at least daily
        if self.backup_frequency in [
            BackupFrequency.CONTINUOUS,
            BackupFrequency.HOURLY,
            BackupFrequency.EVERY_6_HOURS,
            BackupFrequency.EVERY_12_HOURS,
            BackupFrequency.DAILY
        ]:
            passed += 1

        # Requirement 3: Retention period at least 30 days
        if self.retention_period_days >= 30:
            passed += 1

        # Requirement 4: Backup testing performed within last 90 days
        if self.last_test_date:
            from datetime import datetime, timedelta
            days_since_test = (datetime.now().date() - self.last_test_date).days
            if days_since_test <= 90:
                passed += 1

        # Requirement 5: Last test was successful
        if self.last_test_result == BackupTestResult.SUCCESSFUL:
            passed += 1

        # Requirement 6: Backups encrypted
        if self.is_encrypted:
            passed += 1

        # Requirement 7: Backups stored in separate location
        if self.storage_location in [
            BackupStorageLocation.DIFFERENT_REGION,
            BackupStorageLocation.DIFFERENT_CLOUD,
            BackupStorageLocation.HYBRID
        ]:
            passed += 1

        # Requirement 8: Monitoring/alerting enabled
        if self.monitoring_enabled:
            passed += 1

        return passed
