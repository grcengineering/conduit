"""
Evidence Type #3: Patch Management

ASSURE Requirement:
Vendors must maintain a documented patch management process with defined SLAs for
applying critical security patches. Systems must be kept up-to-date with security patches.

This evidence type captures:
- Patch cadence (how often patches are applied)
- Critical patch SLA (time to apply critical patches)
- Last patch date
- Automated patching enabled
- Patch testing process
"""

from datetime import date
from enum import Enum
from typing import Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class PatchCadence(str, Enum):
    """How often patches are applied"""
    CONTINUOUS = "continuous"  # As released (automated)
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    AD_HOC = "ad_hoc"  # No regular schedule


class PatchTestingLevel(str, Enum):
    """Level of testing before applying patches"""
    PRODUCTION_DIRECTLY = "production_directly"  # No testing (risky)
    STAGING_ONLY = "staging_only"  # Test in staging
    COMPREHENSIVE = "comprehensive"  # Dev → Staging → Production
    AUTOMATED_TESTING = "automated_testing"  # Automated test suite
    MANUAL_TESTING = "manual_testing"  # Manual testing process


class PatchManagementEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Patch Management

    ASSURE requires:
    1. Documented patch management process
    2. Regular patch cadence (at least monthly)
    3. Critical patches applied within 30 days
    4. Automated patching where possible
    5. Patch testing before production deployment
    6. Recent patch activity (within last 60 days)
    """

    evidence_type: str = Field(
        default="assure_003_patch_management",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Patch process
    patch_management_process_documented: bool = Field(
        description="Whether a documented patch management process exists"
    )

    patch_cadence: PatchCadence = Field(
        description="How often patches are applied to systems"
    )

    # Critical patch SLA
    critical_patch_sla_days: Optional[int] = Field(
        default=None,
        description="SLA for applying critical security patches (in days)",
        ge=1,
        le=180
    )

    critical_patch_sla_met: bool = Field(
        default=True,
        description="Whether critical patch SLA is consistently met"
    )

    # Patch activity
    last_patch_date: Optional[date] = Field(
        default=None,
        description="Date of most recent patch deployment"
    )

    patch_frequency_description: Optional[str] = Field(
        default=None,
        description="Description of patch frequency and process",
        max_length=1000
    )

    # Automation
    automated_patching_enabled: bool = Field(
        description="Whether automated patching is enabled for some/all systems"
    )

    automated_patching_scope: Optional[str] = Field(
        default=None,
        description="Scope of automated patching (e.g., 'OS patches only', 'all systems')",
        max_length=500
    )

    # Testing
    patch_testing_performed: bool = Field(
        description="Whether patches are tested before production deployment"
    )

    patch_testing_level: Optional[PatchTestingLevel] = Field(
        default=None,
        description="Level of testing performed for patches"
    )

    # Monitoring
    patch_compliance_monitored: bool = Field(
        default=False,
        description="Whether patch compliance is actively monitored"
    )

    patch_monitoring_tool: Optional[str] = Field(
        default=None,
        description="Tool used for patch compliance monitoring (e.g., 'AWS Systems Manager', 'Qualys', 'Tanium')",
        max_length=200
    )

    # Emergency patching
    emergency_patching_process: bool = Field(
        default=False,
        description="Whether an emergency patching process exists for zero-days"
    )

    @field_validator("patch_cadence")
    @classmethod
    def validate_patch_frequency(cls, v: PatchCadence) -> PatchCadence:
        """ASSURE requires at least monthly patching"""
        insufficient_cadence = [PatchCadence.QUARTERLY, PatchCadence.AD_HOC]

        if v in insufficient_cadence:
            raise ValueError(
                f"Patch cadence is {v.value}. "
                f"ASSURE requires patches to be applied at least monthly."
            )
        return v

    @field_validator("critical_patch_sla_days")
    @classmethod
    def validate_critical_sla(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE requires critical patches within 30 days"""
        if v is not None and v > 30:
            raise ValueError(
                f"Critical patch SLA is {v} days. "
                f"ASSURE requires critical security patches to be applied within 30 days."
            )
        return v

    @field_validator("last_patch_date")
    @classmethod
    def validate_patch_recency(cls, v: Optional[date]) -> Optional[date]:
        """ASSURE requires recent patch activity (within 60 days)"""
        if v is not None:
            from datetime import datetime, timedelta
            days_since_patch = (datetime.now().date() - v).days

            if days_since_patch > 60:
                raise ValueError(
                    f"Last patch was {days_since_patch} days ago (on {v}). "
                    f"ASSURE requires regular patching activity (at least every 60 days)."
                )
        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for patch management.

        ASSURE requirements:
        1. Documented patch management process
        2. Patch cadence at least monthly
        3. Critical patch SLA ≤ 30 days
        4. Critical patch SLA consistently met
        5. Recent patch activity (within 60 days)
        6. Automated patching enabled
        7. Patch testing performed before production
        8. Patch compliance monitored
        9. Emergency patching process exists

        Total: 9 requirements (7 mandatory, 2 recommended)
        """
        return 9

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Requirement 1: Documented process
        if self.patch_management_process_documented:
            passed += 1

        # Requirement 2: Patch cadence at least monthly
        if self.patch_cadence in [
            PatchCadence.CONTINUOUS,
            PatchCadence.DAILY,
            PatchCadence.WEEKLY,
            PatchCadence.MONTHLY
        ]:
            passed += 1

        # Requirement 3: Critical patch SLA ≤ 30 days
        if self.critical_patch_sla_days and self.critical_patch_sla_days <= 30:
            passed += 1

        # Requirement 4: Critical patch SLA met
        if self.critical_patch_sla_met:
            passed += 1

        # Requirement 5: Recent patch activity
        if self.last_patch_date:
            from datetime import datetime, timedelta
            days_since_patch = (datetime.now().date() - self.last_patch_date).days
            if days_since_patch <= 60:
                passed += 1

        # Requirement 6: Automated patching enabled
        if self.automated_patching_enabled:
            passed += 1

        # Requirement 7: Patch testing performed
        if self.patch_testing_performed:
            passed += 1

        # Requirement 8: Patch compliance monitored (recommended)
        if self.patch_compliance_monitored:
            passed += 1

        # Requirement 9: Emergency patching process (recommended)
        if self.emergency_patching_process:
            passed += 1

        return passed
