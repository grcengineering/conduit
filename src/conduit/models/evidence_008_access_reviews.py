"""
Evidence Type #8: Access Reviews

ASSURE Requirement:
Vendors must perform regular reviews of user access rights to ensure adherence to
least privilege principles. Access reviews must be documented, conducted at least
quarterly, and include remediation of inappropriate access.

This evidence type captures:
- Last access review date
- Review frequency
- Systems/applications in scope
- Number of users reviewed
- Number of access rights revoked/modified
- Review methodology and approval process
"""

from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class ReviewFrequency(str, Enum):
    """How often access reviews are conducted"""
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"  # Every 6 months
    ANNUAL = "annual"
    AD_HOC = "ad_hoc"  # No regular schedule


class ReviewScope(str, Enum):
    """What is included in access reviews"""
    ALL_USERS_ALL_SYSTEMS = "all_users_all_systems"  # Comprehensive review
    PRIVILEGED_ACCESS_ONLY = "privileged_access_only"  # Only admin/elevated access
    PRODUCTION_SYSTEMS_ONLY = "production_systems_only"  # Only prod environments
    HIGH_RISK_SYSTEMS = "high_risk_systems"  # Systems with sensitive data
    CUSTOM = "custom"  # Custom scope defined by organization


class RemediationAction(str, Enum):
    """Types of remediation actions taken"""
    ACCESS_REVOKED = "access_revoked"  # Access completely removed
    ACCESS_REDUCED = "access_reduced"  # Permissions downgraded
    ACCESS_CONFIRMED = "access_confirmed"  # Access validated as appropriate
    PENDING_REMOVAL = "pending_removal"  # Scheduled for removal


class AccessReviewsEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Access Reviews

    ASSURE requires:
    1. Access reviews conducted at least quarterly
    2. Reviews cover all user accounts (or at minimum, all privileged access)
    3. Reviews documented with findings and remediation actions
    4. Inappropriate access removed within 7 days of review
    5. Management approval of review results
    """

    evidence_type: str = Field(
        default="assure_008_access_reviews",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Review timing
    last_review_date: date = Field(
        description="Date of the most recent access review"
    )

    review_frequency: ReviewFrequency = Field(
        description="How often access reviews are conducted"
    )

    next_scheduled_review: Optional[date] = Field(
        default=None,
        description="Date of next scheduled access review"
    )

    # Review scope
    review_scope: ReviewScope = Field(
        description="What accounts/systems are included in access reviews"
    )

    systems_in_scope: List[str] = Field(
        description="List of systems/applications included in access reviews",
        min_length=1,
        max_length=100
    )

    scope_description: Optional[str] = Field(
        default=None,
        description="Detailed description of review scope (especially if scope is 'custom')",
        max_length=1000
    )

    # Review metrics
    total_users_reviewed: int = Field(
        description="Number of user accounts reviewed in last review",
        ge=0
    )

    privileged_users_reviewed: Optional[int] = Field(
        default=None,
        description="Number of privileged/admin accounts reviewed",
        ge=0
    )

    # Remediation actions
    access_revoked_count: int = Field(
        default=0,
        description="Number of access rights fully revoked during last review",
        ge=0
    )

    access_reduced_count: int = Field(
        default=0,
        description="Number of access rights reduced/downgraded during last review",
        ge=0
    )

    # Review process
    management_approved: bool = Field(
        description="Whether review results were approved by management"
    )

    remediation_deadline_days: Optional[int] = Field(
        default=None,
        description="Required timeframe for remediating inappropriate access (in days)",
        ge=1,
        le=90
    )

    automated_review_tools_used: bool = Field(
        default=False,
        description="Whether automated tools (e.g., IGA systems) are used for access reviews"
    )

    @field_validator("last_review_date")
    @classmethod
    def validate_review_recency(cls, v: date) -> date:
        """ASSURE requires quarterly reviews (every 90 days)"""
        from datetime import datetime, timedelta

        days_since_review = (datetime.now().date() - v).days

        if days_since_review > 90:
            raise ValueError(
                f"Last access review was {days_since_review} days ago (on {v}). "
                f"ASSURE requires access reviews at least every 90 days (quarterly)."
            )

        return v

    @field_validator("review_frequency")
    @classmethod
    def validate_frequency_minimum(cls, v: ReviewFrequency) -> ReviewFrequency:
        """ASSURE requires at least quarterly reviews"""
        insufficient_frequencies = [
            ReviewFrequency.SEMI_ANNUAL,
            ReviewFrequency.ANNUAL,
            ReviewFrequency.AD_HOC
        ]

        if v in insufficient_frequencies:
            raise ValueError(
                f"Access review frequency is {v.value}. "
                f"ASSURE requires access reviews at least quarterly."
            )

        return v

    @field_validator("systems_in_scope")
    @classmethod
    def validate_systems_list(cls, v: List[str]) -> List[str]:
        """Validate systems list is not empty and entries are meaningful"""
        if not v:
            raise ValueError(
                "Systems in scope cannot be empty. "
                "ASSURE requires documentation of which systems are included in access reviews."
            )

        # Check for placeholder/generic values
        generic_values = ["n/a", "na", "none", "unknown", "tbd"]
        if all(system.lower().strip() in generic_values for system in v):
            raise ValueError(
                "Systems in scope contains only placeholder values. "
                "Specific system names are required (e.g., 'Production Database', 'AWS Console', 'GitHub')."
            )

        return v

    @field_validator("remediation_deadline_days")
    @classmethod
    def validate_remediation_deadline(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE recommends remediation within 7 days for critical access"""
        if v is not None and v > 30:
            import logging
            logging.warning(
                f"Remediation deadline is {v} days. "
                f"ASSURE recommends inappropriate access be removed within 7-30 days."
            )
        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for access reviews.

        ASSURE requirements:
        1. Reviews conducted at least quarterly
        2. Last review within 90 days
        3. Reviews cover all systems (or at least privileged access)
        4. At least 1 user reviewed (proving review occurred)
        5. Management approval obtained
        6. Remediation actions documented (revoked or reduced count > 0, or confirmed all access appropriate)
        7. Remediation deadline defined (7-30 days)
        8. Automated tools used for efficiency (recommended, not required)

        Total: 8 requirements (7 mandatory, 1 recommended)
        """
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        from datetime import datetime, timedelta

        # Requirement 1: Review frequency at least quarterly
        if self.review_frequency in [ReviewFrequency.MONTHLY, ReviewFrequency.QUARTERLY]:
            passed += 1

        # Requirement 2: Last review within 90 days
        days_since_review = (datetime.now().date() - self.last_review_date).days
        if days_since_review <= 90:
            passed += 1

        # Requirement 3: Reviews cover all systems or privileged access
        if self.review_scope in [
            ReviewScope.ALL_USERS_ALL_SYSTEMS,
            ReviewScope.PRIVILEGED_ACCESS_ONLY,
            ReviewScope.HIGH_RISK_SYSTEMS
        ]:
            passed += 1

        # Requirement 4: At least 1 user reviewed
        if self.total_users_reviewed > 0:
            passed += 1

        # Requirement 5: Management approval obtained
        if self.management_approved:
            passed += 1

        # Requirement 6: Remediation actions documented
        # Either some access was revoked/reduced, OR review confirmed all access appropriate
        total_remediation_actions = self.access_revoked_count + self.access_reduced_count
        if total_remediation_actions > 0 or self.total_users_reviewed > 0:
            passed += 1

        # Requirement 7: Remediation deadline defined and reasonable (<=30 days)
        if self.remediation_deadline_days is not None and self.remediation_deadline_days <= 30:
            passed += 1

        # Requirement 8: Automated tools used (recommended)
        if self.automated_review_tools_used:
            passed += 1

        return passed
