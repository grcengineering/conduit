"""ASSURE Control #5: Incident Response Evidence"""

from datetime import date, timedelta
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from .base import BaseEvidence


class IncidentType(Enum):
    """Types of incidents covered in incident response plan"""

    SECURITY_BREACH = "security_breach"
    PRIVACY_BREACH = "privacy_breach"
    AVAILABILITY = "availability"
    DATA_INTEGRITY = "data_integrity"
    RANSOMWARE = "ransomware"


class TestType(Enum):
    """Type of incident response test/exercise conducted"""

    TABLETOP = "tabletop"
    WALKTHROUGH = "walkthrough"
    SIMULATION = "simulation"
    LIVE_DRILL = "live_drill"
    NONE = "none"


class NotificationSLA(Enum):
    """Service level agreement for incident notification"""

    IMMEDIATE = "immediate"
    ONE_HOUR = "1_hour"
    FOUR_HOURS = "4_hours"
    TWENTY_FOUR_HOURS = "24_hours"
    SEVENTY_TWO_HOURS = "72_hours"
    NONE = "none"


class IncidentResponseEvidence(BaseEvidence):
    """
    ASSURE Control #5: Incident Response Evidence.

    This evidence type validates that vendors have an incident response (IR) plan
    that is documented, tested annually, and includes notification SLAs for critical incidents.

    ASSURE Requirements:
    - IR plan must exist and be documented
    - Plan must be tested at least annually
    - Must cover critical incident types (security breach, privacy breach, ransomware)
    - Notification SLAs must be defined for security/privacy breaches
    - Test must include lessons learned documentation
    - Plan must be accessible to employees

    SOC 2 Criteria: CC2.2 (Incident Management), CC7.3 (Security Incidents)
    NIST CSF: ID.IM-04 (Incident Management)
    CIS Controls: Control 18 (Incident Response Management)

    Example:
        evidence = IncidentResponseEvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-17",
            plan_exists=True,
            last_test_date="2025-06-15",
            test_type="tabletop",
            incident_types_covered=["security_breach", "privacy_breach", "ransomware"],
            security_breach_sla="24_hours",
            privacy_breach_sla="72_hours",
            lessons_learned_documented=True,
            plan_accessible_to_employees=True,
            extraction_confidence=0.95
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE Incident Response requirements")
    """

    evidence_type: str = Field(default="assure_005_incident_response")

    # Core evidence data (required)
    plan_exists: bool = Field(
        description="Whether an incident response plan exists and is documented"
    )
    last_test_date: Optional[date] = Field(
        default=None, description="Date of most recent IR test/exercise"
    )
    test_type: TestType = Field(
        default=TestType.NONE, description="Type of IR test conducted"
    )
    incident_types_covered: List[IncidentType] = Field(
        default_factory=list,
        description="Types of incidents covered in the IR plan",
    )

    # Notification SLAs (critical for compliance)
    security_breach_sla: NotificationSLA = Field(
        default=NotificationSLA.NONE,
        description="SLA for notifying about security breaches",
    )
    privacy_breach_sla: NotificationSLA = Field(
        default=NotificationSLA.NONE,
        description="SLA for notifying about privacy/data breaches",
    )

    # Additional compliance factors
    lessons_learned_documented: bool = Field(
        default=False,
        description="Whether lessons learned from tests are documented",
    )
    plan_accessible_to_employees: bool = Field(
        default=False,
        description="Whether IR plan is accessible to relevant employees",
    )

    # Optional details
    plan_includes_identification: Optional[bool] = Field(
        default=None, description="Plan includes incident identification procedures"
    )
    plan_includes_reporting: Optional[bool] = Field(
        default=None, description="Plan includes incident reporting procedures"
    )
    plan_includes_containment: Optional[bool] = Field(
        default=None, description="Plan includes incident containment procedures"
    )
    plan_includes_communication: Optional[bool] = Field(
        default=None, description="Plan includes communication procedures"
    )
    plan_includes_mitigation: Optional[bool] = Field(
        default=None, description="Plan includes mitigation/recovery procedures"
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["CC2.2", "CC7.3"],
        description="SOC 2 criteria for incident response management",
    )
    soc2_coverage_percentage: int = Field(
        default=85,
        ge=0,
        le=100,
        description="IR evidence typically 85% covered in SOC 2",
    )

    @field_validator("last_test_date")
    @classmethod
    def validate_test_recency(cls, v: Optional[date]) -> Optional[date]:
        """
        Validate that incident response test is within the last 12 months.

        ASSURE requires vendors to test their IR plan at least annually.

        Args:
            v: The test date to validate (can be None if no test conducted)

        Returns:
            date: The validated test date, or None if no test

        Raises:
            ValueError: If test date is older than 12 months
        """
        if v is None:
            return None

        twelve_months_ago = date.today() - timedelta(days=365)
        if v < twelve_months_ago:
            raise ValueError(
                f"Incident response test date {v} is older than 12 months "
                f"(before {twelve_months_ago}). "
                f"ASSURE requires annual testing."
            )
        return v

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. IR plan must exist and be documented
        2. Plan must be tested within last 12 months
        3. Must cover critical incident types (security_breach, privacy_breach, ransomware)
        4. Notification SLAs must be defined for security/privacy breaches
        5. Lessons learned must be documented from tests
        6. Plan must be accessible to employees

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        try:
            # Requirement 1: Plan must exist
            if not self.plan_exists:
                return False

            # Requirement 2: Plan must be tested within last 12 months
            if self.last_test_date is None:
                return False

            twelve_months_ago = date.today() - timedelta(days=365)
            if self.last_test_date < twelve_months_ago:
                return False

            # Test type must not be NONE
            if self.test_type == TestType.NONE:
                return False

            # Requirement 3: Must cover critical incident types
            required_types = {
                IncidentType.SECURITY_BREACH,
                IncidentType.PRIVACY_BREACH,
                IncidentType.RANSOMWARE,
            }
            covered_types = set(self.incident_types_covered)
            if not required_types.issubset(covered_types):
                return False

            # Requirement 4: Notification SLAs must be defined
            if self.security_breach_sla == NotificationSLA.NONE:
                return False
            if self.privacy_breach_sla == NotificationSLA.NONE:
                return False

            # Requirement 5: Lessons learned documented
            if not self.lessons_learned_documented:
                return False

            # Requirement 6: Plan accessible to employees
            if not self.plan_accessible_to_employees:
                return False

            return True

        except (ValueError, TypeError):
            return False

    def get_non_compliance_reasons(self) -> List[str]:
        """
        Get specific reasons why this evidence is non-compliant.

        Useful for reporting and remediation guidance.

        Returns:
            List[str]: List of non-compliance reasons (empty if compliant)
        """
        reasons = []

        # Check plan exists
        if not self.plan_exists:
            reasons.append("No documented incident response plan exists")
            return reasons  # No point checking other requirements

        # Check test recency
        if self.last_test_date is None:
            reasons.append("Incident response plan has never been tested")
        else:
            twelve_months_ago = date.today() - timedelta(days=365)
            if self.last_test_date < twelve_months_ago:
                reasons.append(
                    f"IR plan testing is older than 12 months (last tested on {self.last_test_date})"
                )

        # Check test type
        if self.test_type == TestType.NONE:
            reasons.append("No incident response test/exercise has been conducted")

        # Check incident type coverage
        required_types = {
            IncidentType.SECURITY_BREACH,
            IncidentType.PRIVACY_BREACH,
            IncidentType.RANSOMWARE,
        }
        covered_types = set(self.incident_types_covered)
        missing_types = required_types - covered_types

        if missing_types:
            missing_names = [t.value for t in missing_types]
            reasons.append(
                f"IR plan does not cover critical incident types: {', '.join(missing_names)}"
            )

        # Check notification SLAs
        if self.security_breach_sla == NotificationSLA.NONE:
            reasons.append("No notification SLA defined for security breaches")

        if self.privacy_breach_sla == NotificationSLA.NONE:
            reasons.append("No notification SLA defined for privacy breaches")

        # Check lessons learned
        if not self.lessons_learned_documented:
            reasons.append("Lessons learned from IR tests are not documented")

        # Check plan accessibility
        if not self.plan_accessible_to_employees:
            reasons.append("IR plan is not accessible to relevant employees")

        return reasons

    def get_total_requirements(self) -> int:
        """
        Incident Response has 6 core requirements that ASSURE checks.

        Requirements:
        1. Plan exists and is documented
        2. Plan tested within 12 months
        3. Covers critical incident types (security, privacy, ransomware)
        4. Notification SLAs defined for security breaches
        5. Notification SLAs defined for privacy breaches
        6. Lessons learned documented

        Returns:
            int: Total of 6 requirements
        """
        return 6

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 6 IR requirements pass validation.

        Returns:
            int: Number of passed requirements (0-6)
        """
        passed = 0

        # Requirement 1: Plan exists
        if self.plan_exists:
            passed += 1

        # Requirement 2: Tested within 12 months
        if self.last_test_date is not None:
            twelve_months_ago = date.today() - timedelta(days=365)
            if (
                self.last_test_date >= twelve_months_ago
                and self.test_type != TestType.NONE
            ):
                passed += 1

        # Requirement 3: Covers critical incident types
        required_types = {
            IncidentType.SECURITY_BREACH,
            IncidentType.PRIVACY_BREACH,
            IncidentType.RANSOMWARE,
        }
        covered_types = set(self.incident_types_covered)
        if required_types.issubset(covered_types):
            passed += 1

        # Requirement 4: Security breach notification SLA
        if self.security_breach_sla != NotificationSLA.NONE:
            passed += 1

        # Requirement 5: Privacy breach notification SLA
        if self.privacy_breach_sla != NotificationSLA.NONE:
            passed += 1

        # Requirement 6: Lessons learned documented
        if self.lessons_learned_documented:
            passed += 1

        return passed
