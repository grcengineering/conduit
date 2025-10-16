"""ASSURE Control #7: BCP/DR Testing Evidence"""

from datetime import date, timedelta
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from .base import BaseEvidence


class TestResult(Enum):
    """BCP/DR test outcome"""

    PASS = "pass"
    PASS_WITH_FINDINGS = "pass_with_findings"
    FAIL = "fail"


class TestType(Enum):
    """Type of BCP/DR test conducted"""

    TABLETOP = "tabletop"
    PARTIAL_FAILOVER = "partial_failover"
    FULL_FAILOVER = "full_failover"


class BCPDRFinding(BaseModel):
    """Individual finding from BCP/DR test"""

    finding: str = Field(min_length=1, description="Description of the finding")
    severity: str = Field(
        pattern="^(critical|high|medium|low)$",
        description="Severity level of the finding",
    )
    remediation_status: str = Field(
        pattern="^(open|in_progress|resolved)$",
        description="Current status of remediation",
    )


class BCPDREvidence(BaseEvidence):
    """
    ASSURE Control #7: BCP/DR Testing Evidence.

    This evidence type validates that vendors conduct regular Business Continuity
    and Disaster Recovery testing to ensure they can recover from incidents.

    ASSURE Requirements:
    - Test must be conducted within the last 12 months
    - Test must show pass or pass with findings (fail is non-compliant)
    - Test scope must be documented

    Example:
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-16",
            test_date="2025-01-15",
            test_result="pass",
            test_type="full_failover",
            scope="Production database and application servers",
            extraction_confidence=0.95
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE BCP/DR requirements")
    """

    evidence_type: str = Field(default="assure_007_bcpdr_testing")

    # Core evidence data (required)
    test_date: date = Field(description="Date of most recent BCP/DR test")
    test_result: TestResult = Field(description="Outcome of the test")
    test_type: TestType = Field(description="Type of test conducted")
    scope: str = Field(
        min_length=1, description="Systems/services included in test scope"
    )

    # Optional details
    findings: List[BCPDRFinding] = Field(
        default_factory=list, description="Findings identified during test"
    )
    recovery_time_objective_met: Optional[bool] = Field(
        default=None, description="Was RTO achieved during test?"
    )
    recovery_point_objective_met: Optional[bool] = Field(
        default=None, description="Was RPO achieved during test?"
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["A1.3"],
        description="SOC 2 availability criteria for business continuity",
    )
    soc2_coverage_percentage: int = Field(
        default=90,
        ge=0,
        le=100,
        description="BCP/DR testing is typically 90% covered in SOC 2",
    )

    @field_validator("test_date")
    @classmethod
    def validate_recency(cls, v: date) -> date:
        """
        Validate that BCP/DR test is within the last 12 months.

        ASSURE requires vendors to conduct BCP/DR testing at least annually.

        Args:
            v: The test date to validate

        Returns:
            date: The validated test date

        Raises:
            ValueError: If test date is older than 12 months
        """
        twelve_months_ago = date.today() - timedelta(days=365)
        if v < twelve_months_ago:
            raise ValueError(
                f"BCP/DR test date {v} is older than 12 months "
                f"(before {twelve_months_ago}). "
                f"ASSURE requires testing within the last year."
            )
        return v

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. Test date is within last 12 months (validated by @field_validator)
        2. Test result is PASS or PASS_WITH_FINDINGS (FAIL is non-compliant)

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        try:
            # Recency check (handled by validator, but we call it here for safety)
            self.validate_recency(self.test_date)

            # Result check: PASS or PASS_WITH_FINDINGS is acceptable
            return self.test_result in [TestResult.PASS, TestResult.PASS_WITH_FINDINGS]

        except ValueError:
            # Test date is too old
            return False

    def get_non_compliance_reasons(self) -> List[str]:
        """
        Get specific reasons why this evidence is non-compliant.

        Useful for reporting and remediation guidance.

        Returns:
            List[str]: List of non-compliance reasons (empty if compliant)
        """
        reasons = []

        # Check test recency
        twelve_months_ago = date.today() - timedelta(days=365)
        if self.test_date < twelve_months_ago:
            reasons.append(
                f"BCP/DR test is older than 12 months (tested on {self.test_date})"
            )

        # Check test result
        if self.test_result == TestResult.FAIL:
            reasons.append("BCP/DR test failed (ASSURE requires passing test)")

        return reasons

    def get_total_requirements(self) -> int:
        """
        BCP/DR has 3 core requirements that ASSURE checks.

        Requirements:
        1. Test date recency (within 12 months)
        2. Test result (must pass or pass with findings)
        3. Test scope (must be documented)

        Returns:
            int: Total of 3 requirements
        """
        return 3

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 3 BCP/DR requirements pass validation.

        Returns:
            int: Number of passed requirements (0-3)
        """
        passed = 0

        # Requirement 1: Test within 12 months
        twelve_months_ago = date.today() - timedelta(days=365)
        if self.test_date >= twelve_months_ago:
            passed += 1

        # Requirement 2: Test passed (or passed with findings)
        if self.test_result in [TestResult.PASS, TestResult.PASS_WITH_FINDINGS]:
            passed += 1

        # Requirement 3: Scope documented (non-empty string)
        if self.scope and len(self.scope.strip()) > 0:
            passed += 1

        return passed
