"""Base evidence class for all CONDUIT evidence types"""

from pydantic import BaseModel, Field
from datetime import date
from typing import Optional, List


class BaseEvidence(BaseModel):
    """
    Base class for all CONDUIT evidence types.

    Provides common fields and behavior shared across all 24 ASSURE evidence types:
    - Vendor identification
    - Evidence metadata (date, confidence)
    - SOC 2 overlap mapping
    - Compliance checking interface

    All evidence types must:
    1. Inherit from this class
    2. Override evidence_type with specific value
    3. Implement is_compliant() method
    """

    # Core metadata (required for all evidence types)
    evidence_type: str = Field(
        description="Unique identifier for this evidence type (e.g., 'assure_007_bcpdr_testing')"
    )
    vendor_name: str = Field(
        min_length=1,
        description="Name of the vendor providing this evidence"
    )
    evidence_date: date = Field(
        description="Date when this evidence was generated or last updated"
    )

    # SOC 2 overlap (helps identify gaps)
    soc2_section_4_criteria: List[str] = Field(
        default_factory=list,
        description="SOC 2 Trust Service Criteria this evidence maps to (e.g., ['CC7.1', 'A1.3'])"
    )
    soc2_coverage_percentage: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Percentage of this ASSURE control covered by SOC 2 (0-100)"
    )

    # LLM extraction metadata
    extraction_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score from LLM extraction (0.0 = low confidence, 1.0 = high confidence)"
    )
    source_document: Optional[str] = Field(
        default=None,
        description="Source document this evidence was extracted from (e.g., 'soc2_report.pdf, page 45')"
    )

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Subclasses MUST override this method to implement control-specific
        compliance logic (e.g., date recency checks, SLA validation, etc.).

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise

        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement is_compliant() method"
        )

    def get_total_requirements(self) -> int:
        """
        Get the total number of requirements for this evidence type.

        Subclasses MUST override this method to return the count of
        sub-requirements that make up this control (e.g., BCP/DR has 3).

        Returns:
            int: Total number of requirements

        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement get_total_requirements() method"
        )

    def get_passed_requirements(self) -> int:
        """
        Get the number of requirements that passed validation.

        Subclasses MUST override this method to count how many
        sub-requirements pass validation (e.g., 2 out of 3 BCP/DR checks).

        Returns:
            int: Number of passed requirements

        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement get_passed_requirements() method"
        )

    def get_compliance_percentage(self) -> float:
        """
        Calculate the compliance percentage for this evidence.

        Uses the simple formula: (passed_requirements / total_requirements) * 100

        This provides a transparent, auditable metric that replaces complex
        0.0-1.0 "strength" scores with clear pass/fail counting.

        Returns:
            float: Compliance percentage (0.0 to 100.0)

        Example:
            If 6 out of 8 sub-requirements pass: 6/8 * 100 = 75.0%
        """
        total = self.get_total_requirements()
        if total == 0:
            return 0.0
        passed = self.get_passed_requirements()
        return (passed / total) * 100.0

    def get_compliance_status(self) -> str:
        """
        Get the compliance status based on percentage thresholds.

        Status thresholds:
        - compliant: >= 85%
        - partially_compliant: 50-84%
        - non_compliant: < 50%

        Returns:
            str: One of 'compliant', 'partially_compliant', 'non_compliant'
        """
        percentage = self.get_compliance_percentage()
        if percentage >= 85:
            return "compliant"
        elif percentage >= 50:
            return "partially_compliant"
        else:
            return "non_compliant"

    class Config:
        """Pydantic configuration"""
        json_schema_extra = {
            "description": "Base evidence type for CONDUIT framework"
        }
