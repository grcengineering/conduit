"""Evidence Type #22: Right to Audit"""
from enum import Enum
from typing import Optional, List
from pydantic import Field, field_validator
from .base import BaseEvidence


class AuditFrequency(str, Enum):
    """Frequency of audit rights"""
    ANNUAL = "annual"  # Once per year
    SEMI_ANNUAL = "semi_annual"  # Twice per year
    QUARTERLY = "quarterly"  # Four times per year
    UPON_REQUEST = "upon_request"  # Anytime upon request
    UPON_CAUSE = "upon_cause"  # Only if cause exists


class AuditCostAllocation(str, Enum):
    """Who bears the cost of audits"""
    CUSTOMER = "customer"  # Customer pays
    VENDOR = "vendor"  # Vendor pays
    SHARED = "shared"  # Costs shared
    CUSTOMER_UNLESS_ISSUES = "customer_unless_issues"  # Customer pays unless issues found
    NOT_SPECIFIED = "not_specified"  # Not specified in contract


class RightToAuditEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Right to Audit

    ASSURE requires:
    1. Right to audit clause exists in contract
    2. Audit frequency at least annual (or upon request)
    3. Reasonable advance notice period (≤30 days)
    4. Audit scope includes security controls and data handling
    5. Customer or third-party auditor can perform audit
    6. Vendor cooperates with audit (access to systems, documentation, personnel)
    7. Cost allocation is reasonable (not prohibitive to customer)
    """

    evidence_type: str = Field(
        default="assure_022_audit_rights",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Audit rights existence
    audit_rights_granted: bool = Field(
        description="Whether customer has right to audit vendor"
    )

    audit_clause_location: Optional[str] = Field(
        default=None,
        description="Location of audit clause in contract (e.g., 'Section 8.4', 'Exhibit C')",
        max_length=200
    )

    # Audit frequency
    audit_frequency: Optional[AuditFrequency] = Field(
        default=None,
        description="How often customer can audit vendor"
    )

    audit_frequency_description: Optional[str] = Field(
        default=None,
        description="Detailed description of audit frequency",
        max_length=500
    )

    # Advance notice
    advance_notice_required: bool = Field(
        default=True,
        description="Whether advance notice is required before audit"
    )

    advance_notice_days: Optional[int] = Field(
        default=None,
        description="Required advance notice period in days",
        ge=0,
        le=90
    )

    # Audit scope
    audit_scope_defined: bool = Field(
        description="Whether audit scope is defined in contract"
    )

    audit_scope_includes_security: bool = Field(
        default=False,
        description="Whether audit scope explicitly includes security controls"
    )

    audit_scope_includes_data_handling: bool = Field(
        default=False,
        description="Whether audit scope includes data handling practices"
    )

    audit_scope_description: Optional[str] = Field(
        default=None,
        description="Description of what can be audited",
        max_length=1000
    )

    # Auditor selection
    third_party_auditor_allowed: bool = Field(
        default=True,
        description="Whether customer can engage third-party auditor"
    )

    auditor_qualifications_required: bool = Field(
        default=False,
        description="Whether auditor must meet specific qualifications (e.g., SOC 2 auditor)"
    )

    # Vendor cooperation
    vendor_cooperation_required: bool = Field(
        default=True,
        description="Whether vendor must cooperate with audit"
    )

    access_to_systems_granted: bool = Field(
        default=False,
        description="Whether auditor gets access to systems"
    )

    access_to_documentation_granted: bool = Field(
        default=False,
        description="Whether auditor gets access to documentation/policies"
    )

    access_to_personnel_granted: bool = Field(
        default=False,
        description="Whether auditor can interview vendor personnel"
    )

    # Cost allocation
    cost_allocation: Optional[AuditCostAllocation] = Field(
        default=None,
        description="Who bears the cost of audits"
    )

    cost_cap_amount: Optional[int] = Field(
        default=None,
        description="Maximum audit cost cap in USD (if applicable)",
        ge=0,
        le=1_000_000
    )

    # Audit reports
    audit_report_to_customer: bool = Field(
        default=True,
        description="Whether audit findings must be shared with customer"
    )

    remediation_plan_required: bool = Field(
        default=False,
        description="Whether vendor must provide remediation plan for audit findings"
    )

    @field_validator("audit_rights_granted")
    @classmethod
    def validate_audit_rights_exist(cls, v: bool) -> bool:
        """ASSURE requires right to audit clause"""
        if not v:
            raise ValueError(
                "No right to audit clause found in contract. "
                "ASSURE requires customer right to audit vendor security and data handling practices."
            )
        return v

    @field_validator("audit_frequency")
    @classmethod
    def validate_minimum_frequency(cls, v: Optional[AuditFrequency]) -> Optional[AuditFrequency]:
        """ASSURE requires at least annual audits or upon-request"""
        if v == AuditFrequency.UPON_CAUSE:
            raise ValueError(
                "Audit rights limited to 'upon cause' only. "
                "ASSURE requires audit rights at least annually or upon request."
            )
        return v

    @field_validator("advance_notice_days")
    @classmethod
    def validate_reasonable_notice(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE requires reasonable advance notice (≤30 days)"""
        if v is not None and v > 30:
            raise ValueError(
                f"Advance notice period is {v} days. "
                f"ASSURE requires reasonable advance notice (30 days or less)."
            )
        return v

    def get_total_requirements(self) -> int:
        """Total number of ASSURE requirements for audit rights evidence"""
        return 7

    def get_passed_requirements(self) -> int:
        """Count how many requirements are met"""
        passed = 0

        # 1. Audit rights clause exists
        if self.audit_rights_granted:
            passed += 1

        # 2. Audit frequency at least annual or upon request
        if self.audit_frequency in [AuditFrequency.ANNUAL, AuditFrequency.SEMI_ANNUAL,
                                    AuditFrequency.QUARTERLY, AuditFrequency.UPON_REQUEST]:
            passed += 1

        # 3. Reasonable advance notice (≤30 days)
        if not self.advance_notice_required or (self.advance_notice_days and self.advance_notice_days <= 30):
            passed += 1

        # 4. Audit scope includes security and data handling
        if self.audit_scope_includes_security and self.audit_scope_includes_data_handling:
            passed += 1

        # 5. Third-party auditor allowed
        if self.third_party_auditor_allowed:
            passed += 1

        # 6. Vendor cooperation required
        if self.vendor_cooperation_required and (self.access_to_systems_granted or
                                                 self.access_to_documentation_granted):
            passed += 1

        # 7. Cost allocation reasonable (not solely customer unless minimal cap)
        if self.cost_allocation in [AuditCostAllocation.VENDOR, AuditCostAllocation.SHARED,
                                    AuditCostAllocation.CUSTOMER_UNLESS_ISSUES]:
            passed += 1
        elif self.cost_allocation == AuditCostAllocation.CUSTOMER and self.cost_cap_amount and self.cost_cap_amount <= 50_000:
            passed += 1

        return passed
