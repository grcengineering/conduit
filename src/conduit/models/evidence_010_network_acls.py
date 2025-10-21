"""Evidence Type #10: Network ACLs"""
from enum import Enum
from typing import Optional
from pydantic import Field, field_validator
from .base import BaseEvidence

class ACLReviewFrequency(str, Enum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"
    ANNUAL = "annual"

class NetworkACLEvidence(BaseEvidence):
    evidence_type: str = Field(default="assure_010_network_acls", frozen=True)

    # Default deny
    default_deny_policy: bool
    network_segmentation_implemented: bool

    # ACL management
    acl_review_frequency: ACLReviewFrequency
    last_acl_review_date: Optional[str] = Field(default=None, max_length=50)

    # Enforcement
    acl_changes_require_approval: bool
    acl_changes_logged: bool = False

    # Tools
    acl_management_tool: Optional[str] = Field(default=None, max_length=200)
    automated_acl_testing: bool = False

    @field_validator("default_deny_policy")
    @classmethod
    def validate_default_deny(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Default deny policy not implemented. ASSURE requires default deny for network ACLs.")
        return v

    def get_total_requirements(self) -> int:
        return 7

    def get_passed_requirements(self) -> int:
        passed = 0
        if self.default_deny_policy: passed += 1
        if self.network_segmentation_implemented: passed += 1
        if self.acl_review_frequency in [ACLReviewFrequency.MONTHLY, ACLReviewFrequency.QUARTERLY]: passed += 1
        if self.acl_changes_require_approval: passed += 1
        if self.acl_changes_logged: passed += 1
        if self.acl_management_tool: passed += 1
        if self.automated_acl_testing: passed += 1
        return passed
