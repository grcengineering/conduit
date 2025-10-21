"""Evidence Type #18: Security Testing"""
from enum import Enum
from typing import List, Optional
from pydantic import Field
from .base import BaseEvidence

class SecurityTestingTool(str, Enum):
    SAST = "sast"  # Static Application Security Testing
    DAST = "dast"  # Dynamic Application Security Testing
    SCA = "sca"  # Software Composition Analysis
    IAST = "iast"  # Interactive Application Security Testing
    MANUAL_PENTEST = "manual_pentest"

class SecurityTestingEvidence(BaseEvidence):
    evidence_type: str = Field(default="assure_018_security_testing", frozen=True)

    # Testing types
    testing_tools_used: List[SecurityTestingTool] = Field(min_length=1)
    sast_enabled: bool
    dast_enabled: bool
    sca_enabled: bool

    # Integration
    integrated_in_cicd: bool
    cicd_blocks_on_findings: bool = False

    # Frequency
    testing_frequency: str = Field(max_length=200)
    last_test_date: Optional[str] = Field(default=None, max_length=50)

    # Remediation
    finding_remediation_sla_days: Optional[int] = Field(default=None, ge=1, le=180)
    high_severity_sla_days: Optional[int] = Field(default=None, ge=1, le=90)

    def get_total_requirements(self) -> int:
        return 8

    def get_passed_requirements(self) -> int:
        passed = 0
        if self.sast_enabled: passed += 1
        if self.dast_enabled or self.sca_enabled: passed += 1
        if len(self.testing_tools_used) >= 2: passed += 1
        if self.integrated_in_cicd: passed += 1
        if self.cicd_blocks_on_findings: passed += 1
        if self.testing_frequency: passed += 1
        if self.finding_remediation_sla_days and self.finding_remediation_sla_days <= 90: passed += 1
        if self.high_severity_sla_days and self.high_severity_sla_days <= 30: passed += 1
        return passed
