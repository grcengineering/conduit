"""Evidence Type #19: Service Level Agreements"""
from enum import Enum
from typing import Optional
from datetime import date
from pydantic import Field, field_validator
from .base import BaseEvidence


class SLAType(str, Enum):
    """Types of SLA metrics"""
    AVAILABILITY = "availability"  # System uptime
    RESPONSE_TIME = "response_time"  # Incident response time
    RESOLUTION_TIME = "resolution_time"  # Incident resolution time
    PERFORMANCE = "performance"  # Application performance
    SUPPORT = "support"  # Support ticket SLA


class SLAViolationRemedy(str, Enum):
    """Remedies for SLA violations"""
    SERVICE_CREDITS = "service_credits"  # Financial credits
    REFUND = "refund"  # Partial/full refund
    CONTRACT_TERMINATION = "contract_termination"  # Right to terminate
    NO_REMEDY = "no_remedy"  # No specific remedy
    OTHER = "other"  # Other remedy


class ServiceLevelAgreementEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Service Level Agreements

    ASSURE requires:
    1. Documented SLAs exist in contract/MSA
    2. Availability SLA ≥99.9% (three nines minimum)
    3. Incident response time SLAs defined
    4. Incident resolution time SLAs defined
    5. Financial remedies for SLA violations (service credits)
    6. SLA performance monitoring and reporting
    7. SLAs cover critical services
    """

    evidence_type: str = Field(
        default="assure_019_sla",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # SLA existence
    sla_documented: bool = Field(
        description="Whether SLAs are formally documented in contract/MSA"
    )

    sla_location: Optional[str] = Field(
        default=None,
        description="Where SLAs are documented (e.g., 'Exhibit A', 'Service Schedule')",
        max_length=200
    )

    # Availability SLA
    availability_sla_exists: bool = Field(
        description="Whether an availability/uptime SLA is defined"
    )

    availability_percentage: Optional[float] = Field(
        default=None,
        description="Committed availability percentage (e.g., 99.9, 99.95, 99.99)",
        ge=90.0,
        le=100.0
    )

    availability_measurement_period: Optional[str] = Field(
        default=None,
        description="Measurement period for availability (e.g., 'monthly', 'quarterly')",
        max_length=100
    )

    # Response time SLA
    response_time_sla_exists: bool = Field(
        description="Whether incident response time SLAs are defined"
    )

    critical_incident_response_hours: Optional[int] = Field(
        default=None,
        description="Response time for critical incidents (in hours)",
        ge=0,
        le=72
    )

    high_incident_response_hours: Optional[int] = Field(
        default=None,
        description="Response time for high-priority incidents (in hours)",
        ge=0,
        le=168
    )

    # Resolution time SLA
    resolution_time_sla_exists: bool = Field(
        description="Whether incident resolution time SLAs are defined"
    )

    critical_incident_resolution_hours: Optional[int] = Field(
        default=None,
        description="Resolution time for critical incidents (in hours)",
        ge=0,
        le=168
    )

    # Remedies for violations
    violation_remedies_defined: bool = Field(
        description="Whether remedies for SLA violations are defined"
    )

    violation_remedy_type: Optional[SLAViolationRemedy] = Field(
        default=None,
        description="Type of remedy for SLA violations"
    )

    service_credits_available: bool = Field(
        default=False,
        description="Whether service credits are available for SLA violations"
    )

    service_credit_percentage: Optional[float] = Field(
        default=None,
        description="Percentage of service credits for violations (e.g., 10.0 for 10%)",
        ge=0.0,
        le=100.0
    )

    # Monitoring and reporting
    sla_performance_monitored: bool = Field(
        default=False,
        description="Whether SLA performance is actively monitored"
    )

    sla_reporting_frequency: Optional[str] = Field(
        default=None,
        description="Frequency of SLA performance reporting (e.g., 'monthly', 'quarterly')",
        max_length=50
    )

    public_status_page: bool = Field(
        default=False,
        description="Whether vendor provides public status page for transparency"
    )

    # Scope
    sla_covers_critical_services: bool = Field(
        default=True,
        description="Whether SLAs cover all critical/production services"
    )

    @field_validator("sla_documented")
    @classmethod
    def validate_sla_exists(cls, v: bool) -> bool:
        """ASSURE requires documented SLAs"""
        if not v:
            raise ValueError(
                "No documented SLAs found. "
                "ASSURE requires formal SLAs in vendor contracts."
            )
        return v

    @field_validator("availability_percentage")
    @classmethod
    def validate_availability_minimum(cls, v: Optional[float]) -> Optional[float]:
        """ASSURE requires ≥99.9% availability SLA"""
        if v is not None and v < 99.9:
            raise ValueError(
                f"Availability SLA is {v}%. "
                f"ASSURE requires minimum 99.9% availability (three nines)."
            )
        return v

    @field_validator("violation_remedies_defined")
    @classmethod
    def validate_remedies_exist(cls, v: bool) -> bool:
        """ASSURE requires financial remedies for SLA violations"""
        if not v:
            raise ValueError(
                "No remedies defined for SLA violations. "
                "ASSURE requires financial remedies (e.g., service credits) for violations."
            )
        return v

    def get_total_requirements(self) -> int:
        """Total number of ASSURE requirements for SLA evidence"""
        return 7

    def get_passed_requirements(self) -> int:
        """Count how many requirements are met"""
        passed = 0

        # 1. Documented SLAs exist
        if self.sla_documented:
            passed += 1

        # 2. Availability SLA ≥99.9%
        if self.availability_sla_exists and self.availability_percentage and self.availability_percentage >= 99.9:
            passed += 1

        # 3. Response time SLAs defined
        if self.response_time_sla_exists and self.critical_incident_response_hours is not None:
            passed += 1

        # 4. Resolution time SLAs defined
        if self.resolution_time_sla_exists and self.critical_incident_resolution_hours is not None:
            passed += 1

        # 5. Financial remedies for violations
        if self.violation_remedies_defined and self.service_credits_available:
            passed += 1

        # 6. SLA performance monitoring
        if self.sla_performance_monitored:
            passed += 1

        # 7. SLAs cover critical services
        if self.sla_covers_critical_services:
            passed += 1

        return passed
