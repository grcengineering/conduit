"""Evidence Type #21: Insurance Coverage"""
from enum import Enum
from typing import Optional
from datetime import date
from pydantic import Field, field_validator
from .base import BaseEvidence


class InsuranceType(str, Enum):
    """Types of insurance coverage"""
    CYBER_LIABILITY = "cyber_liability"  # Cyber/data breach insurance
    ERRORS_OMISSIONS = "errors_omissions"  # E&O/Professional liability
    GENERAL_LIABILITY = "general_liability"  # General liability
    UMBRELLA = "umbrella"  # Umbrella/excess coverage
    TECHNOLOGY_EO = "technology_eo"  # Technology E&O


class InsuranceCoverageEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Insurance Coverage

    ASSURE requires:
    1. Cyber liability insurance exists
    2. Coverage amount ≥$1M minimum ($5M+ preferred)
    3. Errors & Omissions (E&O) coverage exists
    4. Policy is current (not expired)
    5. Certificate of Insurance available on request
    6. Customer named as additional insured (optional but preferred)
    """

    evidence_type: str = Field(
        default="assure_021_insurance",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Cyber liability insurance
    cyber_insurance_exists: bool = Field(
        description="Whether vendor has cyber liability insurance"
    )

    cyber_insurance_carrier: Optional[str] = Field(
        default=None,
        description="Name of cyber insurance carrier",
        max_length=200
    )

    cyber_coverage_amount: Optional[int] = Field(
        default=None,
        description="Cyber insurance coverage amount in USD",
        ge=0,
        le=100_000_000  # $100M max
    )

    cyber_policy_number: Optional[str] = Field(
        default=None,
        description="Cyber insurance policy number",
        max_length=100
    )

    cyber_policy_expiry_date: Optional[date] = Field(
        default=None,
        description="Cyber insurance policy expiration date"
    )

    # Errors & Omissions insurance
    eo_insurance_exists: bool = Field(
        description="Whether vendor has Errors & Omissions (professional liability) insurance"
    )

    eo_insurance_carrier: Optional[str] = Field(
        default=None,
        description="Name of E&O insurance carrier",
        max_length=200
    )

    eo_coverage_amount: Optional[int] = Field(
        default=None,
        description="E&O insurance coverage amount in USD",
        ge=0,
        le=100_000_000
    )

    eo_policy_expiry_date: Optional[date] = Field(
        default=None,
        description="E&O insurance policy expiration date"
    )

    # Combined coverage
    combined_coverage_amount: Optional[int] = Field(
        default=None,
        description="Total combined insurance coverage (cyber + E&O) in USD",
        ge=0,
        le=200_000_000
    )

    # Certificate availability
    certificate_of_insurance_available: bool = Field(
        default=False,
        description="Whether Certificate of Insurance (COI) is available on request"
    )

    certificate_provided_to_customer: bool = Field(
        default=False,
        description="Whether COI has been provided to customer"
    )

    # Additional insured
    customer_named_as_additional_insured: bool = Field(
        default=False,
        description="Whether customer can be named as additional insured"
    )

    # Policy currency
    policy_is_current: bool = Field(
        default=True,
        description="Whether all insurance policies are current (not expired)"
    )

    @field_validator("cyber_insurance_exists")
    @classmethod
    def validate_cyber_insurance(cls, v: bool) -> bool:
        """ASSURE requires cyber liability insurance"""
        if not v:
            raise ValueError(
                "No cyber liability insurance found. "
                "ASSURE requires vendors to maintain cyber/data breach insurance."
            )
        return v

    @field_validator("cyber_coverage_amount")
    @classmethod
    def validate_minimum_coverage(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE requires minimum $1M coverage"""
        if v is not None and v < 1_000_000:
            raise ValueError(
                f"Cyber insurance coverage is ${v:,}. "
                f"ASSURE requires minimum $1,000,000 cyber liability coverage."
            )
        return v

    @field_validator("cyber_policy_expiry_date")
    @classmethod
    def validate_policy_not_expired(cls, v: Optional[date]) -> Optional[date]:
        """ASSURE requires current (non-expired) policies"""
        if v is not None:
            from datetime import datetime
            if v < datetime.now().date():
                raise ValueError(
                    f"Cyber insurance policy expired on {v}. "
                    f"ASSURE requires current insurance policies."
                )
        return v

    def get_total_requirements(self) -> int:
        """Total number of ASSURE requirements for insurance evidence"""
        return 6

    def get_passed_requirements(self) -> int:
        """Count how many requirements are met"""
        passed = 0

        # 1. Cyber liability insurance exists
        if self.cyber_insurance_exists:
            passed += 1

        # 2. Coverage amount ≥$1M
        if self.cyber_coverage_amount and self.cyber_coverage_amount >= 1_000_000:
            passed += 1

        # 3. E&O coverage exists
        if self.eo_insurance_exists:
            passed += 1

        # 4. Policy is current (not expired)
        if self.policy_is_current:
            passed += 1

        # 5. Certificate available on request
        if self.certificate_of_insurance_available:
            passed += 1

        # 6. Customer can be named as additional insured (optional but preferred)
        if self.customer_named_as_additional_insured:
            passed += 1

        return passed
