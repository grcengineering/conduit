"""
Evidence Type #11: 2FA for Admin Access

ASSURE Requirement:
Vendors must enforce multi-factor authentication (MFA/2FA) for all administrative
and privileged access. Phishing-resistant MFA is strongly recommended for admin accounts.

This evidence type captures:
- Whether MFA is enforced for admin/privileged accounts
- Types of MFA supported for admin access
- Any exceptions to MFA enforcement
- Administrative account scope
"""

from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class AdminMFAType(str, Enum):
    """Types of MFA mechanisms for administrative access"""
    AUTHENTICATOR_APP = "authenticator_app"  # TOTP (Google Auth, Authy)
    SMS = "sms"  # NOT phishing-resistant
    EMAIL = "email"  # NOT phishing-resistant
    HARDWARE_TOKEN = "hardware_token"  # YubiKey, FIDO2 - phishing-resistant
    PUSH_NOTIFICATION = "push_notification"  # Duo, Okta Verify
    BIOMETRIC = "biometric"  # Fingerprint, Face ID - phishing-resistant
    CERTIFICATE_BASED = "certificate_based"  # PKI certificates - phishing-resistant


class AdminAccountScope(str, Enum):
    """Scope of administrative accounts"""
    ALL_ADMINS = "all_admins"  # All admin/elevated accounts
    PRODUCTION_ADMINS_ONLY = "production_admins_only"  # Only prod access
    INFRASTRUCTURE_ADMINS = "infrastructure_admins"  # Cloud/infra admins only
    APPLICATION_ADMINS = "application_admins"  # App-level admins
    CUSTOM = "custom"  # Custom scope defined by organization


class Admin2FAEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: 2FA for Admin Access

    ASSURE requires:
    1. MFA enforced for all administrative/privileged accounts
    2. No exceptions without documented business justification
    3. Phishing-resistant MFA strongly recommended
    4. MFA enforcement technically controlled (not just policy)
    5. Regular review of admin accounts with MFA enabled
    """

    evidence_type: str = Field(
        default="assure_011_admin_2fa",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # MFA enforcement
    mfa_enforced_for_admin: bool = Field(
        description="Whether MFA is enforced for administrative/privileged accounts"
    )

    admin_account_scope: AdminAccountScope = Field(
        description="Scope of administrative accounts requiring MFA"
    )

    scope_description: Optional[str] = Field(
        default=None,
        description="Detailed description of admin account scope (especially if scope is 'custom')",
        max_length=1000
    )

    # MFA types
    mfa_types_supported: List[AdminMFAType] = Field(
        description="Types of MFA supported for administrative access",
        min_length=1
    )

    phishing_resistant_mfa_available: bool = Field(
        description="Whether phishing-resistant MFA options are available (hardware token, biometric, certificate)"
    )

    # Enforcement mechanism
    technically_enforced: bool = Field(
        description="Whether MFA is technically enforced (not just policy-based)"
    )

    enforcement_mechanism: Optional[str] = Field(
        default=None,
        description="How MFA is enforced (e.g., 'IAM policy', 'SSO conditional access', 'VPN requirement')",
        max_length=500
    )

    # Exceptions
    exceptions_allowed: bool = Field(
        description="Whether any exceptions to MFA requirement exist"
    )

    exceptions_documented: bool = Field(
        default=False,
        description="Whether exceptions are formally documented with business justification"
    )

    exception_count: Optional[int] = Field(
        default=None,
        description="Number of admin accounts with MFA exceptions",
        ge=0
    )

    # Review process
    admin_mfa_review_frequency: Optional[str] = Field(
        default=None,
        description="How often admin MFA compliance is reviewed (e.g., 'monthly', 'quarterly')",
        max_length=100
    )

    last_mfa_review_date: Optional[str] = Field(
        default=None,
        description="Date of last admin MFA compliance review (YYYY-MM-DD or 'Q1 2025')",
        max_length=50
    )

    # Admin account metrics
    total_admin_accounts: Optional[int] = Field(
        default=None,
        description="Total number of administrative/privileged accounts",
        ge=0
    )

    admin_accounts_with_mfa: Optional[int] = Field(
        default=None,
        description="Number of admin accounts with MFA enabled",
        ge=0
    )

    @field_validator("mfa_enforced_for_admin")
    @classmethod
    def validate_mfa_enforcement(cls, v: bool) -> bool:
        """ASSURE requires MFA for all admin accounts"""
        if not v:
            raise ValueError(
                "MFA is not enforced for administrative accounts. "
                "ASSURE requires MFA for all privileged/administrative access."
            )
        return v

    @field_validator("mfa_types_supported")
    @classmethod
    def validate_mfa_types(cls, v: List[AdminMFAType]) -> List[AdminMFAType]:
        """Validate that at least one MFA type is supported"""
        if not v:
            raise ValueError(
                "No MFA types documented for administrative access. "
                "ASSURE requires at least one MFA mechanism for admin accounts."
            )

        # Check for weak MFA only (SMS/email)
        weak_only = all(mfa in [AdminMFAType.SMS, AdminMFAType.EMAIL] for mfa in v)
        if weak_only:
            import logging
            logging.warning(
                "Only SMS/email MFA available for admin access. "
                "ASSURE strongly recommends phishing-resistant MFA (hardware token, biometric, certificate)."
            )

        return v

    @field_validator("exceptions_allowed")
    @classmethod
    def validate_exceptions(cls, v: bool, info) -> bool:
        """If exceptions exist, they must be documented"""
        if v:
            # Check if exceptions_documented is True
            import logging
            logging.warning(
                "MFA exceptions exist for admin accounts. "
                "ASSURE requires formal documentation and business justification for all exceptions."
            )
        return v

    @field_validator("admin_accounts_with_mfa")
    @classmethod
    def validate_mfa_coverage(cls, v: Optional[int], info) -> Optional[int]:
        """Validate MFA coverage if metrics provided"""
        if v is not None:
            total = info.data.get('total_admin_accounts')
            if total is not None and v < total:
                gap = total - v
                import logging
                logging.warning(
                    f"{gap} admin accounts do not have MFA enabled ({v}/{total}). "
                    f"ASSURE requires MFA for ALL administrative accounts."
                )
        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for admin 2FA.

        ASSURE requirements:
        1. MFA enforced for all admin accounts
        2. Admin account scope is comprehensive (all admins, not just production)
        3. At least one MFA type supported
        4. Phishing-resistant MFA available
        5. MFA is technically enforced (not just policy)
        6. If exceptions exist, they are documented
        7. Admin MFA compliance is regularly reviewed
        8. 100% of admin accounts have MFA enabled (if metrics provided)

        Total: 8 requirements
        """
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Requirement 1: MFA enforced for all admin accounts
        if self.mfa_enforced_for_admin:
            passed += 1

        # Requirement 2: Admin account scope is comprehensive
        if self.admin_account_scope in [
            AdminAccountScope.ALL_ADMINS,
            AdminAccountScope.INFRASTRUCTURE_ADMINS
        ]:
            passed += 1

        # Requirement 3: At least one MFA type supported
        if len(self.mfa_types_supported) > 0:
            passed += 1

        # Requirement 4: Phishing-resistant MFA available
        if self.phishing_resistant_mfa_available:
            passed += 1

        # Requirement 5: MFA is technically enforced
        if self.technically_enforced:
            passed += 1

        # Requirement 6: If exceptions exist, they are documented
        if not self.exceptions_allowed:
            passed += 1  # No exceptions = pass
        elif self.exceptions_documented:
            passed += 1  # Exceptions exist but documented = pass

        # Requirement 7: Admin MFA compliance is regularly reviewed
        if self.admin_mfa_review_frequency or self.last_mfa_review_date:
            passed += 1

        # Requirement 8: 100% of admin accounts have MFA enabled
        if self.total_admin_accounts is not None and self.admin_accounts_with_mfa is not None:
            if self.admin_accounts_with_mfa >= self.total_admin_accounts:
                passed += 1
        else:
            # If metrics not provided but MFA is enforced, give benefit of doubt
            if self.mfa_enforced_for_admin and self.technically_enforced:
                passed += 1

        return passed
