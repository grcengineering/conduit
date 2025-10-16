"""ASSURE Control #23: SSO/MFA Requirements Evidence"""

from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import Field

from .base import BaseEvidence


class MFAType(Enum):
    """Types of MFA mechanisms"""

    AUTHENTICATOR_APP = "authenticator_app"  # TOTP (Google Auth, Authy)
    SMS = "sms"  # NOT phishing-resistant
    EMAIL = "email"  # NOT phishing-resistant
    HARDWARE_TOKEN = "hardware_token"  # YubiKey, FIDO2 - phishing-resistant
    PUSH_NOTIFICATION = "push_notification"  # Duo, Okta Verify
    BIOMETRIC = "biometric"  # Fingerprint, Face ID - phishing-resistant
    DEVICE_TRUST = "device_trust"  # Certificate-based - phishing-resistant


class SSOProtocol(Enum):
    """SSO protocols"""

    SAML = "saml"
    OIDC = "oidc"
    OAUTH2 = "oauth2"


class SSOMMFAEvidence(BaseEvidence):
    """
    ASSURE Control #23: SSO/MFA Requirements Evidence.

    This evidence type validates that vendors support SSO without paywalls
    and offer phishing-resistant MFA options.

    ASSURE Requirements:
    - SSO must be supported (SAML or other protocols)
    - SSO must NOT be behind a paywall (critical requirement!)
    - MFA must be available
    - Phishing-resistant MFA must be available (hardware token, device trust, biometric)

    Example:
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-16",
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML, SSOProtocol.OIDC],
            sso_requires_paid_plan=False,  # Critical!
            mfa_enforced_by_default=True,
            mfa_types_supported=[
                MFAType.AUTHENTICATOR_APP,
                MFAType.HARDWARE_TOKEN
            ],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE SSO/MFA requirements")
    """

    evidence_type: str = Field(default="assure_023_sso_mfa")

    # SSO Support (required)
    sso_supported: bool = Field(description="Does vendor support SSO?")
    sso_protocols: List[SSOProtocol] = Field(
        default_factory=list,
        description="SSO protocols supported (SAML, OIDC, OAuth2)",
    )
    sso_requires_paid_plan: bool = Field(
        description="Is SSO behind a paywall? (ASSURE PROHIBITS this - must be False)"
    )

    # MFA Configuration (required)
    mfa_enforced_by_default: bool = Field(
        description="Is MFA enforced for all users by default?"
    )
    mfa_types_supported: List[MFAType] = Field(
        min_length=1, description="MFA mechanisms available to users"
    )

    # Phishing resistance check
    phishing_resistant_mfa_available: bool = Field(
        description="Are phishing-resistant MFA methods available? (hardware token, device trust, biometric)"
    )

    # Additional details
    mfa_coverage_percentage: int = Field(
        ge=0,
        le=100,
        description="Percentage of users with MFA enabled",
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["CC6.1", "CC6.2"],
        description="SOC 2 logical access and authentication criteria",
    )
    soc2_coverage_percentage: int = Field(
        default=50,
        ge=0,
        le=100,
        description="SSO/MFA is partially covered in SOC 2 (paywall check is ASSURE-specific)",
    )

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. SSO must be supported
        2. SSO must NOT be behind a paywall (ASSURE critical requirement)
        3. MFA must be available (at least one type)
        4. Phishing-resistant MFA must be available

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        # SSO must be supported
        if not self.sso_supported:
            return False

        # SSO must NOT be behind paywall (critical ASSURE requirement)
        if self.sso_requires_paid_plan:
            return False

        # MFA must be available
        if len(self.mfa_types_supported) == 0:
            return False

        # Phishing-resistant MFA must be available
        if not self.phishing_resistant_mfa_available:
            return False

        return True

    def get_non_compliance_reasons(self) -> List[str]:
        """
        Get specific reasons why this evidence is non-compliant.

        Useful for reporting and remediation guidance.

        Returns:
            List[str]: List of non-compliance reasons (empty if compliant)
        """
        reasons = []

        if not self.sso_supported:
            reasons.append("SSO is not supported (ASSURE requires SSO support)")

        if self.sso_requires_paid_plan:
            reasons.append(
                "SSO requires paid plan (ASSURE PROHIBITS SSO paywalls - "
                "this is a critical vendor security practice issue)"
            )

        if len(self.mfa_types_supported) == 0:
            reasons.append("No MFA mechanisms available")

        if not self.phishing_resistant_mfa_available:
            reasons.append(
                "No phishing-resistant MFA available. ASSURE requires at least one of: "
                "hardware token, device trust, or biometric authentication"
            )

        return reasons

    def get_phishing_resistant_mfa_types(self) -> List[MFAType]:
        """
        Get list of phishing-resistant MFA types supported by vendor.

        Phishing-resistant MFA types:
        - Hardware tokens (YubiKey, FIDO2)
        - Device trust (certificate-based)
        - Biometric (fingerprint, Face ID)

        Returns:
            List[MFAType]: Phishing-resistant MFA types from mfa_types_supported
        """
        phishing_resistant = {
            MFAType.HARDWARE_TOKEN,
            MFAType.DEVICE_TRUST,
            MFAType.BIOMETRIC,
        }

        return [mfa for mfa in self.mfa_types_supported if mfa in phishing_resistant]

    def get_non_phishing_resistant_mfa_types(self) -> List[MFAType]:
        """
        Get list of non-phishing-resistant MFA types supported by vendor.

        Non-phishing-resistant MFA types:
        - SMS (vulnerable to SIM swapping)
        - Email (vulnerable to email compromise)
        - Push notifications (can be phished with MFA fatigue attacks)
        - Authenticator apps (TOTP can be phished with real-time attacks)

        Returns:
            List[MFAType]: Non-phishing-resistant MFA types from mfa_types_supported
        """
        non_phishing_resistant = {
            MFAType.SMS,
            MFAType.EMAIL,
            MFAType.PUSH_NOTIFICATION,
            MFAType.AUTHENTICATOR_APP,
        }

        return [mfa for mfa in self.mfa_types_supported if mfa in non_phishing_resistant]

    def get_total_requirements(self) -> int:
        """
        SSO/MFA has 4 core requirements that ASSURE checks.

        Requirements:
        1. SSO supported
        2. SSO not behind paywall (critical!)
        3. MFA available (at least one type)
        4. Phishing-resistant MFA available

        Returns:
            int: Total of 4 requirements
        """
        return 4

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 4 SSO/MFA requirements pass validation.

        Returns:
            int: Number of passed requirements (0-4)
        """
        passed = 0

        # Requirement 1: SSO supported
        if self.sso_supported:
            passed += 1

        # Requirement 2: SSO not behind paywall (CRITICAL!)
        if not self.sso_requires_paid_plan:
            passed += 1

        # Requirement 3: MFA available (at least one type)
        if len(self.mfa_types_supported) > 0:
            passed += 1

        # Requirement 4: Phishing-resistant MFA available
        if self.phishing_resistant_mfa_available:
            passed += 1

        return passed
