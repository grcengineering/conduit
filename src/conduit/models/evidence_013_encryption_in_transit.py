"""ASSURE Control #13: Encryption in Transit Requirements Evidence"""

from datetime import date, timedelta
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class TLSVersion(Enum):
    """TLS versions supported for encryption in transit"""

    TLS_1_3 = "tls_1_3"  # Recommended
    TLS_1_2 = "tls_1_2"  # Minimum acceptable


class WeakProtocol(Enum):
    """Weak/deprecated protocols that must be blocked"""

    TLS_1_1 = "tls_1_1"  # Deprecated
    TLS_1_0 = "tls_1_0"  # Deprecated
    SSL_V3 = "ssl_v3"  # Vulnerable to POODLE
    SSL_V2 = "ssl_v2"  # Critically insecure


class CertificateAuthority(Enum):
    """Certificate authority providers"""

    LETSENCRYPT = "letsencrypt"
    DIGICERT = "digicert"
    COMODO = "comodo"
    GLOBALSIGN = "globalsign"
    SECTIGO = "sectigo"
    INTERNAL = "internal"  # Self-signed or internal CA
    OTHER = "other"


class EncryptionInTransitEvidence(BaseEvidence):
    """
    ASSURE Control #13: Encryption in Transit Requirements Evidence.

    This evidence type validates that vendors use TLS 1.2+ for all data in transit
    and explicitly block weak/deprecated protocols.

    ASSURE Requirements:
    - TLS 1.2 or higher must be supported
    - Weak protocols (TLS 1.1, 1.0, SSL v3, SSL v2) must be explicitly blocked
    - Valid certificate from trusted authority
    - Certificate must not be expired or expiring soon (within 30 days)

    Example:
        evidence = EncryptionInTransitEvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-16",
            tls_versions_supported=[TLSVersion.TLS_1_3, TLSVersion.TLS_1_2],
            weak_protocols_blocked=[
                WeakProtocol.TLS_1_1,
                WeakProtocol.TLS_1_0,
                WeakProtocol.SSL_V3,
                WeakProtocol.SSL_V2
            ],
            certificate_authority=CertificateAuthority.LETSENCRYPT,
            certificate_expiry_date="2026-12-15",
            qualys_ssl_grade="A",
            forward_secrecy_enabled=True,
            extraction_confidence=0.90
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE encryption in transit requirements")
    """

    evidence_type: str = Field(default="assure_013_encryption_in_transit")

    # TLS Support (required)
    tls_versions_supported: List[TLSVersion] = Field(
        min_length=1,
        description="TLS versions supported (must include TLS 1.2 or higher)",
    )

    # Weak Protocol Blocking (required)
    weak_protocols_blocked: List[WeakProtocol] = Field(
        default_factory=list,
        description="Weak/deprecated protocols explicitly blocked (SSL v2, SSL v3, TLS 1.0, TLS 1.1)",
    )

    # Certificate Information
    certificate_authority: Optional[CertificateAuthority] = Field(
        default=None,
        description="Certificate authority that issued the SSL/TLS certificate",
    )
    certificate_expiry_date: Optional[date] = Field(
        default=None,
        description="Certificate expiration date",
    )

    # Additional Security Details
    qualys_ssl_grade: Optional[str] = Field(
        default=None,
        description="Qualys SSL Labs grade (A+, A, B, C, etc.)",
    )
    forward_secrecy_enabled: Optional[bool] = Field(
        default=None,
        description="Does the server support forward secrecy (perfect forward secrecy)?",
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["CC6.1", "CC6.7"],
        description="SOC 2 data security and encryption criteria",
    )
    soc2_coverage_percentage: int = Field(
        default=90,
        ge=0,
        le=100,
        description="Encryption in transit is typically well-covered in SOC 2 reports",
    )

    @field_validator("certificate_expiry_date", mode="before")
    @classmethod
    def parse_date(cls, v):
        """Parse date string to date object"""
        if v is None or isinstance(v, date):
            return v
        if isinstance(v, str):
            return date.fromisoformat(v)
        return v

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. At least TLS 1.2 must be supported
        2. SSL v2 and SSL v3 must be explicitly blocked
        3. Certificate must not be expired
        4. Certificate should not be expiring within 30 days (warning)

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        # Requirement 1: At least TLS 1.2 must be supported
        has_modern_tls = any(
            version in [TLSVersion.TLS_1_2, TLSVersion.TLS_1_3]
            for version in self.tls_versions_supported
        )
        if not has_modern_tls:
            return False

        # Requirement 2: SSL v2 and SSL v3 must be blocked (critical vulnerabilities)
        critical_weak_protocols = {WeakProtocol.SSL_V2, WeakProtocol.SSL_V3}
        blocked_protocols_set = set(self.weak_protocols_blocked)

        if not critical_weak_protocols.issubset(blocked_protocols_set):
            return False

        # Requirement 3: Certificate must not be expired
        if self.certificate_expiry_date:
            if self.certificate_expiry_date < date.today():
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

        # Check TLS version requirement
        has_modern_tls = any(
            version in [TLSVersion.TLS_1_2, TLSVersion.TLS_1_3]
            for version in self.tls_versions_supported
        )
        if not has_modern_tls:
            reasons.append(
                "TLS 1.2 or higher not supported (ASSURE requires minimum TLS 1.2)"
            )

        # Check critical weak protocol blocking
        critical_weak_protocols = {WeakProtocol.SSL_V2, WeakProtocol.SSL_V3}
        blocked_protocols_set = set(self.weak_protocols_blocked)

        if WeakProtocol.SSL_V2 not in blocked_protocols_set:
            reasons.append(
                "SSL v2 is not explicitly blocked (SSL v2 has critical security vulnerabilities)"
            )

        if WeakProtocol.SSL_V3 not in blocked_protocols_set:
            reasons.append(
                "SSL v3 is not explicitly blocked (SSL v3 is vulnerable to POODLE attack)"
            )

        # Check certificate expiry
        if self.certificate_expiry_date:
            if self.certificate_expiry_date < date.today():
                reasons.append(
                    f"SSL/TLS certificate has expired (expired on {self.certificate_expiry_date})"
                )

        return reasons

    def get_warnings(self) -> List[str]:
        """
        Get non-critical warnings about this evidence.

        These don't affect compliance but should be reviewed.

        Returns:
            List[str]: List of warning messages
        """
        warnings = []

        # Check if certificate is expiring soon (within 30 days)
        if self.certificate_expiry_date:
            days_until_expiry = (self.certificate_expiry_date - date.today()).days
            if 0 < days_until_expiry <= 30:
                warnings.append(
                    f"SSL/TLS certificate expiring soon (in {days_until_expiry} days on {self.certificate_expiry_date})"
                )

        # Check if deprecated protocols are blocked
        blocked_protocols_set = set(self.weak_protocols_blocked)

        if WeakProtocol.TLS_1_0 not in blocked_protocols_set:
            warnings.append(
                "TLS 1.0 is not explicitly blocked (TLS 1.0 is deprecated as of 2020)"
            )

        if WeakProtocol.TLS_1_1 not in blocked_protocols_set:
            warnings.append(
                "TLS 1.1 is not explicitly blocked (TLS 1.1 is deprecated as of 2020)"
            )

        # Check Qualys grade if available
        if self.qualys_ssl_grade:
            grade_upper = self.qualys_ssl_grade.upper()
            if grade_upper in ["B", "C", "D", "F"]:
                warnings.append(
                    f"Qualys SSL Labs grade is {self.qualys_ssl_grade} (consider improving to A or A+)"
                )

        # Check forward secrecy
        if self.forward_secrecy_enabled is False:
            warnings.append(
                "Forward secrecy is not enabled (recommended for enhanced security)"
            )

        return warnings

    def get_total_requirements(self) -> int:
        """
        Encryption in Transit has 7 core requirements that ASSURE checks.

        Requirements:
        1. TLS 1.2+ supported
        2. TLS 1.1 blocked
        3. TLS 1.0 blocked
        4. SSL v3 blocked
        5. SSL v2 blocked
        6. Valid certificate (not expired)
        7. Certificate not expiring soon (within 30 days)

        Returns:
            int: Total of 7 requirements
        """
        return 7

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 7 encryption in transit requirements pass validation.

        Returns:
            int: Number of passed requirements (0-7)
        """
        passed = 0

        # Requirement 1: TLS 1.2+ supported
        has_modern_tls = any(
            version in [TLSVersion.TLS_1_2, TLSVersion.TLS_1_3]
            for version in self.tls_versions_supported
        )
        if has_modern_tls:
            passed += 1

        blocked_protocols_set = set(self.weak_protocols_blocked)

        # Requirement 2: TLS 1.1 blocked
        if WeakProtocol.TLS_1_1 in blocked_protocols_set:
            passed += 1

        # Requirement 3: TLS 1.0 blocked
        if WeakProtocol.TLS_1_0 in blocked_protocols_set:
            passed += 1

        # Requirement 4: SSL v3 blocked
        if WeakProtocol.SSL_V3 in blocked_protocols_set:
            passed += 1

        # Requirement 5: SSL v2 blocked
        if WeakProtocol.SSL_V2 in blocked_protocols_set:
            passed += 1

        # Requirement 6: Valid certificate (not expired)
        if self.certificate_expiry_date:
            if self.certificate_expiry_date >= date.today():
                passed += 1
        else:
            # If no expiry date provided, assume valid
            passed += 1

        # Requirement 7: Certificate not expiring soon (within 30 days)
        if self.certificate_expiry_date:
            days_until_expiry = (self.certificate_expiry_date - date.today()).days
            if days_until_expiry > 30:
                passed += 1
        else:
            # If no expiry date provided, assume OK
            passed += 1

        return passed
