"""ASSURE Control #9: Production Access Controls Evidence"""

from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class AccessMethod(Enum):
    """Methods for accessing production systems"""

    JIT = "jit"  # Just-in-time access (preferred)
    BASTION = "bastion"  # Bastion host/jump box
    VPN = "vpn"  # VPN-based access
    DIRECT = "direct"  # Direct access (not recommended)
    NONE = "none"  # No access by default (best practice)


class PrivilegeLevel(Enum):
    """Levels of privilege for production access"""

    READ_ONLY = "read_only"  # Read-only access
    STANDARD = "standard"  # Standard user privileges
    PRIVILEGED = "privileged"  # Elevated privileges
    ADMIN = "admin"  # Administrative privileges


class SessionDuration(Enum):
    """Maximum session durations for production access"""

    FIFTEEN_MIN = "15_min"
    THIRTY_MIN = "30_min"
    ONE_HOUR = "1_hour"
    FOUR_HOURS = "4_hours"
    EIGHT_HOURS = "8_hours"
    PERSISTENT = "persistent"  # No expiration (not recommended)


class ProductionAccessEvidence(BaseEvidence):
    """
    ASSURE Control #9: Production Access Controls Evidence.

    This evidence type validates that production access follows least privilege
    principles with JIT access mechanisms and no persistent privileged access.

    ASSURE Requirements:
    - JIT (just-in-time) access mechanisms required
    - No persistent production access for privileged users
    - Least privilege enforcement (default access is "none")
    - MFA required for privileged access
    - Privileged accounts segregated from standard accounts
    - Session durations must be time-limited (not persistent)

    SOC 2 Overlap:
    - CC5.2: Logical and Physical Access Controls
    - CC6.1: Logical and Physical Access Controls

    NIST CSF Overlap:
    - PR.AA-05: Network integrity is protected
    - PR.IR-01: Response plans are executed during or after an incident

    CIS Controls:
    - Control 6: Access Control Management

    Example:
        evidence = ProductionAccessEvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-17",
            access_method=AccessMethod.JIT,
            default_access=AccessMethod.NONE,
            mfa_required_for_privileged=True,
            max_session_duration=SessionDuration.FOUR_HOURS,
            persistent_access_allowed=False,
            privileged_accounts_segregated=True,
            extraction_confidence=0.95
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE production access requirements")
    """

    evidence_type: str = Field(default="assure_009_production_access")

    # Access Method (required)
    access_method: AccessMethod = Field(
        description="Primary method for accessing production systems (JIT preferred)"
    )
    default_access: AccessMethod = Field(
        description="Default access level for users (should be 'none' for least privilege)"
    )

    # MFA Configuration (required)
    mfa_required_for_privileged: bool = Field(
        description="Is MFA required for privileged/admin access?"
    )

    # Session Management (required)
    max_session_duration: SessionDuration = Field(
        description="Maximum duration for production sessions (should be time-limited)"
    )
    persistent_access_allowed: bool = Field(
        description="Is persistent (non-expiring) access allowed? (ASSURE PROHIBITS this for privileged access)"
    )

    # Privilege Segregation (required)
    privileged_accounts_segregated: bool = Field(
        description="Are privileged accounts segregated from standard user accounts?"
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["CC5.2", "CC6.1"],
        description="SOC 2 logical and physical access control criteria",
    )
    soc2_coverage_percentage: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Production access controls are partially covered in SOC 2 (JIT specifics are ASSURE-specific)",
    )

    @field_validator("persistent_access_allowed", "max_session_duration")
    @classmethod
    def validate_no_persistent_privileged_access(cls, v, info):
        """
        Validate that persistent access is not allowed for privileged access.

        ASSURE requires that privileged access must be time-limited with automatic
        session expiration. This validator ensures this critical requirement is met.
        """
        # Get all values to check relationship
        values = info.data

        # If checking persistent_access_allowed field
        if info.field_name == "persistent_access_allowed":
            if v is True:
                # Persistent access is only acceptable for read-only access
                # For privileged/admin access, this is a critical violation
                pass  # Will be caught by is_compliant()

        # If checking max_session_duration field
        if info.field_name == "max_session_duration":
            persistent_access = values.get("persistent_access_allowed", False)
            if v == SessionDuration.PERSISTENT and persistent_access:
                # This combination is flagged in is_compliant()
                pass

        return v

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. JIT access method must be used for production
        2. Default access must be "none" (least privilege)
        3. MFA must be required for privileged access
        4. Sessions must be time-limited (no persistent access)
        5. Privileged accounts must be segregated
        6. No persistent access allowed for privileged users

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        # Requirement 1: JIT access required
        if self.access_method not in [AccessMethod.JIT, AccessMethod.BASTION]:
            return False

        # Requirement 2: Default access should be "none" (least privilege)
        if self.default_access != AccessMethod.NONE:
            return False

        # Requirement 3: MFA required for privileged access
        if not self.mfa_required_for_privileged:
            return False

        # Requirement 4: Sessions must be time-limited (not persistent)
        if self.max_session_duration == SessionDuration.PERSISTENT:
            return False

        # Requirement 5: Privileged accounts must be segregated
        if not self.privileged_accounts_segregated:
            return False

        # Requirement 6: No persistent access allowed
        if self.persistent_access_allowed:
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

        if self.access_method not in [AccessMethod.JIT, AccessMethod.BASTION]:
            reasons.append(
                f"Production access method is '{self.access_method.value}' "
                "(ASSURE requires JIT or bastion-based access for least privilege)"
            )

        if self.default_access != AccessMethod.NONE:
            reasons.append(
                f"Default access is '{self.default_access.value}' "
                "(ASSURE requires default access to be 'none' for least privilege enforcement)"
            )

        if not self.mfa_required_for_privileged:
            reasons.append(
                "MFA is not required for privileged access "
                "(ASSURE requires MFA for all privileged/admin access)"
            )

        if self.max_session_duration == SessionDuration.PERSISTENT:
            reasons.append(
                "Session duration is persistent "
                "(ASSURE requires time-limited sessions for production access)"
            )

        if not self.privileged_accounts_segregated:
            reasons.append(
                "Privileged accounts are not segregated "
                "(ASSURE requires privileged accounts to be separate from standard accounts)"
            )

        if self.persistent_access_allowed:
            reasons.append(
                "Persistent access is allowed "
                "(ASSURE PROHIBITS persistent production access - this is a critical security issue)"
            )

        return reasons

    def get_total_requirements(self) -> int:
        """
        Production access control has 6 core requirements that ASSURE checks.

        Requirements:
        1. JIT access method (or bastion)
        2. Default access is "none" (least privilege)
        3. MFA required for privileged access
        4. Time-limited sessions (not persistent)
        5. Privileged accounts segregated
        6. No persistent access allowed

        Returns:
            int: Total of 6 requirements
        """
        return 6

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 6 production access requirements pass validation.

        Returns:
            int: Number of passed requirements (0-6)
        """
        passed = 0

        # Requirement 1: JIT access method (or bastion)
        if self.access_method in [AccessMethod.JIT, AccessMethod.BASTION]:
            passed += 1

        # Requirement 2: Default access is "none"
        if self.default_access == AccessMethod.NONE:
            passed += 1

        # Requirement 3: MFA required for privileged access
        if self.mfa_required_for_privileged:
            passed += 1

        # Requirement 4: Time-limited sessions
        if self.max_session_duration != SessionDuration.PERSISTENT:
            passed += 1

        # Requirement 5: Privileged accounts segregated
        if self.privileged_accounts_segregated:
            passed += 1

        # Requirement 6: No persistent access allowed
        if not self.persistent_access_allowed:
            passed += 1

        return passed

    def get_session_duration_hours(self) -> Optional[float]:
        """
        Get the maximum session duration in hours.

        Returns:
            Optional[float]: Session duration in hours, or None if persistent
        """
        duration_map = {
            SessionDuration.FIFTEEN_MIN: 0.25,
            SessionDuration.THIRTY_MIN: 0.5,
            SessionDuration.ONE_HOUR: 1.0,
            SessionDuration.FOUR_HOURS: 4.0,
            SessionDuration.EIGHT_HOURS: 8.0,
            SessionDuration.PERSISTENT: None,
        }
        return duration_map.get(self.max_session_duration)

    def is_jit_access_enabled(self) -> bool:
        """
        Check if JIT (just-in-time) access is enabled.

        Returns:
            bool: True if JIT access is enabled
        """
        return self.access_method == AccessMethod.JIT

    def has_architectural_segmentation(self) -> bool:
        """
        Check if architectural segmentation is in place (bastion or better).

        Returns:
            bool: True if bastion or JIT access is used (indicating segmentation)
        """
        return self.access_method in [AccessMethod.JIT, AccessMethod.BASTION]
