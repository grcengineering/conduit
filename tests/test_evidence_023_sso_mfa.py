"""Tests for ASSURE Control #23: SSO/MFA Requirements Evidence"""

from datetime import date

import pytest
from pydantic import ValidationError

from conduit.models.evidence_023_sso_mfa import (
    MFAType,
    SSOMMFAEvidence,
    SSOProtocol,
)


class TestSSOMMFAEvidence:
    """Test suite for SSO/MFA Requirements evidence model"""

    def test_valid_evidence_passes(self):
        """Test that valid SSO/MFA evidence passes validation"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML, SSOProtocol.OIDC],
            sso_requires_paid_plan=False,  # Critical!
            mfa_enforced_by_default=True,
            mfa_types_supported=[
                MFAType.AUTHENTICATOR_APP,
                MFAType.HARDWARE_TOKEN,
            ],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        assert evidence.vendor_name == "Acme Corp"
        assert evidence.sso_supported is True
        assert evidence.sso_requires_paid_plan is False
        assert evidence.is_compliant() is True

    def test_sso_paywall_makes_non_compliant(self):
        """Test that SSO paywall makes evidence non-compliant (critical ASSURE requirement)"""
        evidence = SSOMMFAEvidence(
            vendor_name="BadVendor Inc",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=True,  # ASSURE PROHIBITS THIS!
            mfa_enforced_by_default=True,
            mfa_types_supported=[MFAType.HARDWARE_TOKEN],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        assert evidence.is_compliant() is False

        reasons = evidence.get_non_compliance_reasons()
        assert any("paywall" in reason.lower() for reason in reasons)

    def test_no_sso_support_is_non_compliant(self):
        """Test that lack of SSO support makes evidence non-compliant"""
        evidence = SSOMMFAEvidence(
            vendor_name="NoSSO Corp",
            evidence_date=date.today(),
            sso_supported=False,  # No SSO!
            sso_protocols=[],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[MFAType.AUTHENTICATOR_APP],
            phishing_resistant_mfa_available=False,
            mfa_coverage_percentage=80,
            extraction_confidence=0.90,
        )

        assert evidence.is_compliant() is False

        reasons = evidence.get_non_compliance_reasons()
        assert any("sso is not supported" in reason.lower() for reason in reasons)

    def test_no_phishing_resistant_mfa_is_non_compliant(self):
        """Test that lack of phishing-resistant MFA makes evidence non-compliant"""
        evidence = SSOMMFAEvidence(
            vendor_name="WeakMFA Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[
                MFAType.SMS,  # Not phishing-resistant
                MFAType.EMAIL,  # Not phishing-resistant
            ],
            phishing_resistant_mfa_available=False,
            mfa_coverage_percentage=100,
            extraction_confidence=0.90,
        )

        assert evidence.is_compliant() is False

        reasons = evidence.get_non_compliance_reasons()
        assert any("phishing-resistant" in reason.lower() for reason in reasons)

    def test_no_mfa_at_all_is_non_compliant(self):
        """Test that no MFA support makes evidence non-compliant"""
        with pytest.raises(ValidationError):
            # This should fail validation because mfa_types_supported requires min_length=1
            SSOMMFAEvidence(
                vendor_name="NoMFA Corp",
                evidence_date=date.today(),
                sso_supported=True,
                sso_protocols=[SSOProtocol.SAML],
                sso_requires_paid_plan=False,
                mfa_enforced_by_default=False,
                mfa_types_supported=[],  # Empty list not allowed!
                phishing_resistant_mfa_available=False,
                mfa_coverage_percentage=0,
                extraction_confidence=0.85,
            )

    def test_get_phishing_resistant_mfa_types(self):
        """Test that phishing-resistant MFA types are correctly identified"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[
                MFAType.SMS,  # Not phishing-resistant
                MFAType.AUTHENTICATOR_APP,  # Not phishing-resistant
                MFAType.HARDWARE_TOKEN,  # Phishing-resistant!
                MFAType.BIOMETRIC,  # Phishing-resistant!
            ],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        phishing_resistant = evidence.get_phishing_resistant_mfa_types()
        assert MFAType.HARDWARE_TOKEN in phishing_resistant
        assert MFAType.BIOMETRIC in phishing_resistant
        assert MFAType.SMS not in phishing_resistant
        assert MFAType.AUTHENTICATOR_APP not in phishing_resistant

    def test_get_non_phishing_resistant_mfa_types(self):
        """Test that non-phishing-resistant MFA types are correctly identified"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[
                MFAType.SMS,  # Not phishing-resistant
                MFAType.AUTHENTICATOR_APP,  # Not phishing-resistant
                MFAType.HARDWARE_TOKEN,  # Phishing-resistant
            ],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        non_phishing_resistant = evidence.get_non_phishing_resistant_mfa_types()
        assert MFAType.SMS in non_phishing_resistant
        assert MFAType.AUTHENTICATOR_APP in non_phishing_resistant
        assert MFAType.HARDWARE_TOKEN not in non_phishing_resistant

    def test_mfa_coverage_percentage_validation(self):
        """Test that MFA coverage percentage is validated (0-100)"""
        with pytest.raises(ValidationError):
            SSOMMFAEvidence(
                vendor_name="Acme Corp",
                evidence_date=date.today(),
                sso_supported=True,
                sso_protocols=[SSOProtocol.SAML],
                sso_requires_paid_plan=False,
                mfa_enforced_by_default=True,
                mfa_types_supported=[MFAType.HARDWARE_TOKEN],
                phishing_resistant_mfa_available=True,
                mfa_coverage_percentage=150,  # Invalid! Must be 0-100
                extraction_confidence=0.95,
            )

    def test_multiple_sso_protocols(self):
        """Test that vendors can support multiple SSO protocols"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML, SSOProtocol.OIDC, SSOProtocol.OAUTH2],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[MFAType.HARDWARE_TOKEN],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        assert len(evidence.sso_protocols) == 3
        assert SSOProtocol.SAML in evidence.sso_protocols
        assert SSOProtocol.OIDC in evidence.sso_protocols

    def test_soc2_overlap_defaults(self):
        """Test that SOC 2 overlap fields have correct defaults"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[MFAType.HARDWARE_TOKEN],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        assert "CC6.1" in evidence.soc2_section_4_criteria
        assert "CC6.2" in evidence.soc2_section_4_criteria
        assert evidence.soc2_coverage_percentage == 50  # Partial SOC 2 coverage

    def test_evidence_type_default(self):
        """Test that evidence_type has correct default value"""
        evidence = SSOMMFAEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            sso_supported=True,
            sso_protocols=[SSOProtocol.SAML],
            sso_requires_paid_plan=False,
            mfa_enforced_by_default=True,
            mfa_types_supported=[MFAType.HARDWARE_TOKEN],
            phishing_resistant_mfa_available=True,
            mfa_coverage_percentage=100,
            extraction_confidence=0.95,
        )

        assert evidence.evidence_type == "assure_023_sso_mfa"


class TestEnums:
    """Test suite for SSO/MFA enums"""

    def test_mfa_type_enum(self):
        """Test MFAType enum values"""
        assert MFAType.AUTHENTICATOR_APP.value == "authenticator_app"
        assert MFAType.SMS.value == "sms"
        assert MFAType.HARDWARE_TOKEN.value == "hardware_token"
        assert MFAType.BIOMETRIC.value == "biometric"
        assert MFAType.DEVICE_TRUST.value == "device_trust"

    def test_sso_protocol_enum(self):
        """Test SSOProtocol enum values"""
        assert SSOProtocol.SAML.value == "saml"
        assert SSOProtocol.OIDC.value == "oidc"
        assert SSOProtocol.OAUTH2.value == "oauth2"
