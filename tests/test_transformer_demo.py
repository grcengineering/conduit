"""
Demo/test script for CONDUIT text extraction.

This demonstrates how to extract evidence from ANY text source:
- Trust center copy/paste
- Vendor email responses
- SOC 2 report excerpts
- Manual text entry

Run this to test the extraction pipeline end-to-end.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from conduit.transformer import text_to_bcpdr, text_to_vulnerability, text_to_sso_mfa
from conduit.models.evidence_007_bcpdr import BCPDREvidence
from conduit.models.evidence_004_vulnerability import VulnerabilityEvidence
from conduit.models.evidence_023_sso_mfa import SSOMMFAEvidence


def test_bcpdr_extraction():
    """Test BCP/DR extraction from trust center text"""
    print("\n" + "="*80)
    print("TEST 1: BCP/DR Testing Evidence Extraction")
    print("="*80)

    # Sample text (could be from trust center, email, SOC 2, etc.)
    text = """
    At Acme Corp, we take business continuity seriously. Our latest disaster
    recovery test was completed on August 15, 2025. We performed a partial
    failover test of our production environment, including database and
    application servers.

    While the test was mostly successful, our actual recovery time was 6 hours,
    which exceeded our 4-hour RTO target. We're working on improvements for
    next quarter. The test scope covered all production systems.
    """

    print(f"\nInput Text:\n{text[:200]}...")
    print("\nExtracting with Claude AI...")

    # Extract
    data = text_to_bcpdr(text, vendor_name="Acme Corp")
    print(f"\nExtracted Data: {data}")

    # Validate with Pydantic
    print("\nValidating with Pydantic schema...")
    evidence = BCPDREvidence.model_validate(data)

    # Show results
    print(f"✅ Valid BCPDREvidence object created!")
    print(f"\nCompliance Results:")
    print(f"  - Compliance: {evidence.get_compliance_percentage()}%")
    print(f"  - Status: {evidence.get_compliance_status()}")
    print(f"  - Passed: {evidence.get_passed_requirements()}/{evidence.get_total_requirements()} requirements")
    print(f"  - Test Date: {evidence.test_date}")
    print(f"  - Test Result: {evidence.test_result}")
    print(f"  - RTO Met: {evidence.recovery_time_objective_met}")

    return evidence


def test_vulnerability_extraction():
    """Test Vulnerability Management extraction"""
    print("\n" + "="*80)
    print("TEST 2: Vulnerability Management Evidence Extraction")
    print("="*80)

    text = """
    DataFlow Inc conducts monthly vulnerability scans using Qualys. The most
    recent scans were:
    - October 1, 2025: 0 critical, 2 high, 5 medium, 12 low
    - September 1, 2025: 0 critical, 3 high, 7 medium, 15 low
    - August 1, 2025: 1 critical, 4 high, 8 medium, 18 low

    Our last penetration test was conducted on March 15, 2024 by SecureOps Inc.
    It was an external black box test that found 0 critical and 2 high severity
    findings. Unfortunately, both high findings remain open.

    We meet our vulnerability SLA targets for most findings.
    """

    print(f"\nInput Text:\n{text[:200]}...")
    print("\nExtracting with Claude AI...")

    data = text_to_vulnerability(text, vendor_name="DataFlow Inc")
    print(f"\nExtracted Data (scans): {len(data.get('scans_last_3_months', []))} scans found")

    print("\nValidating with Pydantic schema...")
    evidence = VulnerabilityEvidence.model_validate(data)

    print(f"✅ Valid VulnerabilityEvidence object created!")
    print(f"\nCompliance Results:")
    print(f"  - Compliance: {evidence.get_compliance_percentage()}%")
    print(f"  - Status: {evidence.get_compliance_status()}")
    print(f"  - Passed: {evidence.get_passed_requirements()}/{evidence.get_total_requirements()} requirements")
    print(f"  - Scans: {len(evidence.scans_last_3_months)}")
    print(f"  - Pentest Date: {evidence.penetration_test.test_date}")
    print(f"  - Critical/High Remediated: {evidence.penetration_test.all_critical_high_remediated}")

    return evidence


def test_sso_mfa_extraction():
    """Test SSO/MFA extraction"""
    print("\n" + "="*80)
    print("TEST 3: SSO/MFA Requirements Evidence Extraction")
    print("="*80)

    text = """
    CloudStore Pro supports SAML 2.0 and OIDC for single sign-on authentication.
    SSO is available on all plans at no additional cost.

    We support multiple MFA options including:
    - Authenticator apps (Google Authenticator, Authy)
    - SMS-based verification
    - Push notifications via our mobile app
    - Hardware tokens (YubiKey, FIDO2)

    MFA is enforced by default for all users. Currently 100% of our users have
    MFA enabled. We support phishing-resistant authentication via hardware tokens.
    """

    print(f"\nInput Text:\n{text[:200]}...")
    print("\nExtracting with Claude AI...")

    data = text_to_sso_mfa(text, vendor_name="CloudStore Pro")
    print(f"\nExtracted Data: {data}")

    print("\nValidating with Pydantic schema...")
    evidence = SSOMMFAEvidence.model_validate(data)

    print(f"✅ Valid SSOMMFAEvidence object created!")
    print(f"\nCompliance Results:")
    print(f"  - Compliance: {evidence.get_compliance_percentage()}%")
    print(f"  - Status: {evidence.get_compliance_status()}")
    print(f"  - Passed: {evidence.get_passed_requirements()}/{evidence.get_total_requirements()} requirements")
    print(f"  - SSO Supported: {evidence.sso_supported}")
    print(f"  - SSO Paywall: {evidence.sso_requires_paid_plan}")
    print(f"  - MFA Types: {len(evidence.mfa_types_supported)}")
    print(f"  - Phishing-Resistant: {evidence.phishing_resistant_mfa_available}")

    return evidence


def main():
    """Run all demo tests"""
    print("\n" + "#"*80)
    print("# CONDUIT Text-to-Evidence Extraction Demo")
    print("# Shows how to extract evidence from ANY text source")
    print("#"*80)

    try:
        # Test all 3 extractors
        bcpdr_evidence = test_bcpdr_extraction()
        vuln_evidence = test_vulnerability_extraction()
        sso_evidence = test_sso_mfa_extraction()

        # Summary
        print("\n" + "="*80)
        print("SUMMARY: All 3 Evidence Types Successfully Extracted!")
        print("="*80)
        print(f"\n1. BCP/DR Testing: {bcpdr_evidence.get_compliance_percentage()}% compliance")
        print(f"2. Vulnerability Management: {vuln_evidence.get_compliance_percentage()}% compliance")
        print(f"3. SSO/MFA: {sso_evidence.get_compliance_percentage()}% compliance")

        print("\n✅ Phase 2 MVP Complete: Text → Claude → Validated Pydantic Objects")
        print("\nNext Steps:")
        print("  - Add CLI command: conduit extract")
        print("  - Test with real SOC 2 text")
        print("  - Wire to dashboard for visualization")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure:")
        print("  1. .env file exists with ANTHROPIC_API_KEY")
        print("  2. Dependencies installed: pdm install")
        print("  3. Claude API key is valid")
        raise


if __name__ == "__main__":
    main()
