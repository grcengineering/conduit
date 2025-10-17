"""LLM-powered text transformation to CONDUIT evidence format

This module provides source-agnostic text extraction functions that transform
ANY text (trust center, email, PDF extract, etc.) into validated CONDUIT evidence.
"""

import os
import re
from datetime import date
from typing import Any

from anthropic import Anthropic
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Model selection
MODEL_CHEAP = os.getenv("CONDUIT_MODEL_CHEAP", "claude-haiku-4-5-20251001")
MODEL_EXPENSIVE = os.getenv("CONDUIT_MODEL_EXPENSIVE", "claude-sonnet-4-5-20250929")


def text_to_bcpdr(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract BCP/DR testing evidence from ANY text source.

    Supports text from:
    - Trust center websites (copy/paste)
    - Vendor email responses
    - SOC 2 reports (pre-extracted text)
    - Policy documents
    - Manual entry

    Args:
        text: Raw text containing BCP/DR information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for BCPDREvidence.model_validate()

    Example:
        >>> text = "BCP/DR test on August 15, 2025, partial failover..."
        >>> data = text_to_bcpdr(text, "Acme Corp")
        >>> evidence = BCPDREvidence.model_validate(data)
        >>> print(evidence.get_compliance_percentage())  # 66.7%
    """

    prompt = f"""Extract BCP/DR (Business Continuity Plan / Disaster Recovery) test information from this text.

TEXT:
{text}

Find and extract these fields:
1. test_date: When was the most recent BCP/DR test conducted? (format: YYYY-MM-DD)
2. test_result: Did the test pass, fail, or pass with findings?
   - "pass" if test was successful with no issues
   - "fail" if test failed or objectives not met
   - "pass_with_findings" if test passed but had minor issues
3. test_type: What type of test was conducted?
   - "tabletop" for discussion-based exercises
   - "partial_failover" for testing specific systems
   - "full_failover" for complete DR activation
4. scope: What systems or services were included in the test? (brief description)
5. recovery_time_objective_met: Was the Recovery Time Objective (RTO) met?
   - true if RTO was met
   - false if RTO was exceeded
   - null if not mentioned

If any information is not present in the text, use null.

Output ONLY these fields, one per line in this exact format:
test_date:
test_result:
test_type:
scope:
recovery_time_objective_met: """

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=500,
        temperature=0.0,  # Deterministic output
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse response
    raw_text = response.content[0].text.strip()
    data: dict[str, Any] = {}

    for line in raw_text.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            # Handle null/empty values
            if value.lower() in ['null', 'n/a', 'not mentioned', '']:
                data[key] = None
            # Handle boolean values
            elif key == 'recovery_time_objective_met':
                if value.lower() in ['true', 'yes', 'met']:
                    data[key] = True
                elif value.lower() in ['false', 'no', 'not met', 'exceeded']:
                    data[key] = False
                else:
                    data[key] = None
            else:
                data[key] = value

    # Add required Pydantic fields
    data['vendor_name'] = vendor_name
    data['evidence_date'] = str(date.today())
    data['evidence_type'] = 'assure_007_bcpdr_testing'
    data['extraction_confidence'] = 0.85 if use_expensive_model else 0.80

    # Map to Pydantic field names if needed
    result = {
        'vendor_name': data.get('vendor_name'),
        'evidence_date': data.get('evidence_date'),
        'evidence_type': data.get('evidence_type'),
        'test_date': data.get('test_date'),
        'test_result': data.get('test_result'),
        'test_type': data.get('test_type'),
        'scope': data.get('scope', 'Not specified'),
        'recovery_time_objective_met': data.get('recovery_time_objective_met'),
        'extraction_confidence': data.get('extraction_confidence'),
    }

    return result


def text_to_vulnerability(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Vulnerability Management evidence from ANY text source.

    Supports text from:
    - Pentest reports
    - Vulnerability scan summaries
    - Security assessment emails
    - SOC 2 reports (pre-extracted text)

    Args:
        text: Raw text containing vulnerability management information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for VulnerabilityEvidence.model_validate()
    """

    prompt = f"""Extract Vulnerability Management information from this text.

TEXT:
{text}

Find and extract these fields:

VULNERABILITY SCANS (last 3 months):
List up to 3 most recent vulnerability scans. For each scan extract:
- scan_date: Date of scan (YYYY-MM-DD)
- scanner_tool: Tool used (e.g., "Qualys", "Tenable", "Nessus")
- scan_type: "authenticated" or "unauthenticated"
- critical_findings: Number of critical vulnerabilities (integer)
- high_findings: Number of high severity vulnerabilities (integer)
- medium_findings: Number of medium severity vulnerabilities (integer)
- low_findings: Number of low severity vulnerabilities (integer)

PENETRATION TEST:
- test_date: Date of most recent pentest (YYYY-MM-DD)
- tester_firm: Company that performed the test
- test_type: Type of test (e.g., "external_black_box", "internal", "web_application")
- critical_findings: Number of critical findings (integer)
- high_findings: Number of high findings (integer)
- medium_findings: Number of medium findings (integer)
- low_findings: Number of low findings (integer)
- all_critical_high_remediated: true if all critical/high findings are fixed, false otherwise

VULNERABILITY SLA:
- vulnerability_sla_met: true if remediation SLAs are being met, false otherwise

Output in this format:
scan1_date:
scan1_tool:
scan1_type:
scan1_critical:
scan1_high:
scan1_medium:
scan1_low:

scan2_date:
scan2_tool:
scan2_type:
scan2_critical:
scan2_high:
scan2_medium:
scan2_low:

scan3_date:
scan3_tool:
scan3_type:
scan3_critical:
scan3_high:
scan3_medium:
scan3_low:

pentest_date:
pentest_firm:
pentest_type:
pentest_critical:
pentest_high:
pentest_medium:
pentest_low:
pentest_remediated:

vulnerability_sla_met: """

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=1000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse response
    raw_text = response.content[0].text.strip()
    parsed: dict[str, Any] = {}

    for line in raw_text.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if value.lower() not in ['null', 'n/a', 'not mentioned', '']:
                # Handle integers
                if any(x in key for x in ['critical', 'high', 'medium', 'low']):
                    try:
                        parsed[key] = int(value)
                    except ValueError:
                        parsed[key] = 0
                # Handle booleans
                elif 'sla_met' in key or 'remediated' in key:
                    parsed[key] = value.lower() in ['true', 'yes', 'met']
                else:
                    parsed[key] = value

    # Build scans array
    scans = []
    for i in range(1, 4):
        if f'scan{i}_date' in parsed:
            scans.append({
                'scan_date': parsed.get(f'scan{i}_date'),
                'scanner_tool': parsed.get(f'scan{i}_tool', 'Unknown'),
                'scan_type': parsed.get(f'scan{i}_type', 'authenticated'),
                'critical_findings': parsed.get(f'scan{i}_critical', 0),
                'high_findings': parsed.get(f'scan{i}_high', 0),
                'medium_findings': parsed.get(f'scan{i}_medium', 0),
                'low_findings': parsed.get(f'scan{i}_low', 0),
            })

    # Build pentest object
    pentest = {
        'test_date': parsed.get('pentest_date'),
        'tester_firm': parsed.get('pentest_firm', 'Unknown'),
        'test_type': parsed.get('pentest_type', 'external_black_box'),
        'critical_findings': parsed.get('pentest_critical', 0),
        'high_findings': parsed.get('pentest_high', 0),
        'medium_findings': parsed.get('pentest_medium', 0),
        'low_findings': parsed.get('pentest_low', 0),
        'all_critical_high_remediated': parsed.get('pentest_remediated', False),
    }

    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_004_vulnerability_mgmt',
        'scans_last_3_months': scans if scans else [],
        'penetration_test': pentest,
        'vulnerability_sla_met': parsed.get('vulnerability_sla_met', False),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


def text_to_sso_mfa(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract SSO/MFA requirements evidence from ANY text source.

    Supports text from:
    - Trust center websites
    - Security questionnaire responses
    - Documentation pages
    - Email responses about authentication

    Args:
        text: Raw text containing SSO/MFA information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for SSOMMFAEvidence.model_validate()
    """

    prompt = f"""Extract SSO (Single Sign-On) and MFA (Multi-Factor Authentication) information from this text.

TEXT:
{text}

Find and extract these fields:

SSO CONFIGURATION:
- sso_supported: Does the vendor support SSO? (true/false)
- sso_protocols: List of SSO protocols supported (e.g., "saml", "oidc", "oauth2")
- sso_requires_paid_plan: Is SSO behind a paywall or paid tier? (true/false)
  CRITICAL: If SSO requires Enterprise/Premium/Paid plan, this is true

MFA CONFIGURATION:
- mfa_enforced_by_default: Is MFA enforced for all users by default? (true/false)
- mfa_types_supported: List of MFA types available:
  Options: "authenticator_app", "sms", "email", "hardware_token", "push_notification", "biometric", "device_trust"
- phishing_resistant_mfa_available: Are phishing-resistant MFA types available? (true/false)
  Phishing-resistant types: hardware_token, biometric, device_trust
- mfa_coverage_percentage: What percentage of users have MFA enabled? (0-100)

Output in this format:
sso_supported:
sso_protocols:
sso_requires_paid_plan:
mfa_enforced_by_default:
mfa_types_supported:
phishing_resistant_mfa_available:
mfa_coverage_percentage: """

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=500,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse response
    raw_text = response.content[0].text.strip()
    parsed: dict[str, Any] = {}

    for line in raw_text.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if value.lower() not in ['null', 'n/a', 'not mentioned', '']:
                # Handle booleans
                if any(x in key for x in ['supported', 'requires', 'enforced', 'available']):
                    parsed[key] = value.lower() in ['true', 'yes']
                # Handle percentage
                elif 'percentage' in key:
                    try:
                        # Extract number from string like "95%" or "95"
                        num = re.search(r'\d+', value)
                        parsed[key] = int(num.group()) if num else 0
                    except ValueError:
                        parsed[key] = 0
                # Handle lists (comma-separated)
                elif 'protocols' in key or 'types_supported' in key:
                    parsed[key] = [p.strip() for p in value.split(',')]
                else:
                    parsed[key] = value

    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_023_sso_mfa',
        'sso_supported': parsed.get('sso_supported', False),
        'sso_protocols': parsed.get('sso_protocols', []),
        'sso_requires_paid_plan': parsed.get('sso_requires_paid_plan', False),
        'mfa_enforced_by_default': parsed.get('mfa_enforced_by_default', False),
        'mfa_types_supported': parsed.get('mfa_types_supported', []),
        'phishing_resistant_mfa_available': parsed.get('phishing_resistant_mfa_available', False),
        'mfa_coverage_percentage': parsed.get('mfa_coverage_percentage', 0),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


# Legacy function name for backward compatibility
def extract_bcpdr_evidence(document: str) -> dict[str, Any]:
    """
    Legacy function - use text_to_bcpdr() instead.

    Args:
        document: Raw document text

    Returns:
        dict: Extracted evidence data

    Raises:
        ValueError: If ANTHROPIC_API_KEY not set or vendor_name missing
    """
    raise NotImplementedError(
        "Use text_to_bcpdr(text, vendor_name) instead. "
        "Example: text_to_bcpdr(document, 'Acme Corp')"
    )


def analyze_soc2_overlap(evidence: dict[str, Any]) -> dict[str, Any]:
    """
    Identify SOC 2 Section 4 overlap with ASSURE evidence.

    Args:
        evidence: CONDUIT evidence data

    Returns:
        dict: Gap analysis report

    Raises:
        NotImplementedError: Phase 3 implementation pending
    """
    raise NotImplementedError("Phase 3: SOC 2 gap analysis (future enhancement)")
