"""LLM-powered text transformation to CONDUIT evidence format

This module provides source-agnostic text extraction functions that transform
ANY text (trust center, email, PDF extract, etc.) into validated CONDUIT evidence.

All extractors use XML format for consistency and reliability.
"""

import os
import re
from datetime import date, datetime
from typing import Any

from anthropic import Anthropic
from dotenv import load_dotenv

from conduit.training_examples import (
    BCPDR_EXAMPLES,
    VULNERABILITY_EXAMPLES,
    SSO_MFA_EXAMPLES,
    INCIDENT_RESPONSE_EXAMPLES,
    ENCRYPTION_IN_TRANSIT_EXAMPLES,
    LOGGING_CONFIG_EXAMPLES,
    PRODUCTION_ACCESS_EXAMPLES,
)
from conduit.xml_parser import parse_evidence_xml
import logging

# Set up logging for normalization tracking
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Model selection
MODEL_CHEAP = os.getenv("CONDUIT_MODEL_CHEAP", "claude-haiku-4-5-20251001")
MODEL_EXPENSIVE = os.getenv("CONDUIT_MODEL_EXPENSIVE", "claude-sonnet-4-5-20250929")


def normalize_sso_protocol(protocol_str: str) -> str:
    """
    Normalize SSO protocol variations to Pydantic enum values.

    Maps variations like "SAML 2.0", "saml", "OAuth 2.0" to standard enum values:
    - "saml"
    - "oidc"
    - "oauth2"

    Args:
        protocol_str: Raw protocol string from Claude's extraction

    Returns:
        str: Normalized protocol value matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_sso_protocol("SAML 2.0")
        'saml'
        >>> normalize_sso_protocol("OpenID Connect")
        'oidc'
        >>> normalize_sso_protocol("Not specified")
        None
    """
    protocol_lower = protocol_str.lower().strip()

    # Handle unspecified/generic responses (including Python string 'none')
    if any(x in protocol_lower for x in ['not specified', 'not mentioned', 'generic', 'okta sso', 'uses sso', 'sso tool', 'sso mentioned', 'none']):
        logger.info(f"Ignoring unspecified SSO protocol: '{protocol_str}'")
        return None

    # Identity providers (map to their common protocols)
    # Azure AD / Entra ID typically uses SAML or OIDC
    if any(x in protocol_lower for x in ['azure active directory', 'azure ad', 'entra id', 'microsoft entra']):
        logger.info(f"Normalized identity provider to protocol: '{protocol_str}' → 'saml' (Azure AD commonly uses SAML/OIDC)")
        return 'saml'  # Most common for enterprise SSO

    # Okta as identity provider
    if 'okta' in protocol_lower and 'sso' not in protocol_lower:
        logger.info(f"Normalized identity provider to protocol: '{protocol_str}' → 'saml' (Okta commonly uses SAML)")
        return 'saml'

    # SAML variations
    if 'saml' in protocol_lower:
        if protocol_str != 'saml':
            logger.info(f"Normalized SSO protocol: '{protocol_str}' → 'saml'")
        return 'saml'

    # OAuth variations
    if 'oauth' in protocol_lower:
        if protocol_str != 'oauth2':
            logger.info(f"Normalized SSO protocol: '{protocol_str}' → 'oauth2'")
        return 'oauth2'

    # OIDC / OpenID Connect variations
    if 'oidc' in protocol_lower or 'openid' in protocol_lower:
        if protocol_str != 'oidc':
            logger.info(f"Normalized SSO protocol: '{protocol_str}' → 'oidc'")
        return 'oidc'

    # Unknown protocol - let Pydantic validation error
    logger.warning(f"Unknown SSO protocol '{protocol_str}' - passing to Pydantic for validation")
    return protocol_str


def normalize_mfa_type(mfa_str: str) -> str:
    """
    Normalize MFA type variations to Pydantic enum values.

    Maps variations like "TOTP", "YubiKey", "SMS codes" to standard enum values:
    - "authenticator_app"
    - "hardware_token"
    - "sms"
    - "email"
    - "push_notification"
    - "biometric"
    - "device_trust"

    Args:
        mfa_str: Raw MFA type string from Claude's extraction

    Returns:
        str: Normalized MFA type matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_mfa_type("TOTP")
        'authenticator_app'
        >>> normalize_mfa_type("YubiKey")
        'hardware_token'
        >>> normalize_mfa_type("Multi-factor authentication (MFA)")
        None
    """
    mfa_lower = mfa_str.lower().strip()

    # Handle generic/unspecified MFA mentions (including Python string 'none')
    if any(x in mfa_lower for x in ['not specified', 'not mentioned', 'multi-factor authentication (mfa)', 'multi-factor authentication', 'okta mfa', 'mfa mentioned', 'none']):
        logger.info(f"Ignoring generic MFA mention: '{mfa_str}'")
        return None

    # TOTP / Authenticator apps
    if any(x in mfa_lower for x in ['totp', 'authenticator', 'google auth', 'authy', 'otp app']):
        if mfa_str != 'authenticator_app':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'authenticator_app'")
        return 'authenticator_app'

    # Hardware tokens / Security keys
    if any(x in mfa_lower for x in ['yubikey', 'fido', 'webauthn', 'security key', 'hardware', 'u2f']):
        if mfa_str != 'hardware_token':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'hardware_token'")
        return 'hardware_token'

    # SMS
    if 'sms' in mfa_lower or 'text message' in mfa_lower:
        if mfa_str != 'sms':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'sms'")
        return 'sms'

    # Email
    if 'email' in mfa_lower or 'e-mail' in mfa_lower:
        if mfa_str != 'email':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'email'")
        return 'email'

    # Push notifications
    if 'push' in mfa_lower or 'notification' in mfa_lower:
        if mfa_str != 'push_notification':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'push_notification'")
        return 'push_notification'

    # Biometric
    if any(x in mfa_lower for x in ['biometric', 'fingerprint', 'face', 'touchid', 'faceid']):
        if mfa_str != 'biometric':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'biometric'")
        return 'biometric'

    # Device trust
    if 'device' in mfa_lower and 'trust' in mfa_lower:
        if mfa_str != 'device_trust':
            logger.info(f"Normalized MFA type: '{mfa_str}' → 'device_trust'")
        return 'device_trust'

    # Unknown MFA type - let Pydantic validation error
    logger.warning(f"Unknown MFA type '{mfa_str}' - passing to Pydantic for validation")
    return mfa_str


def normalize_test_result(result_str: str) -> str:
    """
    Normalize BCP/DR test result variations to Pydantic enum values.

    Maps variations like "No exceptions noted", "Passed", "Failed" to standard enum values:
    - "pass"
    - "pass_with_findings"
    - "fail"

    Args:
        result_str: Raw test result string from Claude's extraction

    Returns:
        str: Normalized test result matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_test_result("No exceptions noted")
        'pass'
        >>> normalize_test_result("Passed with minor findings")
        'pass_with_findings'
    """
    result_lower = result_str.lower().strip()

    # Handle pass variations
    if any(x in result_lower for x in ['no exception', 'pass', 'successful', 'success', 'completed successfully']):
        # Check if there are findings/issues mentioned
        if any(x in result_lower for x in ['finding', 'issue', 'minor', 'observation', 'improvement']):
            logger.info(f"Normalized test result: '{result_str}' → 'pass_with_findings'")
            return 'pass_with_findings'
        else:
            if result_str != 'pass':
                logger.info(f"Normalized test result: '{result_str}' → 'pass'")
            return 'pass'

    # Handle fail variations
    if any(x in result_lower for x in ['fail', 'unsuccessful', 'not successful', 'did not pass']):
        if result_str != 'fail':
            logger.info(f"Normalized test result: '{result_str}' → 'fail'")
        return 'fail'

    # Unknown result
    logger.warning(f"Unknown test result '{result_str}' - passing to Pydantic for validation")
    return result_str


def normalize_test_type(type_str: str) -> str:
    """
    Normalize BCP/DR test type variations to Pydantic enum values.

    Maps variations like "Tabletop Exercise", "Full Failover Test" to standard enum values:
    - "tabletop"
    - "partial_failover"
    - "full_failover"

    Args:
        type_str: Raw test type string from Claude's extraction

    Returns:
        str: Normalized test type matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_test_type("Tabletop Exercise")
        'tabletop'
        >>> normalize_test_type("Partial Failover")
        'partial_failover'
    """
    type_lower = type_str.lower().strip()

    # Handle tabletop variations
    if 'tabletop' in type_lower or 'table top' in type_lower or 'discussion' in type_lower:
        if type_str != 'tabletop':
            logger.info(f"Normalized test type: '{type_str}' → 'tabletop'")
        return 'tabletop'

    # Handle full failover variations
    if 'full' in type_lower and 'failover' in type_lower:
        if type_str != 'full_failover':
            logger.info(f"Normalized test type: '{type_str}' → 'full_failover'")
        return 'full_failover'

    # Handle partial failover variations
    if 'partial' in type_lower and 'failover' in type_lower:
        if type_str != 'partial_failover':
            logger.info(f"Normalized test type: '{type_str}' → 'partial_failover'")
        return 'partial_failover'

    # Just "failover" without full/partial → assume partial
    if 'failover' in type_lower:
        logger.info(f"Normalized test type: '{type_str}' → 'partial_failover' (unspecified failover type)")
        return 'partial_failover'

    # Unknown test type
    logger.warning(f"Unknown test type '{type_str}' - passing to Pydantic for validation")
    return type_str


def text_to_bcpdr(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract BCP/DR testing evidence from ANY text source using XML format.

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

    prompt = f"""{BCPDR_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

{text}

Output in XML format as shown in examples:
<bcpdr>
- test_date:
- test_result:
- test_type:
- scope:
- recovery_time_objective_met:
</bcpdr>
"""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=800,  # Increased for XML format
        temperature=0.0,  # Deterministic output
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'bcpdr')

    # Apply normalization to enum fields
    test_result = parsed_data.get('test_result')
    if test_result:
        test_result = normalize_test_result(test_result)

    test_type = parsed_data.get('test_type')
    if test_type:
        test_type = normalize_test_type(test_type)

    # Build dict for Pydantic validation
    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_007_bcpdr_testing',
        'test_date': parsed_data.get('test_date'),
        'test_result': test_result,
        'test_type': test_type,
        'scope': parsed_data.get('scope', 'Not specified'),
        'recovery_time_objective_met': parsed_data.get('recovery_time_objective_met'),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


def normalize_scan_type(scan_str: str) -> str:
    """
    Normalize vulnerability scan type variations.

    Maps variations to either:
    - "authenticated"
    - "unauthenticated"

    Args:
        scan_str: Raw scan type from Claude

    Returns:
        str: Normalized scan type

    Examples:
        >>> normalize_scan_type("credentialed scan")
        'authenticated'
        >>> normalize_scan_type("external scan")
        'unauthenticated'
    """
    scan_lower = scan_str.lower().strip()

    # Authenticated scan variations
    if any(x in scan_lower for x in ['authenticated', 'credentialed', 'agent', 'internal']):
        if scan_str != 'authenticated':
            logger.info(f"Normalized scan type: '{scan_str}' → 'authenticated'")
        return 'authenticated'

    # Unauthenticated scan variations
    if any(x in scan_lower for x in ['unauthenticated', 'external', 'non-credentialed', 'agentless']):
        if scan_str != 'unauthenticated':
            logger.info(f"Normalized scan type: '{scan_str}' → 'unauthenticated'")
        return 'unauthenticated'

    # Default to authenticated if unclear
    logger.info(f"Unknown scan type '{scan_str}' - defaulting to 'authenticated'")
    return 'authenticated'


def text_to_vulnerability(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Vulnerability Management evidence from ANY text source using XML format.

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

    prompt = f"""{VULNERABILITY_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

{text}

Output in XML format as shown in examples.
"""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=1500,  # Increased for XML with arrays
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'vulnerability')

    # Map scan field names and apply normalization
    scans = parsed_data.get('scans_last_3_months', [])
    mapped_scans = []
    for scan in scans:
        # Map short XML field names to Pydantic field names
        mapped_scan = {
            'scan_date': scan.get('date'),
            'scanner_tool': scan.get('tool'),
            'scan_type': scan.get('type'),
            'critical_findings': scan.get('critical'),
            'high_findings': scan.get('high'),
            'medium_findings': scan.get('medium'),
            'low_findings': scan.get('low'),
        }
        # Apply normalization to scan_type
        if mapped_scan['scan_type']:
            mapped_scan['scan_type'] = normalize_scan_type(mapped_scan['scan_type'])
        mapped_scans.append(mapped_scan)
    scans = mapped_scans

    # Get pentest data and map field names to match Pydantic model
    pentest_data = parsed_data.get('penetration_test', {})
    if pentest_data and any(pentest_data.values()):
        # Map short XML field names to Pydantic field names
        pentest_mapped = {
            'test_date': pentest_data.get('date'),
            'tester_firm': pentest_data.get('firm'),
            'test_type': pentest_data.get('type'),
            'critical_findings': pentest_data.get('critical'),
            'high_findings': pentest_data.get('high'),
            'medium_findings': pentest_data.get('medium'),
            'low_findings': pentest_data.get('low'),
            'all_critical_high_remediated': pentest_data.get('all_remediated'),
        }
        pentest_data = pentest_mapped
    else:
        pentest_data = None

    # Build dict for Pydantic validation
    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_004_vulnerability_mgmt',
        'scans_last_3_months': scans,
        'penetration_test': pentest_data,
        'vulnerability_sla_met': parsed_data.get('vulnerability_sla_met'),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


def text_to_sso_mfa(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract SSO/MFA requirements evidence from ANY text source using XML format.

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

    prompt = f"""{SSO_MFA_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

{text}

Output in XML format as shown in examples:
<sso_mfa>
- sso_supported:
- sso_protocols:
- mfa_enforced:
- mfa_types:
- sso_paywall:
- mfa_phishing_resistant:
</sso_mfa>
"""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=800,  # Increased for XML format
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'sso_mfa')

    # Convert semicolon-separated mfa_types to list
    mfa_types_str = parsed_data.get('mfa_types', '')
    mfa_types_list = [t.strip() for t in mfa_types_str.split(';') if t.strip()] if mfa_types_str else []

    # Convert protocols (also semicolon-separated in examples)
    sso_protocols_str = parsed_data.get('sso_protocols', '')
    sso_protocols_list = [p.strip() for p in sso_protocols_str.split(';') if p.strip()] if sso_protocols_str else []

    # Apply normalization to match Pydantic enum values
    # This bridges Claude's variations (e.g., "SAML 2.0") to strict enums (e.g., "saml")
    # Filter out None values (generic/unspecified mentions)
    normalized_protocols = [p for p in (normalize_sso_protocol(p) for p in sso_protocols_list) if p is not None]
    normalized_mfa_types = [t for t in (normalize_mfa_type(t) for t in mfa_types_list) if t is not None]

    # Build dict for Pydantic validation
    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_023_sso_mfa',
        'sso_supported': parsed_data.get('sso_supported', False),
        'sso_protocols': normalized_protocols,
        'sso_requires_paid_plan': parsed_data.get('sso_paywall', False),
        'mfa_enforced_by_default': parsed_data.get('mfa_enforced', False),
        'mfa_types_supported': normalized_mfa_types,
        'phishing_resistant_mfa_available': parsed_data.get('mfa_phishing_resistant', False),
        'mfa_coverage_percentage': 100 if parsed_data.get('mfa_enforced') else 0,
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


def text_to_encryption_at_rest(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Encryption at Rest evidence from ANY text source using XML format.

    Supports text from:
    - SOC 2 reports (Section 4 controls)
    - Trust center websites
    - Security documentation
    - Policy documents
    - Email responses about encryption

    Args:
        text: Raw text containing encryption at rest information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for EncryptionAtRestEvidence.model_validate()

    Example:
        >>> text = "All data encrypted at rest using AES-256, AWS KMS..."
        >>> data = text_to_encryption_at_rest(text, "Acme Corp")
        >>> evidence = EncryptionAtRestEvidence.model_validate(data)
        >>> print(evidence.get_compliance_percentage())  # 100%
    """
    from conduit.training_examples import ENCRYPTION_AT_REST_EXAMPLES

    prompt = f"""{ENCRYPTION_AT_REST_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for encryption at rest evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=4000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'encryption_at_rest')

    # Normalize and map fields
    stores = parsed_data.get('stores', [])
    normalized_stores = []

    for store in stores:
        # Skip if encrypted status is unknown/no/none
        encrypted_str = store.get('encrypted', '').lower()
        if encrypted_str in ['unknown', 'no', 'none', '']:
            continue

        is_encrypted = encrypted_str in ['yes', 'true', 'enabled']

        # Normalize fields
        store_type = normalize_data_store_type(store.get('type', ''))
        algorithm = normalize_encryption_algorithm(store.get('algorithm', ''))
        key_mgmt = normalize_key_management(store.get('key_mgmt', ''))

        # Skip if we couldn't determine store type
        if not store_type or store_type in ['none', 'unknown']:
            continue

        normalized_store = {
            'evidence_type': 'assure_012_encryption_at_rest',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'store_type': store_type,
            'store_name': store.get('name', '').strip() if store.get('name', '').lower() not in ['none', 'unknown'] else None,
            'is_encrypted': is_encrypted,
            'encryption_algorithm': algorithm,
            'key_management': key_mgmt,
        }
        normalized_stores.append(normalized_store)

    # Key rotation
    key_rotation_str = parsed_data.get('key_rotation', '').lower()
    key_rotation = key_rotation_str in ['yes', 'true', 'enabled']

    # Rotation days
    rotation_days_str = parsed_data.get('rotation_days', '')
    rotation_days = None
    if rotation_days_str and rotation_days_str.lower() not in ['none', 'unknown']:
        try:
            rotation_days = int(rotation_days_str)
        except ValueError:
            pass

    # FIPS compliance
    fips_str = parsed_data.get('fips_compliant', '').lower()
    fips_compliant = fips_str in ['yes', 'true', 'compliant']

    # Build output
    return {
        'evidence_type': 'assure_012_encryption_at_rest',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'soc2_section_4_criteria': ['CC6.1', 'CC6.7'],
        'soc2_coverage_percentage': 100,  # These controls fully cover encryption at rest
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'source_document': None,
        'encrypted_stores': normalized_stores,
        'key_rotation_enabled': key_rotation,
        'key_rotation_frequency_days': rotation_days,
        'fips_140_2_compliant': fips_compliant,
    }


def normalize_encryption_algorithm(algo_str: str) -> str:
    """
    Normalize encryption algorithm variations to Pydantic enum values.

    Maps variations like "AES-256-GCM", "aes256" to standard enum values:
    - "aes_256"
    - "aes_128"
    - "rsa_2048"
    - "rsa_4096"

    Args:
        algo_str: Raw algorithm string from Claude's extraction

    Returns:
        str: Normalized algorithm value matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_encryption_algorithm("AES-256-GCM")
        'aes_256'
        >>> normalize_encryption_algorithm("RSA 2048")
        'rsa_2048'
        >>> normalize_encryption_algorithm("not specified")
        None
    """
    algo_lower = algo_str.lower().strip()

    # Filter generic/unknown
    if any(x in algo_lower for x in ['not specified', 'none', 'unknown', 'industry standard', 'industry-standard']):
        logger.info(f"Ignoring unspecified encryption algorithm: '{algo_str}'")
        return None

    # AES-256 variations
    if any(x in algo_lower for x in ['aes-256', 'aes256', 'aes 256', 'aes-256-gcm', 'aes_256']):
        if algo_str != 'aes_256':
            logger.info(f"Normalized algorithm: '{algo_str}' → 'aes_256'")
        return 'aes_256'

    # AES-128 variations
    if any(x in algo_lower for x in ['aes-128', 'aes128', 'aes 128', 'aes_128']):
        if algo_str != 'aes_128':
            logger.info(f"Normalized algorithm: '{algo_str}' → 'aes_128'")
        return 'aes_128'

    # RSA variations
    if any(x in algo_lower for x in ['rsa-2048', 'rsa2048', 'rsa 2048', 'rsa_2048']):
        if algo_str != 'rsa_2048':
            logger.info(f"Normalized algorithm: '{algo_str}' → 'rsa_2048'")
        return 'rsa_2048'

    if any(x in algo_lower for x in ['rsa-4096', 'rsa4096', 'rsa 4096', 'rsa_4096']):
        if algo_str != 'rsa_4096':
            logger.info(f"Normalized algorithm: '{algo_str}' → 'rsa_4096'")
        return 'rsa_4096'

    # Don't log warning for already-normalized values
    if algo_str in ['aes_256', 'aes_128', 'rsa_2048', 'rsa_4096']:
        return algo_str

    logger.warning(f"Unknown encryption algorithm '{algo_str}'")
    return algo_str


def normalize_key_management(kms_str: str) -> str:
    """
    Normalize key management system variations to Pydantic enum values.

    Maps variations like "AWS KMS", "Key Vault" to standard enum values:
    - "aws_kms"
    - "azure_key_vault"
    - "gcp_kms"
    - "hsm"
    - "internal_kms"
    - "third_party_kms"

    Args:
        kms_str: Raw key management string from Claude's extraction

    Returns:
        str: Normalized KMS value matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_key_management("AWS KMS")
        'aws_kms'
        >>> normalize_key_management("Azure Key Vault")
        'azure_key_vault'
        >>> normalize_key_management("not specified")
        None
    """
    kms_lower = kms_str.lower().strip()

    # Filter generic/unknown
    if any(x in kms_lower for x in ['not specified', 'none', 'unknown']):
        logger.info(f"Ignoring unspecified key management: '{kms_str}'")
        return None

    # AWS KMS variations
    if any(x in kms_lower for x in ['aws kms', 'amazon kms', 'aws key management', 'aws_kms']):
        if kms_str != 'aws_kms':
            logger.info(f"Normalized key management: '{kms_str}' → 'aws_kms'")
        return 'aws_kms'

    # Azure Key Vault variations
    if any(x in kms_lower for x in ['azure key vault', 'azure kv', 'key vault', 'azure_key_vault']):
        if kms_str != 'azure_key_vault':
            logger.info(f"Normalized key management: '{kms_str}' → 'azure_key_vault'")
        return 'azure_key_vault'

    # GCP KMS variations
    if any(x in kms_lower for x in ['gcp kms', 'google kms', 'cloud kms', 'gcp_kms']):
        if kms_str != 'gcp_kms':
            logger.info(f"Normalized key management: '{kms_str}' → 'gcp_kms'")
        return 'gcp_kms'

    # HSM variations
    if any(x in kms_lower for x in ['hsm', 'hardware security module']):
        if kms_str != 'hsm':
            logger.info(f"Normalized key management: '{kms_str}' → 'hsm'")
        return 'hsm'

    # Internal KMS
    if any(x in kms_lower for x in ['internal', 'in-house', 'proprietary', 'internal_kms']):
        if kms_str != 'internal_kms':
            logger.info(f"Normalized key management: '{kms_str}' → 'internal_kms'")
        return 'internal_kms'

    # Third-party KMS
    if any(x in kms_lower for x in ['third party', 'third-party', 'external', 'third_party_kms']):
        if kms_str != 'third_party_kms':
            logger.info(f"Normalized key management: '{kms_str}' → 'third_party_kms'")
        return 'third_party_kms'

    # Don't log warning for already-normalized values
    if kms_str in ['aws_kms', 'azure_key_vault', 'gcp_kms', 'hsm', 'internal_kms', 'third_party_kms']:
        return kms_str

    logger.warning(f"Unknown key management system '{kms_str}'")
    return kms_str


def normalize_incident_type(type_str: str) -> str:
    """
    Normalize incident type variations to Pydantic enum values.

    Maps variations like "data breach", "security incident", "system outage" to standard enum values:
    - "security_breach"
    - "privacy_breach"
    - "availability"
    - "data_integrity"
    - "ransomware"

    Args:
        type_str: Raw incident type string from Claude's extraction

    Returns:
        str: Normalized incident type matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_incident_type("data breach")
        'privacy_breach'
        >>> normalize_incident_type("security incident")
        'security_breach'
        >>> normalize_incident_type("ransomware attack")
        'ransomware'
    """
    type_lower = type_str.lower().strip()

    # Handle unspecified/generic responses
    if any(x in type_lower for x in ['not specified', 'not mentioned', 'unknown', 'none']):
        logger.info(f"Ignoring unspecified incident type: '{type_str}'")
        return None

    # Security breach variations
    if any(x in type_lower for x in ['security incident', 'security breach', 'cyberattack', 'cyber attack', 'intrusion', 'unauthorized access']):
        if type_str != 'security_breach':
            logger.info(f"Normalized incident type: '{type_str}' → 'security_breach'")
        return 'security_breach'

    # Privacy/data breach variations
    if any(x in type_lower for x in ['data breach', 'privacy breach', 'privacy incident', 'pii breach', 'personal data', 'gdpr']):
        if type_str != 'privacy_breach':
            logger.info(f"Normalized incident type: '{type_str}' → 'privacy_breach'")
        return 'privacy_breach'

    # Availability/outage variations
    if any(x in type_lower for x in ['availability', 'system outage', 'downtime', 'service disruption', 'ddos', 'denial of service']):
        if type_str != 'availability':
            logger.info(f"Normalized incident type: '{type_str}' → 'availability'")
        return 'availability'

    # Data integrity variations
    if any(x in type_lower for x in ['data integrity', 'integrity issue', 'data corruption', 'unauthorized modification']):
        if type_str != 'data_integrity':
            logger.info(f"Normalized incident type: '{type_str}' → 'data_integrity'")
        return 'data_integrity'

    # Ransomware variations
    if any(x in type_lower for x in ['ransomware', 'crypto attack', 'encryption attack', 'ransom']):
        if type_str != 'ransomware':
            logger.info(f"Normalized incident type: '{type_str}' → 'ransomware'")
        return 'ransomware'

    # Unknown incident type - let Pydantic validation error
    logger.warning(f"Unknown incident type '{type_str}' - passing to Pydantic for validation")
    return type_str


def normalize_ir_test_type(test_str: str) -> str:
    """
    Normalize incident response test type variations to Pydantic enum values.

    Maps variations like "tabletop exercise", "simulation", "live drill" to standard enum values:
    - "tabletop"
    - "walkthrough"
    - "simulation"
    - "live_drill"
    - "none"

    Args:
        test_str: Raw test type string from Claude's extraction

    Returns:
        str: Normalized test type matching Pydantic enum

    Examples:
        >>> normalize_ir_test_type("tabletop exercise")
        'tabletop'
        >>> normalize_ir_test_type("full simulation")
        'simulation'
    """
    test_lower = test_str.lower().strip()

    # Handle none/unspecified
    if any(x in test_lower for x in ['none', 'not tested', 'no test', 'not mentioned', 'unknown']):
        logger.info(f"No IR test conducted: '{test_str}' → 'none'")
        return 'none'

    # Tabletop exercise variations
    if any(x in test_lower for x in ['tabletop', 'table top', 'discussion', 'desktop']):
        if test_str != 'tabletop':
            logger.info(f"Normalized IR test type: '{test_str}' → 'tabletop'")
        return 'tabletop'

    # Walkthrough variations
    if any(x in test_lower for x in ['walkthrough', 'walk through', 'review', 'structured walkthrough']):
        if test_str != 'walkthrough':
            logger.info(f"Normalized IR test type: '{test_str}' → 'walkthrough'")
        return 'walkthrough'

    # Simulation variations
    if any(x in test_lower for x in ['simulation', 'functional', 'partial', 'exercise']):
        if test_str != 'simulation':
            logger.info(f"Normalized IR test type: '{test_str}' → 'simulation'")
        return 'simulation'

    # Live drill variations
    if any(x in test_lower for x in ['live drill', 'full', 'operational', 'real']):
        if test_str != 'live_drill':
            logger.info(f"Normalized IR test type: '{test_str}' → 'live_drill'")
        return 'live_drill'

    # Unknown test type
    logger.warning(f"Unknown IR test type '{test_str}' - passing to Pydantic for validation")
    return test_str


def normalize_notification_sla(sla_str: str) -> str:
    """
    Normalize notification SLA variations to Pydantic enum values.

    Maps variations like "within 24 hours", "immediately", "72 hours" to standard enum values:
    - "immediate"
    - "1_hour"
    - "4_hours"
    - "24_hours"
    - "72_hours"
    - "none"

    Args:
        sla_str: Raw SLA string from Claude's extraction

    Returns:
        str: Normalized SLA matching Pydantic enum

    Examples:
        >>> normalize_notification_sla("within 24 hours")
        '24_hours'
        >>> normalize_notification_sla("immediately")
        'immediate'
        >>> normalize_notification_sla("3 days")
        '72_hours'
    """
    sla_lower = sla_str.lower().strip()

    # Handle none/unspecified
    if any(x in sla_lower for x in ['none', 'not specified', 'not mentioned', 'no sla', 'unknown']):
        logger.info(f"No SLA specified: '{sla_str}' → 'none'")
        return 'none'

    # Immediate variations
    if any(x in sla_lower for x in ['immediate', 'instantly', 'real time', 'realtime', 'without delay']):
        if sla_str != 'immediate':
            logger.info(f"Normalized notification SLA: '{sla_str}' → 'immediate'")
        return 'immediate'

    # 1 hour variations
    if any(x in sla_lower for x in ['1 hour', 'one hour', 'within an hour', '60 min']):
        if sla_str != '1_hour':
            logger.info(f"Normalized notification SLA: '{sla_str}' → '1_hour'")
        return '1_hour'

    # 4 hours variations
    if any(x in sla_lower for x in ['4 hours', 'four hours', 'within 4 hours']):
        if sla_str != '4_hours':
            logger.info(f"Normalized notification SLA: '{sla_str}' → '4_hours'")
        return '4_hours'

    # 24 hours / 1 day variations
    if any(x in sla_lower for x in ['24 hours', 'twenty four hours', '1 day', 'one day', 'within a day']):
        if sla_str != '24_hours':
            logger.info(f"Normalized notification SLA: '{sla_str}' → '24_hours'")
        return '24_hours'

    # 72 hours / 3 days variations
    if any(x in sla_lower for x in ['72 hours', 'seventy two hours', '3 days', 'three days', 'within 3 days']):
        if sla_str != '72_hours':
            logger.info(f"Normalized notification SLA: '{sla_str}' → '72_hours'")
        return '72_hours'

    # Unknown SLA
    logger.warning(f"Unknown notification SLA '{sla_str}' - passing to Pydantic for validation")
    return sla_str


def normalize_data_store_type(store_str: str) -> str:
    """
    Normalize data store type variations to Pydantic enum values.

    Maps variations like "PostgreSQL", "S3", "snapshots" to standard enum values:
    - "database"
    - "file_storage"
    - "object_storage"
    - "backups"

    Args:
        store_str: Raw store type string from Claude's extraction

    Returns:
        str: Normalized store type matching Pydantic enum

    Examples:
        >>> normalize_data_store_type("PostgreSQL")
        'database'
        >>> normalize_data_store_type("S3 bucket")
        'file_storage'
        >>> normalize_data_store_type("snapshots")
        'backups'
    """
    store_lower = store_str.lower().strip()

    # Database variations
    if any(x in store_lower for x in ['database', 'db', 'rds', 'sql', 'postgresql', 'mysql', 'mongodb', 'dynamodb']):
        if store_str != 'database':
            logger.info(f"Normalized store type: '{store_str}' → 'database'")
        return 'database'

    # File storage variations
    if any(x in store_lower for x in ['file storage', 'file system', 's3', 'blob', 'files', 'file_storage']):
        if store_str != 'file_storage':
            logger.info(f"Normalized store type: '{store_str}' → 'file_storage'")
        return 'file_storage'

    # Object storage (separate enum value)
    if any(x in store_lower for x in ['object storage', 'object_storage', 's3 bucket', 'azure blob']):
        if store_str != 'object_storage':
            logger.info(f"Normalized store type: '{store_str}' → 'object_storage'")
        return 'object_storage'

    # Backups
    if any(x in store_lower for x in ['backup', 'snapshot', 'archive', 'backups']):
        if store_str != 'backups':
            logger.info(f"Normalized store type: '{store_str}' → 'backups'")
        return 'backups'

    # Don't log warning for already-normalized values
    if store_str in ['database', 'file_storage', 'object_storage', 'backups']:
        return store_str

    logger.warning(f"Unknown data store type '{store_str}'")
    return store_str


def text_to_incident_response(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Incident Response evidence from ANY text source using XML format.

    Supports text from:
    - SOC 2 reports (CC2.2, CC7.3 controls)
    - ISO 27001 documentation
    - Trust center websites
    - Policy documents
    - Email responses about incident management

    Args:
        text: Raw text containing incident response information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for IncidentResponseEvidence.model_validate()

    Example:
        >>> text = "We maintain an IR plan covering security incidents..."
        >>> data = text_to_incident_response(text, "Acme Corp")
        >>> evidence = IncidentResponseEvidence.model_validate(data)
        >>> print(evidence.get_compliance_percentage())  # Shows compliance %
    """

    prompt = f"""{INCIDENT_RESPONSE_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

{text}

Output in XML format as shown in examples:
<incident_response>
<plan_exists></plan_exists>
<last_test_date></last_test_date>
<test_type></test_type>
<incident_types_covered>
  <type></type>
</incident_types_covered>
<security_breach_sla></security_breach_sla>
<privacy_breach_sla></privacy_breach_sla>
<lessons_learned_documented></lessons_learned_documented>
<plan_accessible_to_employees></plan_accessible_to_employees>
</incident_response>
"""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=1200,  # Increased for XML with arrays
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'incident_response')

    # Apply normalization to incident types
    incident_types_raw = parsed_data.get('incident_types_covered', [])
    incident_types_normalized = [
        t for t in (normalize_incident_type(type_str) for type_str in incident_types_raw)
        if t is not None
    ]

    # Apply normalization to test type
    test_type = parsed_data.get('test_type')
    if test_type:
        test_type = normalize_ir_test_type(test_type)

    # Apply normalization to SLAs
    security_breach_sla = parsed_data.get('security_breach_sla')
    if security_breach_sla:
        security_breach_sla = normalize_notification_sla(security_breach_sla)

    privacy_breach_sla = parsed_data.get('privacy_breach_sla')
    if privacy_breach_sla:
        privacy_breach_sla = normalize_notification_sla(privacy_breach_sla)

    # Convert boolean-like strings to actual booleans
    plan_exists = parsed_data.get('plan_exists')
    if isinstance(plan_exists, str):
        plan_exists = plan_exists.lower() in ['yes', 'true', 'exists']

    lessons_learned = parsed_data.get('lessons_learned_documented')
    if isinstance(lessons_learned, str):
        lessons_learned = lessons_learned.lower() in ['yes', 'true', 'documented']

    plan_accessible = parsed_data.get('plan_accessible_to_employees')
    if isinstance(plan_accessible, str):
        # Handle "unknown" as False for now, since accessibility is a key requirement
        plan_accessible = plan_accessible.lower() in ['yes', 'true', 'accessible']

    # Build dict for Pydantic validation
    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_005_incident_response',
        'plan_exists': plan_exists if isinstance(plan_exists, bool) else False,
        'last_test_date': parsed_data.get('last_test_date'),
        'test_type': test_type if test_type else 'none',
        'incident_types_covered': incident_types_normalized,
        'security_breach_sla': security_breach_sla if security_breach_sla else 'none',
        'privacy_breach_sla': privacy_breach_sla if privacy_breach_sla else 'none',
        'lessons_learned_documented': lessons_learned if isinstance(lessons_learned, bool) else False,
        'plan_accessible_to_employees': plan_accessible if isinstance(plan_accessible, bool) else False,
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
    }

    return result


def normalize_retention_period(retention_str: str) -> str:
    """
    Normalize log retention period variations to Pydantic enum values.

    Maps variations like "12 months", "365 days", "1 year" to standard enum values:
    - "30_days"
    - "90_days"
    - "1_year"
    - "2_years"
    - "7_years"
    - "indefinite"

    Args:
        retention_str: Raw retention period string from Claude's extraction

    Returns:
        str: Normalized retention period matching Pydantic enum

    Examples:
        >>> normalize_retention_period("12 months")
        '1_year'
        >>> normalize_retention_period("365 days")
        '1_year'
        >>> normalize_retention_period("permanent")
        'indefinite'
    """
    retention_lower = retention_str.lower().strip()

    # 30 days variations
    if any(x in retention_lower for x in ['30 days', '30 day', '1 month', 'one month', '30_days']):
        if retention_str != '30_days':
            logger.info(f"Normalized retention period: '{retention_str}' → '30_days'")
        return '30_days'

    # 90 days variations
    if any(x in retention_lower for x in ['90 days', '90 day', '3 months', 'three months', '90_days']):
        if retention_str != '90_days':
            logger.info(f"Normalized retention period: '{retention_str}' → '90_days'")
        return '90_days'

    # 1 year variations
    if any(x in retention_lower for x in ['1 year', 'one year', '12 months', 'twelve months', '365 days', '1_year']):
        if retention_str != '1_year':
            logger.info(f"Normalized retention period: '{retention_str}' → '1_year'")
        return '1_year'

    # 2 years variations
    if any(x in retention_lower for x in ['2 years', 'two years', '24 months', '730 days', '2_years']):
        if retention_str != '2_years':
            logger.info(f"Normalized retention period: '{retention_str}' → '2_years'")
        return '2_years'

    # 7 years variations
    if any(x in retention_lower for x in ['7 years', 'seven years', '84 months', '7_years']):
        if retention_str != '7_years':
            logger.info(f"Normalized retention period: '{retention_str}' → '7_years'")
        return '7_years'

    # Indefinite variations
    if any(x in retention_lower for x in ['indefinite', 'permanent', 'forever', 'unlimited', 'no expiry']):
        if retention_str != 'indefinite':
            logger.info(f"Normalized retention period: '{retention_str}' → 'indefinite'")
        return 'indefinite'

    # Already normalized or unknown
    if retention_str in ['30_days', '90_days', '1_year', '2_years', '7_years', 'indefinite']:
        return retention_str

    logger.warning(f"Unknown retention period '{retention_str}' - passing to Pydantic for validation")
    return retention_str


def normalize_log_type(log_type_str: str) -> str:
    """
    Normalize log type variations to Pydantic enum values.

    Maps variations like "authentication logs", "security events" to standard enum values:
    - "security"
    - "access"
    - "audit"
    - "application"
    - "system"
    - "database"

    Args:
        log_type_str: Raw log type string from Claude's extraction

    Returns:
        str: Normalized log type matching Pydantic enum, or None if unspecified

    Examples:
        >>> normalize_log_type("authentication logs")
        'access'
        >>> normalize_log_type("security events")
        'security'
        >>> normalize_log_type("db queries")
        'database'
    """
    log_lower = log_type_str.lower().strip()

    # Handle unspecified/generic responses
    if any(x in log_lower for x in ['not specified', 'not mentioned', 'unknown', 'none']):
        logger.info(f"Ignoring unspecified log type: '{log_type_str}'")
        return None

    # Security log variations
    if any(x in log_lower for x in ['security', 'intrusion', 'threat', 'ids', 'ips', 'firewall']):
        if log_type_str != 'security':
            logger.info(f"Normalized log type: '{log_type_str}' → 'security'")
        return 'security'

    # Access log variations
    if any(x in log_lower for x in ['access', 'authentication', 'authorization', 'login', 'logout', 'auth']):
        if log_type_str != 'access':
            logger.info(f"Normalized log type: '{log_type_str}' → 'access'")
        return 'access'

    # Audit log variations
    if any(x in log_lower for x in ['audit', 'compliance', 'trail', 'data change', 'config change', 'modification']):
        if log_type_str != 'audit':
            logger.info(f"Normalized log type: '{log_type_str}' → 'audit'")
        return 'audit'

    # Application log variations
    if any(x in log_lower for x in ['application', 'app', 'error', 'transaction', 'service']):
        if log_type_str != 'application':
            logger.info(f"Normalized log type: '{log_type_str}' → 'application'")
        return 'application'

    # System log variations
    if any(x in log_lower for x in ['system', 'os', 'infrastructure', 'syslog', 'kernel', 'hardware']):
        if log_type_str != 'system':
            logger.info(f"Normalized log type: '{log_type_str}' → 'system'")
        return 'system'

    # Database log variations
    if any(x in log_lower for x in ['database', 'db', 'query', 'sql', 'data access', 'db audit']):
        if log_type_str != 'database':
            logger.info(f"Normalized log type: '{log_type_str}' → 'database'")
        return 'database'

    # Already normalized or unknown
    if log_type_str in ['security', 'access', 'audit', 'application', 'system', 'database']:
        return log_type_str

    logger.warning(f"Unknown log type '{log_type_str}' - passing to Pydantic for validation")
    return log_type_str


def normalize_monitoring_tool(tool_str: str) -> str:
    """
    Normalize monitoring/SIEM tool variations to Pydantic enum values.

    Maps variations like "ELK Stack", "Amazon CloudWatch" to standard enum values:
    - "splunk"
    - "datadog"
    - "elk"
    - "cloudwatch"
    - "sentinel"
    - "sumo_logic"
    - "other"

    Args:
        tool_str: Raw monitoring tool string from Claude's extraction

    Returns:
        str: Normalized monitoring tool matching Pydantic enum

    Examples:
        >>> normalize_monitoring_tool("ELK Stack")
        'elk'
        >>> normalize_monitoring_tool("AWS CloudWatch")
        'cloudwatch'
        >>> normalize_monitoring_tool("Microsoft Sentinel")
        'sentinel'
    """
    tool_lower = tool_str.lower().strip()

    # Handle unspecified/generic responses
    if any(x in tool_lower for x in ['not specified', 'not mentioned', 'unknown', 'none']):
        logger.info(f"No monitoring tool specified: '{tool_str}' → 'other'")
        return 'other'

    # Splunk variations
    if 'splunk' in tool_lower:
        if tool_str != 'splunk':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'splunk'")
        return 'splunk'

    # Datadog variations
    if 'datadog' in tool_lower or 'data dog' in tool_lower:
        if tool_str != 'datadog':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'datadog'")
        return 'datadog'

    # ELK Stack variations
    if any(x in tool_lower for x in ['elk', 'elasticsearch', 'elastic', 'logstash', 'kibana']):
        if tool_str != 'elk':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'elk'")
        return 'elk'

    # CloudWatch variations
    if any(x in tool_lower for x in ['cloudwatch', 'cloud watch', 'aws cloudwatch', 'amazon cloudwatch']):
        if tool_str != 'cloudwatch':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'cloudwatch'")
        return 'cloudwatch'

    # Sentinel variations
    if any(x in tool_lower for x in ['sentinel', 'microsoft sentinel', 'azure sentinel']):
        if tool_str != 'sentinel':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'sentinel'")
        return 'sentinel'

    # Sumo Logic variations
    if any(x in tool_lower for x in ['sumo logic', 'sumologic', 'sumo_logic']):
        if tool_str != 'sumo_logic':
            logger.info(f"Normalized monitoring tool: '{tool_str}' → 'sumo_logic'")
        return 'sumo_logic'

    # Already normalized
    if tool_str in ['splunk', 'datadog', 'elk', 'cloudwatch', 'sentinel', 'sumo_logic', 'other']:
        return tool_str

    # Unknown tool - classify as "other"
    logger.info(f"Unknown monitoring tool '{tool_str}' → 'other'")
    return 'other'


def text_to_logging_config(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Logging Configuration evidence from ANY text source using XML format.

    Supports text from:
    - SOC 2 reports (CC7.2 controls)
    - ISO 27001 documentation
    - Trust center websites
    - Security documentation
    - Policy documents
    - Email responses about logging

    Args:
        text: Raw text containing logging configuration information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for LoggingConfigEvidence.model_validate()

    Example:
        >>> text = "We maintain comprehensive logging with Splunk, 1 year retention..."
        >>> data = text_to_logging_config(text, "Acme Corp")
        >>> evidence = LoggingConfigEvidence.model_validate(data)
        >>> print(evidence.get_compliance_percentage())  # Shows compliance %
    """

    prompt = f"""{LOGGING_CONFIG_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

{text}

Output in XML format as shown in examples:
<logging_config>
<retention_period></retention_period>
<log_types>
  <type></type>
</log_types>
<monitoring_tool></monitoring_tool>
<logs_immutable></logs_immutable>
<centralized_logging></centralized_logging>
</logging_config>
"""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=1200,  # Increased for XML with arrays
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    # Parse XML response
    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'logging_config')

    # Apply normalization to retention period
    retention_period = parsed_data.get('retention_period')
    if retention_period:
        retention_period = normalize_retention_period(retention_period)

    # Apply normalization to log types
    log_types_raw = parsed_data.get('log_types_collected', [])
    log_types_normalized = [
        t for t in (normalize_log_type(type_str) for type_str in log_types_raw)
        if t is not None
    ]

    # Apply normalization to monitoring tool
    monitoring_tool = parsed_data.get('monitoring_tool')
    if monitoring_tool:
        monitoring_tool = normalize_monitoring_tool(monitoring_tool)

    # Convert boolean-like strings to actual booleans
    logs_immutable = parsed_data.get('logs_immutable')
    if isinstance(logs_immutable, str):
        logs_immutable = logs_immutable.lower() in ['yes', 'true', 'enabled', 'immutable']

    centralized_logging = parsed_data.get('centralized_logging')
    if isinstance(centralized_logging, str):
        centralized_logging = centralized_logging.lower() in ['yes', 'true', 'enabled', 'centralized']

    # Build dict for Pydantic validation
    result = {
        'vendor_name': vendor_name,
        'evidence_date': str(date.today()),
        'evidence_type': 'assure_014_logging_config',
        'retention_period': retention_period if retention_period else '30_days',  # Default to minimum
        'log_types_collected': log_types_normalized,
        'monitoring_tool': monitoring_tool if monitoring_tool else 'other',
        'logs_immutable': logs_immutable if isinstance(logs_immutable, bool) else False,
        'centralized_logging': centralized_logging if isinstance(centralized_logging, bool) else False,
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


# ============================================================================
# Evidence #13: Encryption in Transit Normalizers
# ============================================================================

def normalize_tls_version(version_str: str) -> str:
    """
    Normalize TLS version variations to Pydantic enum values.

    Maps variations like "TLS 1.2", "TLSv1.2", "TLS1.2" to standard enum values.
    """
    version_lower = version_str.lower().strip()

    # Filter generic/unknown
    if any(x in version_lower for x in ['not specified', 'none', 'unknown']):
        logger.info(f"Ignoring unspecified TLS version: '{version_str}'")
        return None

    # TLS 1.3 variations
    if any(x in version_lower for x in ['tls 1.3', 'tlsv1.3', 'tls1.3', 'tls_1_3']):
        if version_str != 'tls_1_3':
            logger.info(f"Normalized TLS version: '{version_str}' → 'tls_1_3'")
        return 'tls_1_3'

    # TLS 1.2 variations
    if any(x in version_lower for x in ['tls 1.2', 'tlsv1.2', 'tls1.2', 'tls_1_2']):
        if version_str != 'tls_1_2':
            logger.info(f"Normalized TLS version: '{version_str}' → 'tls_1_2'")
        return 'tls_1_2'

    logger.warning(f"Unknown TLS version '{version_str}'")
    return version_str


def normalize_weak_protocol(protocol_str: str) -> str:
    """Normalize weak protocol variations to Pydantic enum values."""
    protocol_lower = protocol_str.lower().strip()

    # TLS 1.1 variations
    if any(x in protocol_lower for x in ['tls 1.1', 'tlsv1.1', 'tls1.1', 'tls_1_1']):
        logger.info(f"Normalized weak protocol: '{protocol_str}' → 'tls_1_1'")
        return 'tls_1_1'

    # TLS 1.0 variations
    if any(x in protocol_lower for x in ['tls 1.0', 'tlsv1.0', 'tls1.0', 'tls_1_0']):
        logger.info(f"Normalized weak protocol: '{protocol_str}' → 'tls_1_0'")
        return 'tls_1_0'

    # SSL v3 variations
    if any(x in protocol_lower for x in ['ssl 3', 'sslv3', 'ssl3', 'ssl_v3', 'ssl v3']):
        logger.info(f"Normalized weak protocol: '{protocol_str}' → 'ssl_v3'")
        return 'ssl_v3'

    # SSL v2 variations
    if any(x in protocol_lower for x in ['ssl 2', 'sslv2', 'ssl2', 'ssl_v2', 'ssl v2']):
        logger.info(f"Normalized weak protocol: '{protocol_str}' → 'ssl_v2'")
        return 'ssl_v2'

    logger.warning(f"Unknown weak protocol '{protocol_str}'")
    return protocol_str


def normalize_certificate_authority(ca_str: str) -> str:
    """Normalize certificate authority variations to Pydantic enum values."""
    ca_lower = ca_str.lower().strip()

    # Filter generic/unknown
    if any(x in ca_lower for x in ['not specified', 'none', 'unknown']):
        logger.info(f"Ignoring unspecified CA: '{ca_str}'")
        return 'other'

    # Let's Encrypt variations
    if any(x in ca_lower for x in ["let's encrypt", 'letsencrypt', 'lets encrypt', 'le']):
        logger.info(f"Normalized CA: '{ca_str}' → 'letsencrypt'")
        return 'letsencrypt'

    # DigiCert variations
    if any(x in ca_lower for x in ['digicert', 'digi cert']):
        logger.info(f"Normalized CA: '{ca_str}' → 'digicert'")
        return 'digicert'

    # Comodo/Sectigo variations (Comodo was renamed to Sectigo)
    if any(x in ca_lower for x in ['comodo', 'sectigo']):
        logger.info(f"Normalized CA: '{ca_str}' → 'sectigo'")
        return 'sectigo'

    # GlobalSign variations
    if any(x in ca_lower for x in ['globalsign', 'global sign']):
        logger.info(f"Normalized CA: '{ca_str}' → 'globalsign'")
        return 'globalsign'

    # Internal/self-signed variations
    if any(x in ca_lower for x in ['internal', 'self-signed', 'self signed', 'private ca']):
        logger.info(f"Normalized CA: '{ca_str}' → 'internal'")
        return 'internal'

    logger.info(f"Unknown CA '{ca_str}' → 'other'")
    return 'other'


def text_to_encryption_in_transit(
    text: str,
    vendor_name: str,
    use_expensive_model: bool = False
) -> dict[str, Any]:
    """
    Transform text to Encryption in Transit evidence.

    Uses Claude API to extract TLS configuration from SOC 2 reports, Qualys reports, etc.

    Args:
        text: Input text (SOC 2, Qualys SSL report, security doc)
        vendor_name: Name of the vendor
        use_expensive_model: If True, use Sonnet; if False, use Haiku (default)

    Returns:
        dict: Evidence data ready for Pydantic validation
    """
    from .training_examples import ENCRYPTION_IN_TRANSIT_EXAMPLES
    from .xml_parser import parse_evidence_xml

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    prompt = f"""{ENCRYPTION_IN_TRANSIT_EXAMPLES}

Now extract from this vendor's document:

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for encryption in transit evidence."""

    # Call Claude API
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=model,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )

    xml_output = response.content[0].text
    logger.debug(f"Raw Claude output:\n{xml_output}")

    # Parse XML
    parsed_data = parse_evidence_xml(xml_output, 'encryption_in_transit')

    # Normalize TLS versions
    tls_versions_list = parsed_data.get('tls_versions', [])
    normalized_tls = [normalize_tls_version(v) for v in tls_versions_list if v]
    normalized_tls = [v for v in normalized_tls if v]  # Filter None

    # Normalize weak protocols
    weak_blocked_list = parsed_data.get('weak_blocked', [])
    normalized_weak = [normalize_weak_protocol(p) for p in weak_blocked_list if p]
    normalized_weak = [p for p in normalized_weak if p]  # Filter None

    # Normalize certificate authority
    ca_str = parsed_data.get('cert_authority', '')
    normalized_ca = normalize_certificate_authority(ca_str) if ca_str else 'other'

    # Parse certificate expiry date
    cert_expiry_str = parsed_data.get('cert_expiry', '')
    cert_expiry = None
    if cert_expiry_str and cert_expiry_str.lower() not in ['unknown', 'none', 'not specified']:
        try:
            cert_expiry = date.fromisoformat(cert_expiry_str)
        except ValueError:
            logger.warning(f"Could not parse certificate expiry date: '{cert_expiry_str}'")

    # Parse Qualys grade
    qualys_grade = parsed_data.get('qualys_grade', '')
    if qualys_grade and qualys_grade.lower() in ['unknown', 'none']:
        qualys_grade = None

    # Parse forward secrecy
    forward_secrecy_str = parsed_data.get('forward_secrecy', '').lower()
    forward_secrecy = forward_secrecy_str in ['yes', 'true', 'enabled', 'supported']

    # Build output
    return {
        'evidence_type': 'assure_013_encryption_in_transit',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'soc2_section_4_criteria': ['CC6.1', 'CC6.7'],
        'soc2_coverage_percentage': 90,
        'extraction_confidence': 0.85,
        'source_document': None,
        'tls_versions_supported': normalized_tls,
        'weak_protocols_blocked': normalized_weak,
        'certificate_authority': normalized_ca,
        'certificate_expiry_date': cert_expiry.isoformat() if cert_expiry else None,
        'qualys_ssl_grade': qualys_grade,
        'forward_secrecy_enabled': forward_secrecy,
    }


# ============================================================================
# Evidence #9: Production Access Controls Normalizers
# ============================================================================

def normalize_access_method(method_str: str) -> str:
    """
    Normalize access method variations to Pydantic enum values.
    """
    method_lower = method_str.lower().strip()

    # Filter generic/unknown
    if any(x in method_lower for x in ['not specified', 'none', 'unknown', 'not mentioned']):
        logger.info(f"Ignoring unspecified access method: '{method_str}'")
        return None

    # JIT (just-in-time) variations
    if any(x in method_lower for x in ['jit', 'just-in-time', 'just in time', 'temporary', 'time-limited', 'ephemeral']):
        logger.info(f"Normalized access method: '{method_str}' → 'jit'")
        return 'jit'

    # Bastion host variations
    if any(x in method_lower for x in ['bastion', 'jump box', 'jump host', 'jumpbox']):
        logger.info(f"Normalized access method: '{method_str}' → 'bastion'")
        return 'bastion'

    # VPN variations
    if any(x in method_lower for x in ['vpn', 'virtual private network']):
        logger.info(f"Normalized access method: '{method_str}' → 'vpn'")
        return 'vpn'

    # Direct access variations
    if any(x in method_lower for x in ['direct', 'ssh', 'rdp', 'remote desktop']):
        logger.info(f"Normalized access method: '{method_str}' → 'direct'")
        return 'direct'

    # None/no access
    if method_lower in ['none', 'no access', 'denied']:
        logger.info(f"Normalized access method: '{method_str}' → 'none'")
        return 'none'

    logger.warning(f"Unknown access method '{method_str}'")
    return method_str


def normalize_session_duration(duration_str: str) -> str:
    """
    Normalize session duration variations to Pydantic enum values.
    """
    duration_lower = duration_str.lower().strip()

    # Filter unknown
    if any(x in duration_lower for x in ['not specified', 'unknown', 'not mentioned']):
        logger.info(f"Ignoring unspecified session duration: '{duration_str}'")
        return None

    # Persistent/no expiration
    if any(x in duration_lower for x in ['persistent', 'permanent', 'no expiration', 'no timeout', '24/7', 'always']):
        logger.info(f"Normalized session duration: '{duration_str}' → 'persistent'")
        return 'persistent'

    # 15 minutes
    if any(x in duration_lower for x in ['15 min', '15min', '15 minutes', 'fifteen minutes']):
        logger.info(f"Normalized session duration: '{duration_str}' → '15_min'")
        return '15_min'

    # 30 minutes
    if any(x in duration_lower for x in ['30 min', '30min', '30 minutes', 'thirty minutes', 'half hour']):
        logger.info(f"Normalized session duration: '{duration_str}' → '30_min'")
        return '30_min'

    # 1 hour
    if any(x in duration_lower for x in ['1 hour', '1hr', 'one hour', '60 min', '60 minutes']):
        logger.info(f"Normalized session duration: '{duration_str}' → '1_hour'")
        return '1_hour'

    # 4 hours
    if any(x in duration_lower for x in ['4 hour', '4hr', 'four hour', '240 min']):
        logger.info(f"Normalized session duration: '{duration_str}' → '4_hours'")
        return '4_hours'

    # 8 hours
    if any(x in duration_lower for x in ['8 hour', '8hr', 'eight hour', '480 min', 'work day', 'business day']):
        logger.info(f"Normalized session duration: '{duration_str}' → '8_hours'")
        return '8_hours'

    logger.warning(f"Unknown session duration '{duration_str}'")
    return duration_str


def text_to_production_access(
    text: str,
    vendor_name: str,
    use_expensive_model: bool = False
) -> dict[str, Any]:
    """
    Transform text to Production Access Controls evidence.

    Uses Claude API to extract production access controls from SOC 2 reports, security docs, etc.

    Args:
        text: Input text (SOC 2, trust center, security policy)
        vendor_name: Name of the vendor
        use_expensive_model: If True, use Sonnet; if False, use Haiku (default)

    Returns:
        dict: Evidence data ready for Pydantic validation
    """
    from .training_examples import PRODUCTION_ACCESS_EXAMPLES
    from .xml_parser import parse_evidence_xml

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    prompt = f"""{PRODUCTION_ACCESS_EXAMPLES}

Now extract from this vendor's document:

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for production access controls evidence."""

    # Call Claude API
    client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model=model,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )

    xml_output = response.content[0].text
    logger.debug(f"Raw Claude output:\n{xml_output}")

    # Parse XML
    parsed_data = parse_evidence_xml(xml_output, 'production_access')

    # Normalize access method
    access_method_str = parsed_data.get('access_method', '')
    normalized_access_method = normalize_access_method(access_method_str) if access_method_str else 'direct'

    # Normalize default access
    default_access_str = parsed_data.get('default_access', '')
    normalized_default_access = normalize_access_method(default_access_str) if default_access_str else 'none'

    # Parse MFA required
    mfa_required_str = parsed_data.get('mfa_required', '').lower()
    mfa_required = mfa_required_str in ['yes', 'true', 'required', 'mandatory']

    # Normalize session duration
    session_duration_str = parsed_data.get('max_session_duration', '')
    normalized_session_duration = normalize_session_duration(session_duration_str) if session_duration_str else 'persistent'

    # Parse persistent access allowed
    persistent_access_str = parsed_data.get('persistent_access_allowed', '').lower()
    persistent_access_allowed = persistent_access_str in ['yes', 'true', 'allowed', 'permitted']

    # Parse privileged accounts segregated
    segregated_str = parsed_data.get('privileged_accounts_segregated', '').lower()
    privileged_accounts_segregated = segregated_str in ['yes', 'true', 'separated', 'segregated']

    # Build output
    return {
        'evidence_type': 'assure_009_production_access',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'soc2_section_4_criteria': ['CC5.2', 'CC6.1'],
        'soc2_coverage_percentage': 85,
        'extraction_confidence': 0.80,
        'source_document': None,
        'access_method': normalized_access_method,
        'default_access': normalized_default_access,
        'mfa_required_for_privileged': mfa_required,
        'max_session_duration': normalized_session_duration,
        'persistent_access_allowed': persistent_access_allowed,
        'privileged_accounts_segregated': privileged_accounts_segregated,
    }


# ============================================================================
# BATCH 2 EXTRACTION FUNCTIONS (Evidence #1, #2, #6, #8, #15)
# ============================================================================

def normalize_backup_frequency(freq_str: str) -> str:
    """Normalize backup frequency to enum values."""
    freq_lower = freq_str.lower().strip()

    if 'continuous' in freq_lower or 'real-time' in freq_lower or 'streaming' in freq_lower:
        return 'continuous'
    if 'hour' in freq_lower:
        if '6' in freq_lower:
            return 'every_6_hours'
        if '12' in freq_lower:
            return 'every_12_hours'
        return 'hourly'
    if 'daily' in freq_lower or 'day' in freq_lower:
        return 'daily'
    if 'week' in freq_lower:
        return 'weekly'
    if 'month' in freq_lower:
        return 'monthly'

    return 'daily'  # Default assumption


def normalize_review_frequency(freq_str: str) -> str:
    """Normalize access review frequency to enum values."""
    freq_lower = freq_str.lower().strip()

    if 'month' in freq_lower:
        return 'monthly'
    if 'quarter' in freq_lower or 'q1' in freq_lower or 'q2' in freq_lower:
        return 'quarterly'
    if 'semi' in freq_lower or '6 month' in freq_lower:
        return 'semi_annual'
    if 'annual' in freq_lower or 'year' in freq_lower:
        return 'annual'

    return 'quarterly'  # Default assumption


def text_to_backup_configuration(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Backup Configuration evidence from ANY text source using XML format.

    Args:
        text: Raw text containing backup configuration information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for BackupConfiguration.model_validate()
    """
    from conduit.training_examples import BACKUP_CONFIGURATION_EXAMPLES

    prompt = f"""{BACKUP_CONFIGURATION_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for backup configuration evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'backup')

    # Normalize frequency
    frequency = normalize_backup_frequency(parsed_data.get('frequency', 'daily'))

    # Parse retention days
    retention_str = parsed_data.get('retention_days', '30')
    try:
        retention_days = int(retention_str)
    except ValueError:
        retention_days = 30  # Default

    # Parse last test date
    test_date_str = parsed_data.get('last_test_date', '')
    try:
        test_date = datetime.strptime(test_date_str, '%Y-%m-%d').date() if test_date_str else date.today()
    except:
        test_date = date.today()

    # Parse test result
    test_result_str = parsed_data.get('test_result', '').lower()
    if 'success' in test_result_str and 'partial' not in test_result_str:
        test_result = 'successful'
    elif 'partial' in test_result_str:
        test_result = 'partial_success'
    elif 'fail' in test_result_str:
        test_result = 'failed'
    else:
        test_result = 'not_tested'

    # Parse storage location
    location_str = parsed_data.get('storage_location', '').lower()
    if 'different_cloud' in location_str or 'multi-cloud' in location_str:
        storage_location = 'different_cloud'
    elif 'different_region' in location_str or 'separate region' in location_str:
        storage_location = 'different_region'
    elif 'same' in location_str:
        storage_location = 'same_region'
    elif 'hybrid' in location_str:
        storage_location = 'hybrid'
    else:
        storage_location = 'different_region'  # Safe default

    # Parse booleans
    encrypted_val = parsed_data.get('encrypted', 'unknown')
    encrypted_str = str(encrypted_val).lower() if encrypted_val else 'unknown'
    is_encrypted = encrypted_str in ['yes', 'true', 'enabled']

    automated_val = parsed_data.get('automated', 'yes')
    automated_str = str(automated_val).lower() if automated_val else 'yes'
    is_automated = automated_str in ['yes', 'true', 'enabled']

    monitoring_val = parsed_data.get('monitoring', 'no')
    monitoring_str = str(monitoring_val).lower() if monitoring_val else 'no'
    monitoring_enabled = monitoring_str in ['yes', 'true', 'enabled']

    return {
        'evidence_type': 'assure_006_backup_configuration',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'backup_frequency': frequency,
        'backup_schedule_description': parsed_data.get('schedule', None),
        'retention_period_days': retention_days,
        'last_test_date': test_date.isoformat(),
        'last_test_result': test_result,
        'test_frequency_days': 90,  # Assume quarterly
        'backup_scope': parsed_data.get('scope', 'Customer data'),
        'storage_location': storage_location,
        'is_encrypted': is_encrypted,
        'is_automated': is_automated,
        'monitoring_enabled': monitoring_enabled,
    }


def text_to_access_reviews(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Access Reviews evidence from ANY text source using XML format.

    Args:
        text: Raw text containing access review information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for AccessReviewsEvidence.model_validate()
    """
    from conduit.training_examples import ACCESS_REVIEWS_EXAMPLES

    prompt = f"""{ACCESS_REVIEWS_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for access reviews evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'access_review')

    # Parse last review date
    review_date_str = parsed_data.get('last_review_date', '')
    try:
        review_date = datetime.strptime(review_date_str, '%Y-%m-%d').date() if review_date_str else date.today()
    except:
        review_date = date.today()

    # Normalize frequency
    frequency = normalize_review_frequency(parsed_data.get('frequency', 'quarterly'))

    # Parse scope
    scope_str = parsed_data.get('scope', '').lower()
    if 'all' in scope_str and 'system' in scope_str:
        scope = 'all_users_all_systems'
    elif 'privileged' in scope_str or 'admin' in scope_str:
        scope = 'privileged_access_only'
    elif 'production' in scope_str:
        scope = 'production_systems_only'
    elif 'high' in scope_str and 'risk' in scope_str:
        scope = 'high_risk_systems'
    else:
        scope = 'custom'

    # Parse systems list
    systems_str = parsed_data.get('systems', 'production systems')
    systems_in_scope = [s.strip() for s in systems_str.split(',')]

    # Parse counts
    try:
        users_reviewed = int(parsed_data.get('users_reviewed', '0'))
    except ValueError:
        users_reviewed = 0

    try:
        privileged_reviewed = int(parsed_data.get('privileged_users_reviewed', '0'))
    except ValueError:
        privileged_reviewed = None

    try:
        access_revoked = int(parsed_data.get('access_revoked', '0'))
    except ValueError:
        access_revoked = 0

    try:
        access_reduced = int(parsed_data.get('access_reduced', '0'))
    except ValueError:
        access_reduced = 0

    # Parse booleans
    approved_val = parsed_data.get('management_approved', 'unknown')
    approved_str = str(approved_val).lower() if approved_val else 'unknown'
    management_approved = approved_str in ['yes', 'true', 'approved']

    automated_val = parsed_data.get('automated_tools', 'no')
    automated_str = str(automated_val).lower() if automated_val else 'no'
    automated_tools_used = automated_str in ['yes', 'true', 'enabled']

    # Parse remediation deadline
    try:
        remediation_days = int(parsed_data.get('remediation_deadline_days', '7'))
    except ValueError:
        remediation_days = 7  # Default

    return {
        'evidence_type': 'assure_008_access_reviews',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'last_review_date': review_date.isoformat(),
        'review_frequency': frequency,
        'next_scheduled_review': None,
        'review_scope': scope,
        'systems_in_scope': systems_in_scope,
        'scope_description': None,
        'total_users_reviewed': users_reviewed,
        'privileged_users_reviewed': privileged_reviewed,
        'access_revoked_count': access_revoked,
        'access_reduced_count': access_reduced,
        'management_approved': management_approved,
        'remediation_deadline_days': remediation_days,
        'automated_review_tools_used': automated_tools_used,
    }


def text_to_security_alerts(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Security Alerts Configuration evidence from ANY text source using XML format.

    Args:
        text: Raw text containing security alerts information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for SecurityAlertsEvidence.model_validate()
    """
    from conduit.training_examples import SECURITY_ALERTS_EXAMPLES

    prompt = f"""{SECURITY_ALERTS_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for security alerts evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=3000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'security_alerts')

    # Parse alert configurations
    alerts_data = parsed_data.get('alerts', [])
    alert_configurations = []

    for alert in alerts_data:
        # Parse alert type
        alert_type_str = alert.get('type', '').lower()
        alert_type = alert_type_str.replace(' ', '_')

        # Parse enabled status
        enabled_str = alert.get('enabled', 'yes').lower()
        is_enabled = enabled_str in ['yes', 'true', 'enabled']

        # Parse severity
        severity_str = alert.get('severity', 'medium').lower()
        severity = severity_str

        # Parse channels
        channels_str = alert.get('channels', 'email')
        channels_list = [ch.strip() for ch in channels_str.split(',')]

        # Parse SLA hours
        sla_str = alert.get('response_sla_hours', '')
        try:
            response_sla = float(sla_str) if sla_str and sla_str != 'unknown' else None
        except ValueError:
            response_sla = None

        alert_config = {
            'evidence_type': 'assure_015_security_alerts',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'alert_type': alert_type,
            'is_enabled': is_enabled,
            'severity': severity,
            'threshold_description': alert.get('threshold', None),
            'notification_channels': channels_list,
            'response_sla_hours': response_sla,
        }
        alert_configurations.append(alert_config)

    # Parse monitoring section
    monitoring_data = parsed_data.get('monitoring', {})

    coverage_str = monitoring_data.get('coverage', '24/7').lower()
    if '24' in coverage_str or '24/7' in coverage_str:
        monitoring_coverage = '24/7'
    elif 'business' in coverage_str:
        monitoring_coverage = 'business_hours'
    elif 'extended' in coverage_str:
        monitoring_coverage = 'extended_hours'
    elif 'weekday' in coverage_str:
        monitoring_coverage = 'weekdays_only'
    else:
        monitoring_coverage = '24/7'

    team_size_str = monitoring_data.get('team_size', '')
    try:
        team_size = int(team_size_str) if team_size_str and team_size_str != 'unknown' else None
    except ValueError:
        team_size = None

    incident_plan_str = monitoring_data.get('incident_response_plan', 'unknown').lower()
    incident_response_plan_exists = incident_plan_str in ['yes', 'true', 'exists']

    escalation_str = monitoring_data.get('escalation_defined', 'unknown').lower()
    escalation_process_defined = escalation_str in ['yes', 'true', 'defined']

    siem_str = monitoring_data.get('siem_integrated', 'no').lower()
    integrated_with_siem = siem_str in ['yes', 'true', 'enabled']

    siem_platform = monitoring_data.get('siem_platform', None)

    return {
        'evidence_type': 'assure_015_security_alerts',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'alert_configurations': alert_configurations,
        'monitoring_coverage': monitoring_coverage,
        'monitoring_team_size': team_size,
        'incident_response_plan_exists': incident_response_plan_exists,
        'escalation_process_defined': escalation_process_defined,
        'false_positive_rate_acceptable': True,  # Assume acceptable
        'alert_tuning_frequency': None,
        'integrated_with_siem': integrated_with_siem,
        'siem_platform': siem_platform,
    }


def text_to_data_mapping(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Data Mapping & Subprocessors evidence from ANY text source using XML format.

    Args:
        text: Raw text containing data mapping information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for DataMappingEvidence.model_validate()
    """
    from conduit.training_examples import DATA_MAPPING_EXAMPLES

    prompt = f"""{DATA_MAPPING_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for data mapping evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=4000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'data_mapping')

    # Parse attestation section
    attestation = parsed_data.get('attestation', {})

    last_updated_str = attestation.get('last_updated', '')
    try:
        last_updated = datetime.strptime(last_updated_str, '%Y-%m-%d').date() if last_updated_str and last_updated_str != 'unknown' else date.today()
    except:
        last_updated = date.today()

    doc_exists_str = attestation.get('document_exists', 'yes').lower()
    document_exists = doc_exists_str in ['yes', 'true', 'exists']

    legal_reviewed_str = attestation.get('legal_reviewed', 'no').lower()
    legal_reviewed = legal_reviewed_str in ['yes', 'true', 'reviewed']

    gdpr_str = attestation.get('gdpr_article_28', 'no').lower()
    gdpr_compliant = gdpr_str in ['yes', 'true', 'compliant']

    dsr_str = attestation.get('data_subject_rights', 'yes').lower()
    data_subject_rights = dsr_str in ['yes', 'true', 'supported']

    # Parse data flows
    flows_data = parsed_data.get('data_flows', [])
    data_flows = []

    for flow in flows_data:
        retention_str = flow.get('retention_days', '')
        try:
            retention_days = int(retention_str) if retention_str and retention_str != 'unknown' else None
        except ValueError:
            retention_days = None

        encrypted_rest_str = flow.get('encrypted_at_rest', 'unknown').lower()
        encrypted_rest = encrypted_rest_str in ['yes', 'true', 'encrypted']

        encrypted_transit_str = flow.get('encrypted_in_transit', 'unknown').lower()
        encrypted_transit = encrypted_transit_str in ['yes', 'true', 'encrypted']

        data_flow = {
            'evidence_type': 'assure_002_data_mapping',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'data_category': flow.get('category', 'customer_content'),
            'sensitivity': flow.get('sensitivity', 'sensitive'),
            'source_system': flow.get('source', 'application'),
            'storage_location': flow.get('storage', 'cloud storage'),
            'geographic_region': flow.get('region', 'us'),
            'retention_period_days': retention_days,
            'encrypted_at_rest': encrypted_rest,
            'encrypted_in_transit': encrypted_transit,
        }
        data_flows.append(data_flow)

    # Parse subprocessors
    subprocessors_data = parsed_data.get('subprocessors', [])
    subprocessors = []

    for sp in subprocessors_data:
        contract_str = sp.get('contract', 'unknown').lower()
        contract_in_place = contract_str in ['yes', 'true', 'executed']

        soc2_str = sp.get('soc2', 'unknown').lower()
        soc2_certified = soc2_str in ['yes', 'true', 'certified']

        # Parse data categories list
        categories_str = sp.get('data_categories', 'customer_content')
        data_categories = [cat.strip() for cat in categories_str.split(',')]

        subprocessor = {
            'evidence_type': 'assure_002_data_mapping',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'name': sp.get('name', 'Unknown'),
            'role': sp.get('role', 'cloud_infrastructure'),
            'data_categories': data_categories,
            'geographic_location': sp.get('location', 'us'),
            'contract_in_place': contract_in_place,
            'soc2_certified': soc2_certified,
            'url': sp.get('url', None),
        }
        subprocessors.append(subprocessor)

    # Parse SBOM section
    sbom_data = parsed_data.get('sbom', {})

    sbom_available_str = sbom_data.get('available', 'no').lower()
    sbom_available = sbom_available_str in ['yes', 'true', 'available']

    sbom_format = sbom_data.get('format', None) if sbom_available else None

    sbom_last_updated_str = sbom_data.get('last_updated', '')
    try:
        sbom_last_updated = datetime.strptime(sbom_last_updated_str, '%Y-%m-%d').date() if sbom_last_updated_str and sbom_last_updated_str != 'unknown' else None
    except:
        sbom_last_updated = None

    return {
        'evidence_type': 'assure_002_data_mapping',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'data_mapping_last_updated': last_updated.isoformat(),
        'data_mapping_document_exists': document_exists,
        'data_mapping_reviewed_by_legal': legal_reviewed,
        'data_flows': data_flows,
        'subprocessors': subprocessors,
        'subprocessor_list_publicly_available': False,  # Assume not public
        'customer_notification_on_changes': False,  # Assume not notified
        'gdpr_article_28_compliance': gdpr_compliant,
        'data_subject_rights_supported': data_subject_rights,
        'sbom_available': sbom_available,
        'sbom_format': sbom_format,
        'sbom_last_updated': sbom_last_updated.isoformat() if sbom_last_updated else None,
    }


def text_to_architecture(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Architecture & Segmentation evidence from ANY text source using XML format.

    Args:
        text: Raw text containing architecture information
        vendor_name: Name of the vendor
        use_expensive_model: Use Sonnet (expensive) instead of Haiku (cheap)

    Returns:
        dict: Ready for ArchitectureEvidence.model_validate()
    """
    from conduit.training_examples import ARCHITECTURE_EXAMPLES

    prompt = f"""{ARCHITECTURE_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}

DOCUMENT TEXT:
{text}

Output the XML structure for architecture evidence as shown in examples."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=4000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    logger.debug(f"Raw Claude output:\n{raw_text}")

    parsed_data = parse_evidence_xml(raw_text, 'architecture')

    # Parse documentation section
    doc_data = parsed_data.get('documentation', {})

    diagram_available_str = doc_data.get('diagram_available', 'unknown').lower()
    diagram_available = diagram_available_str in ['yes', 'true', 'available']

    diagram_url = doc_data.get('diagram_url', None)
    last_updated = doc_data.get('last_updated', None)

    # Parse segmentation section
    seg_data = parsed_data.get('segmentation', {})

    segmentation_strategy = seg_data.get('strategy', 'vpc_based')
    segmentation_description = seg_data.get('description', 'Network segmentation in place')
    multi_tenancy_model = seg_data.get('multi_tenancy', 'shared_logical_isolation')

    tenant_tested_str = seg_data.get('tenant_isolation_tested', 'no').lower()
    tenant_isolation_tested = tenant_tested_str in ['yes', 'true', 'tested']

    # Parse infrastructure section
    infra_data = parsed_data.get('infrastructure', {})

    primary_cloud_provider = infra_data.get('provider', 'aws')

    ha_str = infra_data.get('high_availability', 'unknown').lower()
    high_availability_configured = ha_str in ['yes', 'true', 'enabled']

    dr_region = infra_data.get('dr_region', None)

    prod_sep_str = infra_data.get('prod_nonprod_separated', 'yes').lower()
    production_non_production_separated = prod_sep_str in ['yes', 'true', 'separated']

    jump_box_str = infra_data.get('jump_box_required', 'no').lower()
    jump_box_required_for_admin_access = jump_box_str in ['yes', 'true', 'required']

    ids_ips_str = infra_data.get('ids_ips_deployed', 'no').lower()
    network_ids_ips_deployed = ids_ips_str in ['yes', 'true', 'deployed']

    # Parse network segments
    segments_data = parsed_data.get('segments', [])
    network_segments = []

    for seg in segments_data:
        firewall_str = seg.get('firewall', 'yes').lower()
        firewall_rules_enforced = firewall_str in ['yes', 'true', 'enabled']

        default_deny_str = seg.get('default_deny', 'yes').lower()
        default_deny_policy = default_deny_str in ['yes', 'true', 'enabled']

        # Parse allowed sources/destinations as lists
        inbound_str = seg.get('inbound', '')
        allowed_inbound = [s.strip() for s in inbound_str.split(',')]

        outbound_str = seg.get('outbound', '')
        allowed_outbound = [s.strip() for s in outbound_str.split(',')]

        segment = {
            'evidence_type': 'assure_001_architecture',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'segment_name': seg.get('name', 'Network Segment'),
            'security_zone': seg.get('zone', 'application_tier'),
            'allowed_inbound_sources': allowed_inbound,
            'allowed_outbound_destinations': allowed_outbound,
            'firewall_rules_enforced': firewall_rules_enforced,
            'default_deny_policy': default_deny_policy,
        }
        network_segments.append(segment)

    # Parse infrastructure components
    components_data = parsed_data.get('components', [])
    infrastructure_components = []

    for comp in components_data:
        public_str = comp.get('publicly_accessible', 'no').lower()
        publicly_accessible = public_str in ['yes', 'true', 'public']

        customer_data_str = comp.get('has_customer_data', 'no').lower()
        has_customer_data = customer_data_str in ['yes', 'true', 'contains']

        component = {
            'evidence_type': 'assure_001_architecture',
            'vendor_name': vendor_name,
            'evidence_date': date.today().isoformat(),
            'extraction_confidence': 0.85 if use_expensive_model else 0.80,
            'component_name': comp.get('name', 'Component'),
            'component_type': comp.get('type', 'server'),
            'security_zone': comp.get('zone', 'application_tier'),
            'publicly_accessible': publicly_accessible,
            'data_classification': comp.get('data_classification', 'internal'),
            'has_customer_data': has_customer_data,
        }
        infrastructure_components.append(component)

    return {
        'evidence_type': 'assure_001_architecture',
        'vendor_name': vendor_name,
        'evidence_date': date.today().isoformat(),
        'extraction_confidence': 0.85 if use_expensive_model else 0.80,
        'architecture_diagram_available': diagram_available,
        'architecture_diagram_url': diagram_url,
        'architecture_last_updated': last_updated,
        'segmentation_strategy': segmentation_strategy,
        'segmentation_description': segmentation_description,
        'multi_tenancy_model': multi_tenancy_model,
        'tenant_isolation_tested': tenant_isolation_tested,
        'primary_cloud_provider': primary_cloud_provider,
        'high_availability_configured': high_availability_configured,
        'disaster_recovery_region': dr_region,
        'network_segments': network_segments,
        'infrastructure_components': infrastructure_components,
        'production_non_production_separated': production_non_production_separated,
        'jump_box_required_for_admin_access': jump_box_required_for_admin_access,
        'network_ids_ips_deployed': network_ids_ips_deployed,
    }


# =============================================================================
# BATCH 3: TECHNICAL ACCESS & CHANGE CONTROLS (6 evidence types)
# =============================================================================

def text_to_admin_2fa(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Admin 2FA evidence from text using Claude.

    Args:
        text: Source text (SOC 2, security docs, emails, trust center)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching Admin2FAEvidence Pydantic schema
    """
    from conduit.training_examples import ADMIN_2FA_EXAMPLES

    prompt = f"""{ADMIN_2FA_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for admin 2FA evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'admin_2fa')

    # Parse boolean fields
    mfa_enforced_val = parsed_data.get('mfa_enforced', 'no')
    mfa_enforced_str = str(mfa_enforced_val).lower() if mfa_enforced_val else 'no'
    mfa_enforced = mfa_enforced_str in ['yes', 'true', 'enabled', 'required', 'mandatory']

    phishing_resistant_val = parsed_data.get('phishing_resistant', 'no')
    phishing_resistant_str = str(phishing_resistant_val).lower() if phishing_resistant_val else 'no'
    phishing_resistant = phishing_resistant_str in ['yes', 'true', 'enabled']

    technically_enforced_val = parsed_data.get('technically_enforced', 'unknown')
    technically_enforced_str = str(technically_enforced_val).lower() if technically_enforced_val else 'unknown'
    technically_enforced = technically_enforced_str in ['yes', 'true', 'enabled']

    exceptions_allowed_val = parsed_data.get('exceptions_allowed', 'no')
    exceptions_allowed_str = str(exceptions_allowed_val).lower() if exceptions_allowed_val else 'no'
    exceptions_allowed = exceptions_allowed_str in ['yes', 'true']

    exceptions_documented_val = parsed_data.get('exceptions_documented', 'no')
    exceptions_documented_str = str(exceptions_documented_val).lower() if exceptions_documented_val else 'no'
    exceptions_documented = exceptions_documented_str in ['yes', 'true']

    # Parse MFA types (can be comma-separated list)
    mfa_types_str = parsed_data.get('mfa_types', 'authenticator_app')
    raw_mfa_types = [t.strip() for t in mfa_types_str.split(',')]

    # Normalize MFA types to match enum
    mfa_type_mapping = {
        'two_factor_authentication': 'authenticator_app',
        '2fa': 'authenticator_app',
        'mfa': 'authenticator_app',
        'totp': 'authenticator_app',
        'authenticator': 'authenticator_app',
        'google_authenticator': 'authenticator_app',
        'microsoft_authenticator': 'authenticator_app',
        'okta_verify': 'push_notification',
        'duo': 'push_notification',
        'push': 'push_notification',
        'text_message': 'sms',
        'sms_code': 'sms',
        'phone': 'sms',
        'yubikey': 'hardware_token',
        'security_key': 'hardware_token',
        'fido2': 'hardware_token',
        'webauthn': 'hardware_token',
        'u2f': 'hardware_token',
        'fingerprint': 'biometric',
        'face_recognition': 'biometric',
        'touchid': 'biometric',
        'faceid': 'biometric',
        'certificate': 'certificate_based',
        'pki': 'certificate_based',
    }

    mfa_types = []
    for raw_type in raw_mfa_types:
        normalized = raw_type.lower().replace(' ', '_').replace('-', '_')
        mapped_type = mfa_type_mapping.get(normalized, normalized)

        # Validate against allowed types
        allowed_types = ['authenticator_app', 'sms', 'email', 'hardware_token',
                        'push_notification', 'biometric', 'certificate_based']
        if mapped_type in allowed_types:
            mfa_types.append(mapped_type)
        else:
            # Default to authenticator_app if unknown
            mfa_types.append('authenticator_app')

    if not mfa_types:
        mfa_types = ['authenticator_app']

    # Parse scope
    scope = parsed_data.get('scope', 'custom').strip().lower().replace(' ', '_')
    if scope not in ['all_admins', 'production_admins_only', 'infrastructure_admins', 'application_admins', 'custom']:
        scope = 'custom'

    # Parse optional integer fields
    exception_count_str = parsed_data.get('exception_count', 'unknown')
    exception_count = None
    if exception_count_str not in ['unknown', 'none', None]:
        try:
            exception_count = int(exception_count_str)
        except (ValueError, TypeError):
            exception_count = None

    total_admin_accounts_str = parsed_data.get('total_admin_accounts', 'unknown')
    total_admin_accounts = None
    if total_admin_accounts_str not in ['unknown', 'none', None]:
        try:
            total_admin_accounts = int(total_admin_accounts_str)
        except (ValueError, TypeError):
            total_admin_accounts = None

    admin_accounts_with_mfa_str = parsed_data.get('admin_accounts_with_mfa', 'unknown')
    admin_accounts_with_mfa = None
    if admin_accounts_with_mfa_str not in ['unknown', 'none', None]:
        try:
            admin_accounts_with_mfa = int(admin_accounts_with_mfa_str)
        except (ValueError, TypeError):
            admin_accounts_with_mfa = None

    # Parse optional string fields
    scope_description = parsed_data.get('scope_description', None)
    if scope_description and scope_description.lower() in ['unknown', 'none', 'n/a']:
        scope_description = None

    enforcement_mechanism = parsed_data.get('enforcement_mechanism', None)
    if enforcement_mechanism and enforcement_mechanism.lower() in ['unknown', 'none', 'n/a']:
        enforcement_mechanism = None

    review_frequency = parsed_data.get('review_frequency', None)
    if review_frequency and review_frequency.lower() in ['unknown', 'none', 'n/a']:
        review_frequency = None

    last_review = parsed_data.get('last_review', None)
    if last_review and last_review.lower() in ['unknown', 'none', 'n/a']:
        last_review = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_011_admin_2fa',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'mfa_enforced_for_admin': mfa_enforced,
        'admin_account_scope': scope,
        'scope_description': scope_description,
        'mfa_types_supported': mfa_types,
        'phishing_resistant_mfa_available': phishing_resistant,
        'technically_enforced': technically_enforced,
        'enforcement_mechanism': enforcement_mechanism,
        'exceptions_allowed': exceptions_allowed,
        'exceptions_documented': exceptions_documented,
        'exception_count': exception_count,
        'admin_mfa_review_frequency': review_frequency,
        'last_mfa_review_date': last_review,
        'total_admin_accounts': total_admin_accounts,
        'admin_accounts_with_mfa': admin_accounts_with_mfa,
        'extraction_confidence': extraction_confidence,
    }


def text_to_code_review(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Code Review evidence from text using Claude.

    Args:
        text: Source text (SOC 2, development docs, GitHub policies)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching CodeReviewEvidence Pydantic schema
    """
    from conduit.training_examples import CODE_REVIEW_EXAMPLES

    prompt = f"""{CODE_REVIEW_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for code review evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'code_review')

    # Parse boolean fields
    peer_review_required_val = parsed_data.get('peer_review_required', 'no')
    peer_review_required_str = str(peer_review_required_val).lower() if peer_review_required_val else 'no'
    peer_review_required = peer_review_required_str in ['yes', 'true', 'enabled', 'required', 'mandatory']

    technically_enforced_val = parsed_data.get('technically_enforced', 'no')
    technically_enforced_str = str(technically_enforced_val).lower() if technically_enforced_val else 'no'
    technically_enforced = technically_enforced_str in ['yes', 'true', 'enabled']

    branch_protection_val = parsed_data.get('branch_protection', 'no')
    branch_protection_str = str(branch_protection_val).lower() if branch_protection_val else 'no'
    branch_protection = branch_protection_str in ['yes', 'true', 'enabled']

    security_checks_included_val = parsed_data.get('security_checks_included', 'no')
    security_checks_included_str = str(security_checks_included_val).lower() if security_checks_included_val else 'no'
    security_checks_included = security_checks_included_str in ['yes', 'true', 'enabled']

    automated_checks_block_merge_val = parsed_data.get('automated_checks_block_merge', 'no')
    automated_checks_block_merge_str = str(automated_checks_block_merge_val).lower() if automated_checks_block_merge_val else 'no'
    automated_checks_block_merge = automated_checks_block_merge_str in ['yes', 'true', 'enabled']

    # Parse review tool
    review_tool = parsed_data.get('review_tool', 'other').strip().lower().replace(' ', '_')
    if review_tool not in ['github', 'gitlab', 'bitbucket', 'azure_devops', 'gerrit', 'phabricator', 'informal_process', 'other']:
        review_tool = 'other'

    # Parse minimum reviewers
    minimum_reviewers_str = parsed_data.get('minimum_reviewers', 'unknown')
    minimum_reviewers = None
    if minimum_reviewers_str not in ['unknown', 'none', None]:
        try:
            minimum_reviewers = int(minimum_reviewers_str)
        except (ValueError, TypeError):
            minimum_reviewers = None

    # Parse security check types (comma-separated list) with normalization
    security_check_types_str = parsed_data.get('security_check_types', 'none')
    if security_check_types_str.lower() in ['none', 'unknown', 'n/a']:
        raw_security_checks = []
    else:
        raw_security_checks = [t.strip() for t in security_check_types_str.split(',')]

    # Normalize security check types
    security_check_mapping = {
        'sast': 'security_best_practices',
        'static_analysis': 'security_best_practices',
        'dependency_scanning': 'dependency_security',
        'dependency_checks': 'dependency_security',
        'vulnerabilities': 'dependency_security',
        'secret_scanning': 'sensitive_data',
        'secrets': 'sensitive_data',
        'hardcoded_credentials': 'sensitive_data',
        'manual_security_review': 'security_best_practices',
        'security_review': 'security_best_practices',
        'linting': 'security_best_practices',
        'unit_tests': 'security_best_practices',
    }

    security_check_types = []
    allowed_security_checks = ['input_validation', 'authentication', 'sensitive_data',
                              'sql_injection', 'xss', 'dependency_security', 'access_control',
                              'cryptography', 'error_handling', 'security_best_practices']

    for raw_check in raw_security_checks:
        normalized = raw_check.lower().replace(' ', '_').replace('-', '_')
        mapped_check = security_check_mapping.get(normalized, normalized)

        if mapped_check in allowed_security_checks:
            security_check_types.append(mapped_check)
        elif normalized in allowed_security_checks:
            security_check_types.append(normalized)

    # Parse reviewer qualifications (comma-separated list) with normalization
    reviewer_qualifications_str = parsed_data.get('reviewer_qualifications', 'any_team_member')
    raw_qualifications = [t.strip() for t in reviewer_qualifications_str.split(',')]

    # Normalize reviewer qualifications
    qualification_mapping = {
        'senior_engineer': 'senior_developer',
        'senior': 'senior_developer',
        'lead': 'team_lead',
        'lead_developer': 'team_lead',
        'tech_lead': 'team_lead',
        'security': 'security_engineer',
        'security_trained': 'security_trained',
        'developer': 'any_team_member',
        'any': 'any_team_member',
    }

    reviewer_qualifications = []
    allowed_qualifications = ['senior_developer', 'security_engineer', 'team_lead',
                             'architect', 'any_team_member', 'security_trained']

    for raw_qual in raw_qualifications:
        normalized = raw_qual.lower().replace(' ', '_').replace('-', '_')
        mapped_qual = qualification_mapping.get(normalized, normalized)

        if mapped_qual in allowed_qualifications:
            reviewer_qualifications.append(mapped_qual)
        elif normalized in allowed_qualifications:
            reviewer_qualifications.append(normalized)
        else:
            reviewer_qualifications.append('any_team_member')

    if not reviewer_qualifications:
        reviewer_qualifications = ['any_team_member']

    # Parse optional percentage fields
    review_coverage_percentage_str = parsed_data.get('review_coverage_percentage', 'unknown')
    review_coverage_percentage = None
    if review_coverage_percentage_str not in ['unknown', 'none', None]:
        try:
            review_coverage_percentage = float(review_coverage_percentage_str)
        except (ValueError, TypeError):
            review_coverage_percentage = None

    average_review_turnaround_hours_str = parsed_data.get('average_review_turnaround_hours', 'unknown')
    average_review_turnaround_hours = None
    if average_review_turnaround_hours_str not in ['unknown', 'none', None]:
        try:
            average_review_turnaround_hours = float(average_review_turnaround_hours_str)
        except (ValueError, TypeError):
            average_review_turnaround_hours = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_017_code_review',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'peer_review_required': peer_review_required,
        'review_tool': review_tool,
        'technically_enforced': technically_enforced,
        'branch_protection_enabled': branch_protection,
        'minimum_reviewers_required': minimum_reviewers,
        'security_checks_included': security_checks_included,
        'security_check_types': security_check_types,
        'reviewer_qualifications': reviewer_qualifications,
        'automated_checks_block_merge': automated_checks_block_merge,
        'review_bypass_allowed': not branch_protection,  # If branch protection enabled, bypass not allowed
        'review_coverage_percentage': review_coverage_percentage,
        'average_review_turnaround_hours': average_review_turnaround_hours,
        'extraction_confidence': extraction_confidence,
    }


def text_to_patch_management(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Patch Management evidence from text using Claude.

    Args:
        text: Source text (SOC 2, vulnerability reports, IT policies)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching PatchManagementEvidence Pydantic schema
    """
    from conduit.training_examples import PATCH_MANAGEMENT_EXAMPLES

    prompt = f"""{PATCH_MANAGEMENT_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for patch management evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'patch_management')

    # Parse boolean fields
    documented_process_val = parsed_data.get('documented_process', 'no')
    documented_process_str = str(documented_process_val).lower() if documented_process_val else 'no'
    documented_process = documented_process_str in ['yes', 'true', 'enabled']

    automated_patching_val = parsed_data.get('automated_patching', 'unknown')
    automated_patching_str = str(automated_patching_val).lower() if automated_patching_val else 'unknown'
    if automated_patching_str == 'unknown':
        automated_patching = None
    else:
        automated_patching = automated_patching_str in ['yes', 'true', 'enabled']

    patch_testing_environment_val = parsed_data.get('patch_testing_environment', 'unknown')
    patch_testing_environment_str = str(patch_testing_environment_val).lower() if patch_testing_environment_val else 'unknown'
    if patch_testing_environment_str == 'unknown':
        patch_testing_environment = None
    else:
        patch_testing_environment = patch_testing_environment_str in ['yes', 'true', 'enabled']

    monitoring_enabled_val = parsed_data.get('monitoring_enabled', 'unknown')
    monitoring_enabled_str = str(monitoring_enabled_val).lower() if monitoring_enabled_val else 'unknown'
    if monitoring_enabled_str == 'unknown':
        monitoring_enabled = None
    else:
        monitoring_enabled = monitoring_enabled_str in ['yes', 'true', 'enabled']

    # Parse patch frequency
    patch_frequency = parsed_data.get('patch_frequency', 'ad_hoc').strip().lower().replace(' ', '_').replace('-', '_')
    if patch_frequency not in ['continuous', 'weekly', 'monthly', 'quarterly', 'annually', 'ad_hoc']:
        patch_frequency = 'ad_hoc'

    # Parse SLA days
    critical_patch_sla_str = parsed_data.get('critical_patch_sla', 'unknown')
    critical_patch_sla = None
    if critical_patch_sla_str not in ['unknown', 'none', None]:
        try:
            critical_patch_sla = int(critical_patch_sla_str)
        except (ValueError, TypeError):
            critical_patch_sla = None

    high_patch_sla_str = parsed_data.get('high_patch_sla', 'unknown')
    high_patch_sla = None
    if high_patch_sla_str not in ['unknown', 'none', None]:
        try:
            high_patch_sla = int(high_patch_sla_str)
        except (ValueError, TypeError):
            high_patch_sla = None

    medium_patch_sla_str = parsed_data.get('medium_patch_sla', 'unknown')
    medium_patch_sla = None
    if medium_patch_sla_str not in ['unknown', 'none', None]:
        try:
            medium_patch_sla = int(medium_patch_sla_str)
        except (ValueError, TypeError):
            medium_patch_sla = None

    # Parse last patch date
    last_patch_date_str = parsed_data.get('last_patch_date', 'unknown')
    last_patch_date = None
    if last_patch_date_str not in ['unknown', 'none', None, 'n/a']:
        try:
            # Try parsing YYYY-MM-DD format
            last_patch_date = datetime.strptime(last_patch_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            last_patch_date = None

    # Parse optional string fields
    automated_tool = parsed_data.get('automated_tool', None)
    if automated_tool and automated_tool.lower() in ['unknown', 'none', 'n/a']:
        automated_tool = None

    monitoring_tool = parsed_data.get('monitoring_tool', None)
    if monitoring_tool and monitoring_tool.lower() in ['unknown', 'none', 'n/a']:
        monitoring_tool = None

    compliance_review_frequency = parsed_data.get('compliance_review_frequency', None)
    if compliance_review_frequency and compliance_review_frequency.lower() in ['unknown', 'none', 'n/a']:
        compliance_review_frequency = None

    # Parse patch success rate
    patch_success_rate_str = parsed_data.get('patch_success_rate', 'unknown')
    patch_success_rate = None
    if patch_success_rate_str not in ['unknown', 'none', None]:
        try:
            patch_success_rate = float(patch_success_rate_str)
        except (ValueError, TypeError):
            patch_success_rate = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_003_patch_management',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'patch_management_process_documented': documented_process,
        'patch_cadence': patch_frequency,
        'critical_patch_sla_days': critical_patch_sla,
        'last_patch_date': last_patch_date,
        'automated_patching_enabled': automated_patching if automated_patching is not None else False,
        'automated_patching_scope': automated_tool,
        'patch_testing_performed': patch_testing_environment if patch_testing_environment is not None else False,
        'patch_compliance_monitored': monitoring_enabled if monitoring_enabled is not None else False,
        'patch_monitoring_tool': monitoring_tool,
        'extraction_confidence': extraction_confidence,
    }


def text_to_security_testing(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Security Testing evidence from text using Claude.

    Args:
        text: Source text (SOC 2, DevSecOps docs, AppSec reports)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching SecurityTestingEvidence Pydantic schema
    """
    from conduit.training_examples import SECURITY_TESTING_EXAMPLES

    prompt = f"""{SECURITY_TESTING_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for security testing evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'security_testing')

    # Parse boolean fields
    sast_enabled_val = parsed_data.get('sast_enabled', 'no')
    sast_enabled_str = str(sast_enabled_val).lower() if sast_enabled_val else 'no'
    sast_enabled = sast_enabled_str in ['yes', 'true', 'enabled']

    dast_enabled_val = parsed_data.get('dast_enabled', 'no')
    dast_enabled_str = str(dast_enabled_val).lower() if dast_enabled_val else 'no'
    dast_enabled = dast_enabled_str in ['yes', 'true', 'enabled']

    sca_enabled_val = parsed_data.get('sca_enabled', 'no')
    sca_enabled_str = str(sca_enabled_val).lower() if sca_enabled_val else 'no'
    sca_enabled = sca_enabled_str in ['yes', 'true', 'enabled']

    container_scanning_enabled_val = parsed_data.get('container_scanning_enabled', 'unknown')
    container_scanning_enabled_str = str(container_scanning_enabled_val).lower() if container_scanning_enabled_val else 'unknown'
    if container_scanning_enabled_str == 'unknown':
        container_scanning_enabled = None
    else:
        container_scanning_enabled = container_scanning_enabled_str in ['yes', 'true', 'enabled']

    ci_cd_integrated_val = parsed_data.get('ci_cd_integrated', 'no')
    ci_cd_integrated_str = str(ci_cd_integrated_val).lower() if ci_cd_integrated_val else 'no'
    ci_cd_integrated = ci_cd_integrated_str in ['yes', 'true', 'enabled']

    automated_blocking_val = parsed_data.get('automated_blocking', 'no')
    automated_blocking_str = str(automated_blocking_val).lower() if automated_blocking_val else 'no'
    automated_blocking = automated_blocking_str in ['yes', 'true', 'enabled']

    # Parse tool lists (comma-separated)
    sast_tools_str = parsed_data.get('sast_tools', 'none')
    if sast_tools_str.lower() in ['none', 'unknown', 'n/a']:
        sast_tools = []
    else:
        sast_tools = [t.strip() for t in sast_tools_str.split(',')]

    dast_tools_str = parsed_data.get('dast_tools', 'none')
    if dast_tools_str.lower() in ['none', 'unknown', 'n/a']:
        dast_tools = []
    else:
        dast_tools = [t.strip() for t in dast_tools_str.split(',')]

    sca_tools_str = parsed_data.get('sca_tools', 'none')
    if sca_tools_str.lower() in ['none', 'unknown', 'n/a']:
        sca_tools = []
    else:
        sca_tools = [t.strip() for t in sca_tools_str.split(',')]

    container_scanning_tools_str = parsed_data.get('container_scanning_tools', 'unknown')
    if container_scanning_tools_str.lower() in ['none', 'unknown', 'n/a']:
        container_scanning_tools = []
    else:
        container_scanning_tools = [t.strip() for t in container_scanning_tools_str.split(',')]

    # Parse blocking severity threshold
    blocking_severity_threshold = parsed_data.get('blocking_severity_threshold', 'none').strip().lower()
    if blocking_severity_threshold not in ['critical', 'high', 'medium', 'low', 'none']:
        blocking_severity_threshold = 'none'

    # Parse coverage percentages
    sast_coverage_percentage_str = parsed_data.get('sast_coverage_percentage', 'unknown')
    sast_coverage_percentage = None
    if sast_coverage_percentage_str not in ['unknown', 'none', None]:
        try:
            sast_coverage_percentage = float(sast_coverage_percentage_str)
        except (ValueError, TypeError):
            sast_coverage_percentage = None

    dast_coverage_percentage_str = parsed_data.get('dast_coverage_percentage', 'unknown')
    dast_coverage_percentage = None
    if dast_coverage_percentage_str not in ['unknown', 'none', None]:
        try:
            dast_coverage_percentage = float(dast_coverage_percentage_str)
        except (ValueError, TypeError):
            dast_coverage_percentage = None

    sca_coverage_percentage_str = parsed_data.get('sca_coverage_percentage', 'unknown')
    sca_coverage_percentage = None
    if sca_coverage_percentage_str not in ['unknown', 'none', None]:
        try:
            sca_coverage_percentage = float(sca_coverage_percentage_str)
        except (ValueError, TypeError):
            sca_coverage_percentage = None

    # Parse remediation SLAs
    critical_remediation_sla_days_str = parsed_data.get('critical_remediation_sla_days', 'unknown')
    critical_remediation_sla_days = None
    if critical_remediation_sla_days_str not in ['unknown', 'none', None]:
        try:
            critical_remediation_sla_days = int(critical_remediation_sla_days_str)
        except (ValueError, TypeError):
            critical_remediation_sla_days = None

    high_remediation_sla_days_str = parsed_data.get('high_remediation_sla_days', 'unknown')
    high_remediation_sla_days = None
    if high_remediation_sla_days_str not in ['unknown', 'none', None]:
        try:
            high_remediation_sla_days = int(high_remediation_sla_days_str)
        except (ValueError, TypeError):
            high_remediation_sla_days = None

    medium_remediation_sla_days_str = parsed_data.get('medium_remediation_sla_days', 'unknown')
    medium_remediation_sla_days = None
    if medium_remediation_sla_days_str not in ['unknown', 'none', None]:
        try:
            medium_remediation_sla_days = int(medium_remediation_sla_days_str)
        except (ValueError, TypeError):
            medium_remediation_sla_days = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_018_security_testing',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'sast_enabled': sast_enabled,
        'sast_tools': sast_tools,
        'dast_enabled': dast_enabled,
        'dast_tools': dast_tools,
        'sca_enabled': sca_enabled,
        'sca_tools': sca_tools,
        'container_scanning_enabled': container_scanning_enabled,
        'container_scanning_tools': container_scanning_tools,
        'ci_cd_integrated': ci_cd_integrated,
        'automated_blocking_enabled': automated_blocking,
        'blocking_severity_threshold': blocking_severity_threshold,
        'sast_coverage_percentage': sast_coverage_percentage,
        'dast_coverage_percentage': dast_coverage_percentage,
        'sca_coverage_percentage': sca_coverage_percentage,
        'critical_remediation_sla_days': critical_remediation_sla_days,
        'high_remediation_sla_days': high_remediation_sla_days,
        'medium_remediation_sla_days': medium_remediation_sla_days,
        'extraction_confidence': extraction_confidence,
    }


def text_to_network_acls(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Network ACL evidence from text using Claude.

    Args:
        text: Source text (SOC 2, network policies, infrastructure docs)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching NetworkACLEvidence Pydantic schema
    """
    from conduit.training_examples import NETWORK_ACL_EXAMPLES

    prompt = f"""{NETWORK_ACL_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for network ACL evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'network_acl')

    # Parse boolean fields (can be yes/no/unknown)
    default_deny_policy_val = parsed_data.get('default_deny_policy', 'unknown')
    default_deny_policy_str = str(default_deny_policy_val).lower() if default_deny_policy_val else 'unknown'
    if default_deny_policy_str == 'unknown':
        default_deny_policy = None
    else:
        default_deny_policy = default_deny_policy_str in ['yes', 'true', 'enabled']

    network_segmentation_val = parsed_data.get('network_segmentation', 'unknown')
    network_segmentation_str = str(network_segmentation_val).lower() if network_segmentation_val else 'unknown'
    if network_segmentation_str == 'unknown':
        network_segmentation = None
    else:
        network_segmentation = network_segmentation_str in ['yes', 'true', 'enabled']

    rules_documented_val = parsed_data.get('rules_documented', 'unknown')
    rules_documented_str = str(rules_documented_val).lower() if rules_documented_val else 'unknown'
    if rules_documented_str == 'unknown':
        rules_documented = None
    else:
        rules_documented = rules_documented_str in ['yes', 'true', 'enabled']

    change_approval_required_val = parsed_data.get('change_approval_required', 'unknown')
    change_approval_required_str = str(change_approval_required_val).lower() if change_approval_required_val else 'unknown'
    if change_approval_required_str == 'unknown':
        change_approval_required = None
    else:
        change_approval_required = change_approval_required_str in ['yes', 'true', 'enabled']

    automated_monitoring_val = parsed_data.get('automated_monitoring', 'unknown')
    automated_monitoring_str = str(automated_monitoring_val).lower() if automated_monitoring_val else 'unknown'
    if automated_monitoring_str == 'unknown':
        automated_monitoring = None
    else:
        automated_monitoring = automated_monitoring_str in ['yes', 'true', 'enabled']

    # Parse segmentation method
    segmentation_method = parsed_data.get('segmentation_method', 'unknown').strip().lower().replace(' ', '_').replace('-', '_')
    if segmentation_method not in ['vpc_based', 'vlan_based', 'subnet_based', 'firewall_zones', 'zero_trust', 'unknown']:
        segmentation_method = 'unknown'

    # Parse ACL tool
    acl_tool = parsed_data.get('acl_tool', None)
    if acl_tool and acl_tool.lower() in ['unknown', 'none', 'n/a']:
        acl_tool = None

    # Parse optional string fields
    documentation_location = parsed_data.get('documentation_location', None)
    if documentation_location and documentation_location.lower() in ['unknown', 'none', 'n/a']:
        documentation_location = None

    approval_authority = parsed_data.get('approval_authority', None)
    if approval_authority and approval_authority.lower() in ['unknown', 'none', 'n/a']:
        approval_authority = None

    # Parse review frequency (note: model uses 'semi_annual' not 'semi_annually')
    review_frequency = parsed_data.get('review_frequency', 'annual').strip().lower().replace(' ', '_').replace('-', '_')
    if review_frequency == 'semi_annually':
        review_frequency = 'semi_annual'
    if review_frequency not in ['monthly', 'quarterly', 'semi_annual', 'annual']:
        review_frequency = 'annual'

    # Parse last review date
    last_review_date_str = parsed_data.get('last_review_date', 'unknown')
    last_review_date = None
    if last_review_date_str not in ['unknown', 'none', None, 'n/a']:
        try:
            # Try parsing YYYY-MM-DD format
            last_review_date = datetime.strptime(last_review_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            last_review_date = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_010_network_acls',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'default_deny_policy': default_deny_policy if default_deny_policy is not None else False,
        'network_segmentation_implemented': network_segmentation if network_segmentation is not None else False,
        'acl_review_frequency': review_frequency,
        'last_acl_review_date': str(last_review_date) if last_review_date else None,
        'acl_changes_require_approval': change_approval_required if change_approval_required is not None else False,
        'acl_changes_logged': automated_monitoring if automated_monitoring is not None else False,
        'acl_management_tool': acl_tool,
        'extraction_confidence': extraction_confidence,
    }


def text_to_change_management(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Change Management evidence from text using Claude.

    Args:
        text: Source text (SOC 2, ITIL docs, change policies)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching ChangeManagementEvidence Pydantic schema
    """
    from conduit.training_examples import CHANGE_MANAGEMENT_EXAMPLES

    prompt = f"""{CHANGE_MANAGEMENT_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for change management evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'change_management')

    # Parse boolean fields
    documented_process_val = parsed_data.get('documented_process', 'no')
    documented_process_str = str(documented_process_val).lower() if documented_process_val else 'no'
    documented_process = documented_process_str in ['yes', 'true', 'enabled']

    approval_required_val = parsed_data.get('approval_required', 'no')
    approval_required_str = str(approval_required_val).lower() if approval_required_val else 'no'
    approval_required = approval_required_str in ['yes', 'true', 'enabled']

    testing_required_val = parsed_data.get('testing_required', 'unknown')
    testing_required_str = str(testing_required_val).lower() if testing_required_val else 'unknown'
    if testing_required_str == 'unknown':
        testing_required = None
    else:
        testing_required = testing_required_str in ['yes', 'true', 'enabled']

    rollback_plan_required_val = parsed_data.get('rollback_plan_required', 'unknown')
    rollback_plan_required_str = str(rollback_plan_required_val).lower() if rollback_plan_required_val else 'unknown'
    if rollback_plan_required_str == 'unknown':
        rollback_plan_required = None
    else:
        rollback_plan_required = rollback_plan_required_str in ['yes', 'true', 'enabled']

    change_logging_enabled_val = parsed_data.get('change_logging_enabled', 'no')
    change_logging_enabled_str = str(change_logging_enabled_val).lower() if change_logging_enabled_val else 'no'
    change_logging_enabled = change_logging_enabled_str in ['yes', 'true', 'enabled']

    post_implementation_review_val = parsed_data.get('post_implementation_review', 'no')
    post_implementation_review_str = str(post_implementation_review_val).lower() if post_implementation_review_val else 'no'
    post_implementation_review = post_implementation_review_str in ['yes', 'true', 'enabled']

    emergency_change_process_val = parsed_data.get('emergency_change_process', 'unknown')
    emergency_change_process_str = str(emergency_change_process_val).lower() if emergency_change_process_val else 'unknown'
    if emergency_change_process_str == 'unknown':
        emergency_change_process = None
    else:
        emergency_change_process = emergency_change_process_str in ['yes', 'true', 'enabled']

    # Parse change categories (comma-separated list)
    change_categories_str = parsed_data.get('change_categories', 'standard')
    change_categories = [t.strip() for t in change_categories_str.split(',')]

    # Parse optional string fields
    approval_authority = parsed_data.get('approval_authority', None)
    if approval_authority and approval_authority.lower() in ['unknown', 'none', 'n/a']:
        approval_authority = None

    testing_environment = parsed_data.get('testing_environment', None)
    if testing_environment and testing_environment.lower() in ['unknown', 'none', 'n/a']:
        testing_environment = None

    change_logging_tool = parsed_data.get('change_logging_tool', None)
    if change_logging_tool and change_logging_tool.lower() in ['unknown', 'none', 'n/a']:
        change_logging_tool = None

    cab_meeting_frequency = parsed_data.get('cab_meeting_frequency', None)
    if cab_meeting_frequency and cab_meeting_frequency.lower() in ['unknown', 'none', 'n/a']:
        cab_meeting_frequency = None

    # Parse change success rate
    change_success_rate_percentage_str = parsed_data.get('change_success_rate_percentage', 'unknown')
    change_success_rate_percentage = None
    if change_success_rate_percentage_str not in ['unknown', 'none', None]:
        try:
            change_success_rate_percentage = float(change_success_rate_percentage_str)
        except (ValueError, TypeError):
            change_success_rate_percentage = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_016_change_management',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'documented_change_process': documented_process,
        'change_categories': change_categories,
        'change_approval_required': approval_required,
        'approval_authority': approval_authority,
        'change_testing_required': testing_required,
        'testing_environment': testing_environment,
        'rollback_plan_required': rollback_plan_required,
        'change_logging_enabled': change_logging_enabled,
        'change_logging_tool': change_logging_tool,
        'post_implementation_review_required': post_implementation_review,
        'emergency_change_process_exists': emergency_change_process,
        'change_success_rate_percentage': change_success_rate_percentage,
        'cab_meeting_frequency': cab_meeting_frequency,
        'extraction_confidence': extraction_confidence,
    }


# =============================================================================
# BATCH 4: CONTRACTS & INFRASTRUCTURE (4 evidence types)
# =============================================================================

def text_to_sla(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Service Level Agreement (SLA) evidence from text using Claude.

    Args:
        text: Source text (contracts, MSAs, SLAs, trust centers)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching ServiceLevelAgreementEvidence Pydantic schema
    """
    from conduit.training_examples import SLA_EXAMPLES

    prompt = f"""{SLA_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for SLA evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'sla')

    # Parse boolean fields
    sla_documented_val = parsed_data.get('sla_documented', 'no')
    sla_documented_str = str(sla_documented_val).lower() if sla_documented_val else 'no'
    sla_documented = sla_documented_str in ['yes', 'true', 'enabled']

    availability_sla_exists_val = parsed_data.get('availability_sla_exists', 'no')
    availability_sla_exists_str = str(availability_sla_exists_val).lower() if availability_sla_exists_val else 'no'
    availability_sla_exists = availability_sla_exists_str in ['yes', 'true', 'enabled']

    response_time_sla_exists_val = parsed_data.get('response_time_sla_exists', 'no')
    response_time_sla_exists_str = str(response_time_sla_exists_val).lower() if response_time_sla_exists_val else 'no'
    response_time_sla_exists = response_time_sla_exists_str in ['yes', 'true', 'enabled']

    resolution_time_sla_exists_val = parsed_data.get('resolution_time_sla_exists', 'no')
    resolution_time_sla_exists_str = str(resolution_time_sla_exists_val).lower() if resolution_time_sla_exists_val else 'no'
    resolution_time_sla_exists = resolution_time_sla_exists_str in ['yes', 'true', 'enabled']

    violation_remedies_defined_val = parsed_data.get('violation_remedies_defined', 'no')
    violation_remedies_defined_str = str(violation_remedies_defined_val).lower() if violation_remedies_defined_val else 'no'
    violation_remedies_defined = violation_remedies_defined_str in ['yes', 'true', 'enabled']

    service_credits_available_val = parsed_data.get('service_credits_available', 'no')
    service_credits_available_str = str(service_credits_available_val).lower() if service_credits_available_val else 'no'
    service_credits_available = service_credits_available_str in ['yes', 'true', 'enabled']

    sla_performance_monitored_val = parsed_data.get('sla_performance_monitored', 'no')
    sla_performance_monitored_str = str(sla_performance_monitored_val).lower() if sla_performance_monitored_val else 'no'
    sla_performance_monitored = sla_performance_monitored_str in ['yes', 'true', 'enabled']

    public_status_page_val = parsed_data.get('public_status_page', 'no')
    public_status_page_str = str(public_status_page_val).lower() if public_status_page_val else 'no'
    public_status_page = public_status_page_str in ['yes', 'true', 'enabled']

    sla_covers_critical_services_val = parsed_data.get('sla_covers_critical_services', 'yes')
    sla_covers_critical_services_str = str(sla_covers_critical_services_val).lower() if sla_covers_critical_services_val else 'yes'
    sla_covers_critical_services = sla_covers_critical_services_str in ['yes', 'true', 'enabled']

    # Parse availability percentage
    availability_percentage_str = parsed_data.get('availability_percentage', 'unknown')
    availability_percentage = None
    if availability_percentage_str not in ['unknown', 'none', None]:
        try:
            availability_percentage = float(availability_percentage_str)
        except (ValueError, TypeError):
            availability_percentage = None

    # Parse response/resolution times
    critical_incident_response_hours_str = parsed_data.get('critical_incident_response_hours', 'unknown')
    critical_incident_response_hours = None
    if critical_incident_response_hours_str not in ['unknown', 'none', None]:
        try:
            critical_incident_response_hours = int(critical_incident_response_hours_str)
        except (ValueError, TypeError):
            critical_incident_response_hours = None

    high_incident_response_hours_str = parsed_data.get('high_incident_response_hours', 'unknown')
    high_incident_response_hours = None
    if high_incident_response_hours_str not in ['unknown', 'none', None]:
        try:
            high_incident_response_hours = int(high_incident_response_hours_str)
        except (ValueError, TypeError):
            high_incident_response_hours = None

    critical_incident_resolution_hours_str = parsed_data.get('critical_incident_resolution_hours', 'unknown')
    critical_incident_resolution_hours = None
    if critical_incident_resolution_hours_str not in ['unknown', 'none', None]:
        try:
            critical_incident_resolution_hours = int(critical_incident_resolution_hours_str)
        except (ValueError, TypeError):
            critical_incident_resolution_hours = None

    # Parse service credit percentage
    service_credit_percentage_str = parsed_data.get('service_credit_percentage', 'unknown')
    service_credit_percentage = None
    if service_credit_percentage_str not in ['unknown', 'none', None]:
        try:
            service_credit_percentage = float(service_credit_percentage_str)
        except (ValueError, TypeError):
            service_credit_percentage = None

    # Parse violation remedy type
    violation_remedy_type_str = parsed_data.get('violation_remedy_type', 'no_remedy')
    violation_remedy_type = violation_remedy_type_str.strip().lower().replace(' ', '_').replace('-', '_')
    if violation_remedy_type not in ['service_credits', 'refund', 'contract_termination', 'no_remedy', 'other']:
        violation_remedy_type = 'no_remedy'

    # Parse optional string fields
    sla_location = parsed_data.get('sla_location', None)
    if sla_location and sla_location.lower() in ['unknown', 'none', 'n/a']:
        sla_location = None

    availability_measurement_period = parsed_data.get('availability_measurement_period', None)
    if availability_measurement_period and availability_measurement_period.lower() in ['unknown', 'none', 'n/a']:
        availability_measurement_period = None

    sla_reporting_frequency_raw = parsed_data.get('sla_reporting_frequency', None)
    sla_reporting_frequency = None  # Default to None
    if sla_reporting_frequency_raw is not None:
        sla_reporting_frequency_str = str(sla_reporting_frequency_raw).strip().lower()
        if sla_reporting_frequency_str not in ['unknown', 'none', 'n/a', 'null', 'not specified', '']:
            sla_reporting_frequency = sla_reporting_frequency_str  # Keep the lowercase string

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_019_sla',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'sla_documented': sla_documented,
        'sla_location': sla_location,
        'availability_sla_exists': availability_sla_exists,
        'availability_percentage': availability_percentage,
        'availability_measurement_period': availability_measurement_period,
        'response_time_sla_exists': response_time_sla_exists,
        'critical_incident_response_hours': critical_incident_response_hours,
        'high_incident_response_hours': high_incident_response_hours,
        'resolution_time_sla_exists': resolution_time_sla_exists,
        'critical_incident_resolution_hours': critical_incident_resolution_hours,
        'violation_remedies_defined': violation_remedies_defined,
        'violation_remedy_type': violation_remedy_type,
        'service_credits_available': service_credits_available,
        'service_credit_percentage': service_credit_percentage,
        'sla_performance_monitored': sla_performance_monitored,
        'sla_reporting_frequency': sla_reporting_frequency,
        'public_status_page': public_status_page,
        'sla_covers_critical_services': sla_covers_critical_services,
        'extraction_confidence': extraction_confidence,
    }


def text_to_data_retention(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Data Retention & Deletion evidence from text using Claude.

    Args:
        text: Source text (privacy policies, DPAs, SOC 2, contracts)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching DataRetentionEvidence Pydantic schema
    """
    from conduit.training_examples import DATA_RETENTION_EXAMPLES

    prompt = f"""{DATA_RETENTION_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for data retention evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'data_retention')

    # Parse boolean fields
    retention_policy_documented_val = parsed_data.get('retention_policy_documented', 'no')
    retention_policy_documented_str = str(retention_policy_documented_val).lower() if retention_policy_documented_val else 'no'
    retention_policy_documented = retention_policy_documented_str in ['yes', 'true', 'enabled']

    retention_periods_defined_val = parsed_data.get('retention_periods_defined', 'no')
    retention_periods_defined_str = str(retention_periods_defined_val).lower() if retention_periods_defined_val else 'no'
    retention_periods_defined = retention_periods_defined_str in ['yes', 'true', 'enabled']

    deletion_process_documented_val = parsed_data.get('deletion_process_documented', 'no')
    deletion_process_documented_str = str(deletion_process_documented_val).lower() if deletion_process_documented_val else 'no'
    deletion_process_documented = deletion_process_documented_str in ['yes', 'true', 'enabled']

    deletion_on_request_supported_val = parsed_data.get('deletion_on_request_supported', 'no')
    deletion_on_request_supported_str = str(deletion_on_request_supported_val).lower() if deletion_on_request_supported_val else 'no'
    deletion_on_request_supported = deletion_on_request_supported_str in ['yes', 'true', 'enabled']

    deletion_verification_available_val = parsed_data.get('deletion_verification_available', 'no')
    deletion_verification_available_str = str(deletion_verification_available_val).lower() if deletion_verification_available_val else 'no'
    deletion_verification_available = deletion_verification_available_str in ['yes', 'true', 'enabled']

    deletion_certificate_provided_val = parsed_data.get('deletion_certificate_provided', 'no')
    deletion_certificate_provided_str = str(deletion_certificate_provided_val).lower() if deletion_certificate_provided_val else 'no'
    deletion_certificate_provided = deletion_certificate_provided_str in ['yes', 'true', 'enabled']

    backups_included_in_deletion_val = parsed_data.get('backups_included_in_deletion', 'no')
    backups_included_in_deletion_str = str(backups_included_in_deletion_val).lower() if backups_included_in_deletion_val else 'no'
    backups_included_in_deletion = backups_included_in_deletion_str in ['yes', 'true', 'enabled']

    gdpr_compliant_val = parsed_data.get('gdpr_compliant', 'no')
    gdpr_compliant_str = str(gdpr_compliant_val).lower() if gdpr_compliant_val else 'no'
    gdpr_compliant = gdpr_compliant_str in ['yes', 'true', 'enabled']

    ccpa_compliant_val = parsed_data.get('ccpa_compliant', 'no')
    ccpa_compliant_str = str(ccpa_compliant_val).lower() if ccpa_compliant_val else 'no'
    ccpa_compliant = ccpa_compliant_str in ['yes', 'true', 'enabled']

    # Parse retention periods (in days)
    default_retention_period_days_str = parsed_data.get('default_retention_period_days', 'unknown')
    default_retention_period_days = None
    if default_retention_period_days_str not in ['unknown', 'none', None]:
        try:
            default_retention_period_days = int(default_retention_period_days_str)
        except (ValueError, TypeError):
            default_retention_period_days = None

    customer_data_retention_days_str = parsed_data.get('customer_data_retention_days', 'unknown')
    customer_data_retention_days = None
    if customer_data_retention_days_str not in ['unknown', 'none', None]:
        try:
            customer_data_retention_days = int(customer_data_retention_days_str)
        except (ValueError, TypeError):
            customer_data_retention_days = None

    log_data_retention_days_str = parsed_data.get('log_data_retention_days', 'unknown')
    log_data_retention_days = None
    if log_data_retention_days_str not in ['unknown', 'none', None]:
        try:
            log_data_retention_days = int(log_data_retention_days_str)
        except (ValueError, TypeError):
            log_data_retention_days = None

    backup_data_retention_days_str = parsed_data.get('backup_data_retention_days', 'unknown')
    backup_data_retention_days = None
    if backup_data_retention_days_str not in ['unknown', 'none', None]:
        try:
            backup_data_retention_days = int(backup_data_retention_days_str)
        except (ValueError, TypeError):
            backup_data_retention_days = None

    deletion_request_timeframe_days_str = parsed_data.get('deletion_request_timeframe_days', 'unknown')
    deletion_request_timeframe_days = None
    if deletion_request_timeframe_days_str not in ['unknown', 'none', None]:
        try:
            deletion_request_timeframe_days = int(deletion_request_timeframe_days_str)
        except (ValueError, TypeError):
            deletion_request_timeframe_days = None

    backup_deletion_timeframe_days_str = parsed_data.get('backup_deletion_timeframe_days', 'unknown')
    backup_deletion_timeframe_days = None
    if backup_deletion_timeframe_days_str not in ['unknown', 'none', None]:
        try:
            backup_deletion_timeframe_days = int(backup_deletion_timeframe_days_str)
        except (ValueError, TypeError):
            backup_deletion_timeframe_days = None

    # Parse deletion method
    deletion_method_str = parsed_data.get('deletion_method', 'unknown')
    deletion_method = deletion_method_str.strip().lower().replace(' ', '_').replace('-', '_')
    if deletion_method not in ['secure_deletion', 'crypto_erasure', 'physical_destruction', 'logical_deletion', 'anonymization']:
        deletion_method = None

    # Parse data subject rights (comma-separated list)
    data_subject_rights_str = parsed_data.get('data_subject_rights', '')
    if data_subject_rights_str and data_subject_rights_str.lower() not in ['unknown', 'none', 'n/a', '']:
        data_subject_rights = [r.strip() for r in data_subject_rights_str.split(',')]
    else:
        data_subject_rights = []

    # Parse optional string fields
    retention_policy_location = parsed_data.get('retention_policy_location', None)
    if retention_policy_location and retention_policy_location.lower() in ['unknown', 'none', 'n/a']:
        retention_policy_location = None

    retention_policy_last_updated = parsed_data.get('retention_policy_last_updated', None)
    if retention_policy_last_updated and retention_policy_last_updated.lower() in ['unknown', 'none', 'n/a']:
        retention_policy_last_updated = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_020_data_retention',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'retention_policy_documented': retention_policy_documented,
        'retention_policy_location': retention_policy_location,
        'retention_policy_last_updated': retention_policy_last_updated,
        'retention_periods_defined': retention_periods_defined,
        'default_retention_period_days': default_retention_period_days,
        'customer_data_retention_days': customer_data_retention_days,
        'log_data_retention_days': log_data_retention_days,
        'backup_data_retention_days': backup_data_retention_days,
        'deletion_process_documented': deletion_process_documented,
        'deletion_on_request_supported': deletion_on_request_supported,
        'deletion_request_timeframe_days': deletion_request_timeframe_days,
        'deletion_method': deletion_method,
        'deletion_verification_available': deletion_verification_available,
        'deletion_certificate_provided': deletion_certificate_provided,
        'backups_included_in_deletion': backups_included_in_deletion,
        'backup_deletion_timeframe_days': backup_deletion_timeframe_days,
        'gdpr_compliant': gdpr_compliant,
        'ccpa_compliant': ccpa_compliant,
        'data_subject_rights_supported': data_subject_rights,
        'extraction_confidence': extraction_confidence,
    }


def text_to_insurance(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Insurance Coverage evidence from text using Claude.

    Args:
        text: Source text (insurance certificates, vendor questionnaires, contracts)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching InsuranceCoverageEvidence Pydantic schema
    """
    from conduit.training_examples import INSURANCE_EXAMPLES

    prompt = f"""{INSURANCE_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for insurance coverage evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'insurance')

    # Parse boolean fields
    cyber_insurance_exists_val = parsed_data.get('cyber_insurance_exists', 'no')
    cyber_insurance_exists_str = str(cyber_insurance_exists_val).lower() if cyber_insurance_exists_val else 'no'
    cyber_insurance_exists = cyber_insurance_exists_str in ['yes', 'true', 'enabled']

    eo_insurance_exists_val = parsed_data.get('eo_insurance_exists', 'no')
    eo_insurance_exists_str = str(eo_insurance_exists_val).lower() if eo_insurance_exists_val else 'no'
    eo_insurance_exists = eo_insurance_exists_str in ['yes', 'true', 'enabled']

    certificate_of_insurance_available_val = parsed_data.get('certificate_of_insurance_available', 'no')
    certificate_of_insurance_available_str = str(certificate_of_insurance_available_val).lower() if certificate_of_insurance_available_val else 'no'
    certificate_of_insurance_available = certificate_of_insurance_available_str in ['yes', 'true', 'enabled']

    certificate_provided_to_customer_val = parsed_data.get('certificate_provided_to_customer', 'no')
    certificate_provided_to_customer_str = str(certificate_provided_to_customer_val).lower() if certificate_provided_to_customer_val else 'no'
    certificate_provided_to_customer = certificate_provided_to_customer_str in ['yes', 'true', 'enabled']

    customer_named_as_additional_insured_val = parsed_data.get('customer_named_as_additional_insured', 'no')
    customer_named_as_additional_insured_str = str(customer_named_as_additional_insured_val).lower() if customer_named_as_additional_insured_val else 'no'
    customer_named_as_additional_insured = customer_named_as_additional_insured_str in ['yes', 'true', 'enabled']

    policy_is_current_val = parsed_data.get('policy_is_current', 'yes')
    policy_is_current_str = str(policy_is_current_val).lower() if policy_is_current_val else 'yes'
    policy_is_current = policy_is_current_str in ['yes', 'true', 'current']

    # Parse coverage amounts (convert to USD integer)
    cyber_coverage_amount_str = parsed_data.get('cyber_coverage_amount', 'unknown')
    cyber_coverage_amount = None
    if cyber_coverage_amount_str not in ['unknown', 'none', None]:
        try:
            # Handle formats: "5000000", "5M", "$5,000,000", or integer 5000000
            cleaned = str(cyber_coverage_amount_str).replace('$', '').replace(',', '').lower()
            if 'm' in cleaned or 'million' in cleaned:
                cleaned = cleaned.replace('m', '').replace('million', '').strip()
                cyber_coverage_amount = int(float(cleaned) * 1_000_000)
            elif 'k' in cleaned:
                cleaned = cleaned.replace('k', '').strip()
                cyber_coverage_amount = int(float(cleaned) * 1_000)
            else:
                cyber_coverage_amount = int(float(cleaned))
        except (ValueError, TypeError):
            cyber_coverage_amount = None

    eo_coverage_amount_str = parsed_data.get('eo_coverage_amount', 'unknown')
    eo_coverage_amount = None
    if eo_coverage_amount_str not in ['unknown', 'none', None]:
        try:
            cleaned = str(eo_coverage_amount_str).replace('$', '').replace(',', '').lower()
            if 'm' in cleaned or 'million' in cleaned:
                cleaned = cleaned.replace('m', '').replace('million', '').strip()
                eo_coverage_amount = int(float(cleaned) * 1_000_000)
            elif 'k' in cleaned:
                cleaned = cleaned.replace('k', '').strip()
                eo_coverage_amount = int(float(cleaned) * 1_000)
            else:
                eo_coverage_amount = int(float(cleaned))
        except (ValueError, TypeError):
            eo_coverage_amount = None

    combined_coverage_amount_str = parsed_data.get('combined_coverage_amount', 'unknown')
    combined_coverage_amount = None
    if combined_coverage_amount_str not in ['unknown', 'none', None]:
        try:
            cleaned = str(combined_coverage_amount_str).replace('$', '').replace(',', '').lower()
            if 'm' in cleaned or 'million' in cleaned:
                cleaned = cleaned.replace('m', '').replace('million', '').strip()
                combined_coverage_amount = int(float(cleaned) * 1_000_000)
            elif 'k' in cleaned:
                cleaned = cleaned.replace('k', '').strip()
                combined_coverage_amount = int(float(cleaned) * 1_000)
            else:
                combined_coverage_amount = int(float(cleaned))
        except (ValueError, TypeError):
            combined_coverage_amount = None

    # Parse expiry dates
    cyber_policy_expiry_date_str = parsed_data.get('cyber_policy_expiry_date', 'unknown')
    cyber_policy_expiry_date = None
    if cyber_policy_expiry_date_str not in ['unknown', 'none', None, 'n/a']:
        try:
            cyber_policy_expiry_date = datetime.strptime(cyber_policy_expiry_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            cyber_policy_expiry_date = None

    eo_policy_expiry_date_str = parsed_data.get('eo_policy_expiry_date', 'unknown')
    eo_policy_expiry_date = None
    if eo_policy_expiry_date_str not in ['unknown', 'none', None, 'n/a']:
        try:
            eo_policy_expiry_date = datetime.strptime(eo_policy_expiry_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            eo_policy_expiry_date = None

    # Parse optional string fields
    cyber_insurance_carrier = parsed_data.get('cyber_insurance_carrier', None)
    if cyber_insurance_carrier and cyber_insurance_carrier.lower() in ['unknown', 'none', 'n/a']:
        cyber_insurance_carrier = None

    cyber_policy_number = parsed_data.get('cyber_policy_number', None)
    if cyber_policy_number and cyber_policy_number.lower() in ['unknown', 'none', 'n/a']:
        cyber_policy_number = None

    eo_insurance_carrier = parsed_data.get('eo_insurance_carrier', None)
    if eo_insurance_carrier and eo_insurance_carrier.lower() in ['unknown', 'none', 'n/a']:
        eo_insurance_carrier = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_021_insurance',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'cyber_insurance_exists': cyber_insurance_exists,
        'cyber_insurance_carrier': cyber_insurance_carrier,
        'cyber_coverage_amount': cyber_coverage_amount,
        'cyber_policy_number': cyber_policy_number,
        'cyber_policy_expiry_date': cyber_policy_expiry_date,
        'eo_insurance_exists': eo_insurance_exists,
        'eo_insurance_carrier': eo_insurance_carrier,
        'eo_coverage_amount': eo_coverage_amount,
        'eo_policy_expiry_date': eo_policy_expiry_date,
        'combined_coverage_amount': combined_coverage_amount,
        'certificate_of_insurance_available': certificate_of_insurance_available,
        'certificate_provided_to_customer': certificate_provided_to_customer,
        'customer_named_as_additional_insured': customer_named_as_additional_insured,
        'policy_is_current': policy_is_current,
        'extraction_confidence': extraction_confidence,
    }


def text_to_audit_rights(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract Right to Audit evidence from text using Claude.

    Args:
        text: Source text (contracts, MSAs, SOC 2)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching RightToAuditEvidence Pydantic schema
    """
    from conduit.training_examples import AUDIT_RIGHTS_EXAMPLES

    prompt = f"""{AUDIT_RIGHTS_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for audit rights evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2000,
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'audit_rights')

    # Parse boolean fields
    audit_rights_granted_val = parsed_data.get('audit_rights_granted', 'no')
    audit_rights_granted_str = str(audit_rights_granted_val).lower() if audit_rights_granted_val else 'no'
    audit_rights_granted = audit_rights_granted_str in ['yes', 'true', 'enabled']

    advance_notice_required_val = parsed_data.get('advance_notice_required', 'yes')
    advance_notice_required_str = str(advance_notice_required_val).lower() if advance_notice_required_val else 'yes'
    advance_notice_required = advance_notice_required_str in ['yes', 'true', 'required']

    audit_scope_defined_val = parsed_data.get('audit_scope_defined', 'no')
    audit_scope_defined_str = str(audit_scope_defined_val).lower() if audit_scope_defined_val else 'no'
    audit_scope_defined = audit_scope_defined_str in ['yes', 'true', 'enabled']

    audit_scope_includes_security_val = parsed_data.get('audit_scope_includes_security', 'no')
    audit_scope_includes_security_str = str(audit_scope_includes_security_val).lower() if audit_scope_includes_security_val else 'no'
    audit_scope_includes_security = audit_scope_includes_security_str in ['yes', 'true', 'enabled']

    audit_scope_includes_data_handling_val = parsed_data.get('audit_scope_includes_data_handling', 'no')
    audit_scope_includes_data_handling_str = str(audit_scope_includes_data_handling_val).lower() if audit_scope_includes_data_handling_val else 'no'
    audit_scope_includes_data_handling = audit_scope_includes_data_handling_str in ['yes', 'true', 'enabled']

    third_party_auditor_allowed_val = parsed_data.get('third_party_auditor_allowed', 'yes')
    third_party_auditor_allowed_str = str(third_party_auditor_allowed_val).lower() if third_party_auditor_allowed_val else 'yes'
    third_party_auditor_allowed = third_party_auditor_allowed_str in ['yes', 'true', 'enabled']

    auditor_qualifications_required_val = parsed_data.get('auditor_qualifications_required', 'no')
    auditor_qualifications_required_str = str(auditor_qualifications_required_val).lower() if auditor_qualifications_required_val else 'no'
    auditor_qualifications_required = auditor_qualifications_required_str in ['yes', 'true', 'required']

    vendor_cooperation_required_val = parsed_data.get('vendor_cooperation_required', 'yes')
    vendor_cooperation_required_str = str(vendor_cooperation_required_val).lower() if vendor_cooperation_required_val else 'yes'
    vendor_cooperation_required = vendor_cooperation_required_str in ['yes', 'true', 'required']

    access_to_systems_granted_val = parsed_data.get('access_to_systems_granted', 'no')
    access_to_systems_granted_str = str(access_to_systems_granted_val).lower() if access_to_systems_granted_val else 'no'
    access_to_systems_granted = access_to_systems_granted_str in ['yes', 'true', 'enabled']

    access_to_documentation_granted_val = parsed_data.get('access_to_documentation_granted', 'no')
    access_to_documentation_granted_str = str(access_to_documentation_granted_val).lower() if access_to_documentation_granted_val else 'no'
    access_to_documentation_granted = access_to_documentation_granted_str in ['yes', 'true', 'enabled']

    access_to_personnel_granted_val = parsed_data.get('access_to_personnel_granted', 'no')
    access_to_personnel_granted_str = str(access_to_personnel_granted_val).lower() if access_to_personnel_granted_val else 'no'
    access_to_personnel_granted = access_to_personnel_granted_str in ['yes', 'true', 'enabled']

    audit_report_to_customer_val = parsed_data.get('audit_report_to_customer', 'yes')
    audit_report_to_customer_str = str(audit_report_to_customer_val).lower() if audit_report_to_customer_val else 'yes'
    audit_report_to_customer = audit_report_to_customer_str in ['yes', 'true', 'enabled']

    remediation_plan_required_val = parsed_data.get('remediation_plan_required', 'no')
    remediation_plan_required_str = str(remediation_plan_required_val).lower() if remediation_plan_required_val else 'no'
    remediation_plan_required = remediation_plan_required_str in ['yes', 'true', 'required']

    # Parse audit frequency enum
    audit_frequency_str = parsed_data.get('audit_frequency', 'unknown')
    audit_frequency = audit_frequency_str.strip().lower().replace(' ', '_').replace('-', '_')
    if audit_frequency not in ['annual', 'semi_annual', 'quarterly', 'upon_request', 'upon_cause']:
        audit_frequency = None

    # Parse cost allocation enum
    cost_allocation_str = parsed_data.get('cost_allocation', 'not_specified')
    cost_allocation = cost_allocation_str.strip().lower().replace(' ', '_').replace('-', '_')
    if cost_allocation not in ['customer', 'vendor', 'shared', 'customer_unless_issues', 'not_specified']:
        cost_allocation = 'not_specified'

    # Parse advance notice days
    advance_notice_days_str = parsed_data.get('advance_notice_days', 'unknown')
    advance_notice_days = None
    if advance_notice_days_str not in ['unknown', 'none', None]:
        try:
            advance_notice_days = int(advance_notice_days_str)
        except (ValueError, TypeError):
            advance_notice_days = None

    # Parse cost cap amount
    cost_cap_amount_str = parsed_data.get('cost_cap_amount', 'unknown')
    cost_cap_amount = None
    if cost_cap_amount_str not in ['unknown', 'none', None]:
        try:
            cleaned = cost_cap_amount_str.replace('$', '').replace(',', '').lower()
            if 'k' in cleaned:
                cleaned = cleaned.replace('k', '').strip()
                cost_cap_amount = int(float(cleaned) * 1_000)
            else:
                cost_cap_amount = int(float(cleaned))
        except (ValueError, TypeError):
            cost_cap_amount = None

    # Parse optional string fields
    audit_clause_location = parsed_data.get('audit_clause_location', None)
    if audit_clause_location and audit_clause_location.lower() in ['unknown', 'none', 'n/a']:
        audit_clause_location = None

    audit_frequency_description = parsed_data.get('audit_frequency_description', None)
    if audit_frequency_description and audit_frequency_description.lower() in ['unknown', 'none', 'n/a']:
        audit_frequency_description = None

    audit_scope_description = parsed_data.get('audit_scope_description', None)
    if audit_scope_description and audit_scope_description.lower() in ['unknown', 'none', 'n/a']:
        audit_scope_description = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_022_audit_rights',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'audit_rights_granted': audit_rights_granted,
        'audit_clause_location': audit_clause_location,
        'audit_frequency': audit_frequency,
        'audit_frequency_description': audit_frequency_description,
        'advance_notice_required': advance_notice_required,
        'advance_notice_days': advance_notice_days,
        'audit_scope_defined': audit_scope_defined,
        'audit_scope_includes_security': audit_scope_includes_security,
        'audit_scope_includes_data_handling': audit_scope_includes_data_handling,
        'audit_scope_description': audit_scope_description,
        'third_party_auditor_allowed': third_party_auditor_allowed,
        'auditor_qualifications_required': auditor_qualifications_required,
        'vendor_cooperation_required': vendor_cooperation_required,
        'access_to_systems_granted': access_to_systems_granted,
        'access_to_documentation_granted': access_to_documentation_granted,
        'access_to_personnel_granted': access_to_personnel_granted,
        'cost_allocation': cost_allocation,
        'cost_cap_amount': cost_cap_amount,
        'audit_report_to_customer': audit_report_to_customer,
        'remediation_plan_required': remediation_plan_required,
        'extraction_confidence': extraction_confidence,
    }


# =============================================================================
# BATCH 5: AI GOVERNANCE (1 evidence type)
# =============================================================================

def text_to_ai_governance(text: str, vendor_name: str, use_expensive_model: bool = False) -> dict[str, Any]:
    """
    Extract AI/ML Security Controls evidence from text using Claude.

    Args:
        text: Source text (AI governance docs, model cards, vendor questionnaires)
        vendor_name: Vendor name
        use_expensive_model: Use Sonnet instead of Haiku

    Returns:
        Dictionary matching AIGovernanceEvidence Pydantic schema
    """
    from conduit.training_examples import AI_GOVERNANCE_EXAMPLES

    prompt = f"""{AI_GOVERNANCE_EXAMPLES}

NOW EXTRACT FROM THIS TEXT ({len(text):,} characters):

VENDOR: {vendor_name}
DOCUMENT TEXT: {text}

Output the XML structure for AI governance evidence. Extract all available information."""

    model = MODEL_EXPENSIVE if use_expensive_model else MODEL_CHEAP

    response = client.messages.create(
        model=model,
        max_tokens=2500,  # AI governance may need more tokens
        temperature=0.0,
        messages=[{"role": "user", "content": prompt}]
    )

    raw_text = response.content[0].text.strip()
    parsed_data = parse_evidence_xml(raw_text, 'ai_governance')

    # Parse boolean fields (many!)
    ai_systems_used_val = parsed_data.get('ai_systems_used', 'no')
    ai_systems_used_str = str(ai_systems_used_val).lower() if ai_systems_used_val else 'no'
    ai_systems_used = ai_systems_used_str in ['yes', 'true', 'enabled']

    # Early return if no AI systems used
    if not ai_systems_used:
        return {
            'evidence_type': 'assure_024_ai_governance',
            'vendor_name': vendor_name,
            'evidence_date': datetime.now().date().isoformat(),
            'ai_systems_used': False,
            'extraction_confidence': 0.90,
        }

    # Parse remaining boolean fields
    ai_inventory_maintained_val = parsed_data.get('ai_inventory_maintained', 'no')
    ai_inventory_maintained = str(ai_inventory_maintained_val).lower() in ['yes', 'true', 'enabled']

    ai_risk_assessment_performed_val = parsed_data.get('ai_risk_assessment_performed', 'no')
    ai_risk_assessment_performed = str(ai_risk_assessment_performed_val).lower() in ['yes', 'true', 'enabled']

    training_data_governance_exists_val = parsed_data.get('training_data_governance_exists', 'no')
    training_data_governance_exists = str(training_data_governance_exists_val).lower() in ['yes', 'true', 'enabled']

    training_data_provenance_tracked_val = parsed_data.get('training_data_provenance_tracked', 'no')
    training_data_provenance_tracked = str(training_data_provenance_tracked_val).lower() in ['yes', 'true', 'enabled']

    training_data_quality_validated_val = parsed_data.get('training_data_quality_validated', 'no')
    training_data_quality_validated = str(training_data_quality_validated_val).lower() in ['yes', 'true', 'enabled']

    customer_data_used_for_training_val = parsed_data.get('customer_data_used_for_training', 'no')
    customer_data_used_for_training = str(customer_data_used_for_training_val).lower() in ['yes', 'true', 'enabled']

    customer_data_training_opt_out_val = parsed_data.get('customer_data_training_opt_out', 'no')
    customer_data_training_opt_out = str(customer_data_training_opt_out_val).lower() in ['yes', 'true', 'enabled']

    model_validation_performed_val = parsed_data.get('model_validation_performed', 'no')
    model_validation_performed = str(model_validation_performed_val).lower() in ['yes', 'true', 'enabled']

    bias_testing_performed_val = parsed_data.get('bias_testing_performed', 'no')
    bias_testing_performed = str(bias_testing_performed_val).lower() in ['yes', 'true', 'enabled']

    accuracy_metrics_tracked_val = parsed_data.get('accuracy_metrics_tracked', 'no')
    accuracy_metrics_tracked = str(accuracy_metrics_tracked_val).lower() in ['yes', 'true', 'enabled']

    explainability_provided_val = parsed_data.get('explainability_provided', 'no')
    explainability_provided = str(explainability_provided_val).lower() in ['yes', 'true', 'enabled']

    model_cards_published_val = parsed_data.get('model_cards_published', 'no')
    model_cards_published = str(model_cards_published_val).lower() in ['yes', 'true', 'enabled']

    ai_transparency_report_val = parsed_data.get('ai_transparency_report', 'no')
    ai_transparency_report = str(ai_transparency_report_val).lower() in ['yes', 'true', 'enabled']

    human_oversight_exists_val = parsed_data.get('human_oversight_exists', 'no')
    human_oversight_exists = str(human_oversight_exists_val).lower() in ['yes', 'true', 'enabled']

    human_review_for_critical_decisions_val = parsed_data.get('human_review_for_critical_decisions', 'no')
    human_review_for_critical_decisions = str(human_review_for_critical_decisions_val).lower() in ['yes', 'true', 'enabled']

    ai_decision_appeal_process_val = parsed_data.get('ai_decision_appeal_process', 'no')
    ai_decision_appeal_process = str(ai_decision_appeal_process_val).lower() in ['yes', 'true', 'enabled']

    adversarial_testing_performed_val = parsed_data.get('adversarial_testing_performed', 'no')
    adversarial_testing_performed = str(adversarial_testing_performed_val).lower() in ['yes', 'true', 'enabled']

    red_team_testing_performed_val = parsed_data.get('red_team_testing_performed', 'no')
    red_team_testing_performed = str(red_team_testing_performed_val).lower() in ['yes', 'true', 'enabled']

    ai_incident_response_plan_val = parsed_data.get('ai_incident_response_plan', 'no')
    ai_incident_response_plan = str(ai_incident_response_plan_val).lower() in ['yes', 'true', 'enabled']

    ai_incident_monitoring_val = parsed_data.get('ai_incident_monitoring', 'no')
    ai_incident_monitoring = str(ai_incident_monitoring_val).lower() in ['yes', 'true', 'enabled']

    third_party_ai_models_used_val = parsed_data.get('third_party_ai_models_used', 'no')
    third_party_ai_models_used = str(third_party_ai_models_used_val).lower() in ['yes', 'true', 'enabled']

    third_party_ai_risk_assessed_val = parsed_data.get('third_party_ai_risk_assessed', 'no')
    third_party_ai_risk_assessed = str(third_party_ai_risk_assessed_val).lower() in ['yes', 'true', 'enabled']

    # Parse AI use cases (comma-separated list)
    ai_use_cases_str = parsed_data.get('ai_use_cases', '')
    if ai_use_cases_str and ai_use_cases_str.lower() not in ['unknown', 'none', 'n/a', '']:
        ai_use_cases = [u.strip() for u in ai_use_cases_str.split(',')]
    else:
        ai_use_cases = []

    # Parse risk level enum
    highest_ai_risk_level_str = parsed_data.get('highest_ai_risk_level', 'minimal')
    highest_ai_risk_level = highest_ai_risk_level_str.strip().lower().replace(' ', '_')
    if highest_ai_risk_level not in ['critical', 'high', 'medium', 'low', 'minimal']:
        highest_ai_risk_level = 'minimal'

    # Parse third-party AI vendors (comma-separated list)
    third_party_ai_vendors_str = parsed_data.get('third_party_ai_vendors', '')
    if third_party_ai_vendors_str and third_party_ai_vendors_str.lower() not in ['unknown', 'none', 'n/a', '']:
        third_party_ai_vendors = [v.strip() for v in third_party_ai_vendors_str.split(',')]
    else:
        third_party_ai_vendors = []

    # Parse optional string fields
    ai_use_case_descriptions = parsed_data.get('ai_use_case_descriptions', None)
    if ai_use_case_descriptions and ai_use_case_descriptions.lower() in ['unknown', 'none', 'n/a']:
        ai_use_case_descriptions = None

    ai_risk_framework_used = parsed_data.get('ai_risk_framework_used', None)
    if ai_risk_framework_used and ai_risk_framework_used.lower() in ['unknown', 'none', 'n/a']:
        ai_risk_framework_used = None

    bias_testing_frequency = parsed_data.get('bias_testing_frequency', None)
    if bias_testing_frequency and bias_testing_frequency.lower() in ['unknown', 'none', 'n/a']:
        bias_testing_frequency = None

    # Extraction confidence
    confidence_str = parsed_data.get('extraction_confidence', '0.80')
    try:
        extraction_confidence = float(confidence_str)
    except (ValueError, TypeError):
        extraction_confidence = 0.80

    return {
        'evidence_type': 'assure_024_ai_governance',
        'vendor_name': vendor_name,
        'evidence_date': datetime.now().date().isoformat(),
        'ai_systems_used': ai_systems_used,
        'ai_inventory_maintained': ai_inventory_maintained,
        'ai_use_cases': ai_use_cases,
        'ai_use_case_descriptions': ai_use_case_descriptions,
        'ai_risk_assessment_performed': ai_risk_assessment_performed,
        'highest_ai_risk_level': highest_ai_risk_level,
        'ai_risk_framework_used': ai_risk_framework_used,
        'training_data_governance_exists': training_data_governance_exists,
        'training_data_provenance_tracked': training_data_provenance_tracked,
        'training_data_quality_validated': training_data_quality_validated,
        'customer_data_used_for_training': customer_data_used_for_training,
        'customer_data_training_opt_out': customer_data_training_opt_out,
        'model_validation_performed': model_validation_performed,
        'bias_testing_performed': bias_testing_performed,
        'bias_testing_frequency': bias_testing_frequency,
        'accuracy_metrics_tracked': accuracy_metrics_tracked,
        'explainability_provided': explainability_provided,
        'model_cards_published': model_cards_published,
        'ai_transparency_report': ai_transparency_report,
        'human_oversight_exists': human_oversight_exists,
        'human_review_for_critical_decisions': human_review_for_critical_decisions,
        'ai_decision_appeal_process': ai_decision_appeal_process,
        'adversarial_testing_performed': adversarial_testing_performed,
        'red_team_testing_performed': red_team_testing_performed,
        'ai_incident_response_plan': ai_incident_response_plan,
        'ai_incident_monitoring': ai_incident_monitoring,
        'third_party_ai_models_used': third_party_ai_models_used,
        'third_party_ai_risk_assessed': third_party_ai_risk_assessed,
        'third_party_ai_vendors': third_party_ai_vendors,
        'extraction_confidence': extraction_confidence,
    }


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
