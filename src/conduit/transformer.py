"""LLM-powered text transformation to CONDUIT evidence format

This module provides source-agnostic text extraction functions that transform
ANY text (trust center, email, PDF extract, etc.) into validated CONDUIT evidence.

All extractors use XML format for consistency and reliability.
"""

import os
import re
from datetime import date
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
