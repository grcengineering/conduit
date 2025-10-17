"""Unified XML parser for all CONDUIT evidence types"""

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def parse_evidence_xml(text: str, root_tag: str) -> Dict[str, Any]:
    """
    Parse XML evidence response from Claude.

    Handles:
    - Simple fields: <bcpdr>- field: value</bcpdr>
    - Arrays: <scans><scan>...</scan><scan>...</scan></scans>
    - Nested: <vulnerability><scans>...</scans><pentest>...</pentest></vulnerability>

    Args:
        text: Claude's XML response
        root_tag: Root tag (e.g., 'bcpdr', 'vulnerability', 'sso_mfa')

    Returns:
        Parsed dictionary ready for Pydantic

    Raises:
        ValueError: If root tag not found in response

    Examples:
        >>> xml = "<bcpdr>- test_date: 2025-08-15\\n- test_result: pass</bcpdr>"
        >>> parse_evidence_xml(xml, 'bcpdr')
        {'test_date': '2025-08-15', 'test_result': 'pass'}
    """
    # Extract root block
    root_pattern = rf'<{root_tag}>(.*?)</{root_tag}>'
    root_match = re.search(root_pattern, text, re.DOTALL)

    if not root_match:
        raise ValueError(f"No <{root_tag}> block found in response")

    root_content = root_match.group(1)

    # Parse based on evidence type structure
    if root_tag == 'bcpdr':
        return _parse_simple_fields(root_content)
    elif root_tag == 'vulnerability':
        return _parse_vulnerability(root_content)
    elif root_tag == 'sso_mfa':
        return _parse_simple_fields(root_content)
    elif root_tag == 'encryption_at_rest':
        return _parse_encryption_at_rest(root_content)
    elif root_tag == 'encryption_in_transit':
        return _parse_encryption_in_transit(root_content)
    elif root_tag == 'incident_response':
        return _parse_incident_response(root_content)
    elif root_tag == 'logging_config':
        return _parse_logging_config(root_content)
    elif root_tag == 'production_access':
        return _parse_simple_fields(root_content)
    else:
        # Default: parse as simple fields
        return _parse_simple_fields(root_content)


def _parse_simple_fields(content: str) -> Dict[str, Any]:
    """
    Parse simple key-value fields from XML content.

    Format: "- key: value" per line

    Args:
        content: Content inside XML tags

    Returns:
        Dictionary with parsed fields

    Examples:
        >>> content = "- test_date: 2025-08-15\\n- test_result: pass"
        >>> _parse_simple_fields(content)
        {'test_date': '2025-08-15', 'test_result': 'pass'}
    """
    data = {}
    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('- ') and ':' in line:
            key, value = line[2:].split(':', 1)
            data[key.strip()] = _convert_value(value.strip())
    return data


def _parse_vulnerability(content: str) -> Dict[str, Any]:
    """
    Parse vulnerability evidence with nested structures.

    Handles:
    - <scans> array with multiple <scan> blocks
    - <pentest> single block
    - <sla> single block

    Args:
        content: Content inside <vulnerability> tags

    Returns:
        Dictionary with parsed vulnerability data including arrays

    Examples:
        >>> content = "<scans><scan>- date: 2024-08-15</scan></scans>"
        >>> result = _parse_vulnerability(content)
        >>> len(result['scans_last_3_months'])
        1
    """
    result = {}

    # Parse scans array
    scans_match = re.search(r'<scans>(.*?)</scans>', content, re.DOTALL)
    if scans_match:
        scan_blocks = re.findall(r'<scan>(.*?)</scan>', scans_match.group(1), re.DOTALL)
        result['scans_last_3_months'] = [_parse_simple_fields(block) for block in scan_blocks]

    # Parse pentest
    pentest_match = re.search(r'<pentest>(.*?)</pentest>', content, re.DOTALL)
    if pentest_match:
        result['penetration_test'] = _parse_simple_fields(pentest_match.group(1))

    # Parse SLA
    sla_match = re.search(r'<sla>(.*?)</sla>', content, re.DOTALL)
    if sla_match:
        sla_data = _parse_simple_fields(sla_match.group(1))
        result['vulnerability_sla_met'] = sla_data.get('vulnerability_sla_met')

    return result


def _convert_value(value: str) -> Any:
    """
    Convert string value to appropriate Python type.

    Conversions:
    - "null", "n/a", "" → None
    - "true", "yes" → True
    - "false", "no" → False
    - Digits → int
    - Everything else → str

    Args:
        value: String value to convert

    Returns:
        Converted value with appropriate type

    Examples:
        >>> _convert_value("true")
        True
        >>> _convert_value("null")
        None
        >>> _convert_value("42")
        42
        >>> _convert_value("hello")
        'hello'
    """
    value_lower = value.lower()

    # Handle null/empty
    if value_lower in ['null', 'n/a', 'not mentioned', 'not specified', '']:
        return None

    # Handle boolean
    if value_lower in ['true', 'yes']:
        return True
    if value_lower in ['false', 'no']:
        return False

    # Handle integer
    if value.isdigit():
        return int(value)

    # String (keep as-is)
    return value


def _parse_encryption_at_rest(content: str) -> Dict[str, Any]:
    """
    Parse encryption at rest XML structure with nested stores array.

    Handles:
    - <stores> array with multiple <store> blocks
    - Top-level fields: key_rotation, rotation_days, fips_compliant

    Args:
        content: Content inside <encryption_at_rest> tags

    Returns:
        Dictionary with parsed encryption data including stores array

    Examples:
        >>> content = "<stores><store><type>database</type></store></stores>"
        >>> result = _parse_encryption_at_rest(content)
        >>> len(result['stores'])
        1
    """
    result = {}

    # Parse stores array - wrap content in a root tag for ET parsing
    try:
        wrapped_xml = f"<root>{content}</root>"
        root = ET.fromstring(wrapped_xml)

        # Extract stores array
        stores_elem = root.find('stores')
        stores = []

        if stores_elem is not None:
            for store_elem in stores_elem.findall('store'):
                store = {
                    'type': store_elem.findtext('type', '').strip(),
                    'name': store_elem.findtext('name', '').strip(),
                    'encrypted': store_elem.findtext('encrypted', '').strip(),
                    'algorithm': store_elem.findtext('algorithm', '').strip(),
                    'key_mgmt': store_elem.findtext('key_mgmt', '').strip(),
                }
                stores.append(store)

        result['stores'] = stores

        # Parse top-level fields
        key_rotation_elem = root.find('key_rotation')
        if key_rotation_elem is not None:
            result['key_rotation'] = key_rotation_elem.text.strip() if key_rotation_elem.text else ''
        else:
            result['key_rotation'] = ''

        rotation_days_elem = root.find('rotation_days')
        if rotation_days_elem is not None:
            result['rotation_days'] = rotation_days_elem.text.strip() if rotation_days_elem.text else ''
        else:
            result['rotation_days'] = ''

        fips_elem = root.find('fips_compliant')
        if fips_elem is not None:
            result['fips_compliant'] = fips_elem.text.strip() if fips_elem.text else ''
        else:
            result['fips_compliant'] = ''

    except ET.ParseError as e:
        # If XML parsing fails, return empty structure
        result = {
            'stores': [],
            'key_rotation': '',
            'rotation_days': '',
            'fips_compliant': '',
        }

    return result


def _parse_incident_response(content: str) -> Dict[str, Any]:
    """
    Parse incident response XML structure with nested incident_types_covered array.

    Handles:
    - <incident_types_covered> array with multiple <type> elements
    - Top-level fields: plan_exists, last_test_date, test_type, SLAs, etc.

    Args:
        content: Content inside <incident_response> tags

    Returns:
        Dictionary with parsed incident response data including incident types array

    Examples:
        >>> content = "<incident_types_covered><type>security_breach</type></incident_types_covered>"
        >>> result = _parse_incident_response(content)
        >>> 'security_breach' in result['incident_types_covered']
        True
    """
    result = {}

    # Parse incident_types_covered array - wrap content in a root tag for ET parsing
    try:
        wrapped_xml = f"<root>{content}</root>"
        root = ET.fromstring(wrapped_xml)

        # Extract incident_types_covered array
        types_elem = root.find('incident_types_covered')
        incident_types = []

        if types_elem is not None:
            for type_elem in types_elem.findall('type'):
                if type_elem.text:
                    incident_types.append(type_elem.text.strip())

        result['incident_types_covered'] = incident_types

        # Parse top-level simple fields using ET
        simple_fields = [
            'plan_exists',
            'last_test_date',
            'test_type',
            'security_breach_sla',
            'privacy_breach_sla',
            'lessons_learned_documented',
            'plan_accessible_to_employees',
        ]

        for field in simple_fields:
            elem = root.find(field)
            if elem is not None and elem.text:
                value = elem.text.strip()
                result[field] = _convert_value(value)
            else:
                result[field] = None

    except ET.ParseError as e:
        # If XML parsing fails, fall back to simple field parsing
        result = _parse_simple_fields(content)
        # Ensure incident_types_covered is at least an empty list
        if 'incident_types_covered' not in result:
            result['incident_types_covered'] = []

    return result


def _parse_encryption_in_transit(content: str) -> Dict[str, Any]:
    """
    Parse encryption in transit XML structure with nested arrays.

    Handles:
    - <tls_versions> array with multiple <version> elements
    - <weak_blocked> array with multiple <protocol> elements
    - Top-level fields: cert_authority, cert_expiry, qualys_grade, forward_secrecy

    Args:
        content: Content inside <encryption_in_transit> tags

    Returns:
        Dictionary with parsed encryption in transit data including arrays

    Examples:
        >>> content = "<tls_versions><version>tls_1_3</version></tls_versions>"
        >>> result = _parse_encryption_in_transit(content)
        >>> 'tls_1_3' in result['tls_versions']
        True
    """
    result = {}

    # Parse arrays using ElementTree - wrap content in a root tag for ET parsing
    try:
        wrapped_xml = f"<root>{content}</root>"
        root = ET.fromstring(wrapped_xml)

        # Extract tls_versions array
        tls_versions_elem = root.find('tls_versions')
        tls_versions = []

        if tls_versions_elem is not None:
            for version_elem in tls_versions_elem.findall('version'):
                if version_elem.text:
                    tls_versions.append(version_elem.text.strip())

        result['tls_versions'] = tls_versions

        # Extract weak_blocked array
        weak_blocked_elem = root.find('weak_blocked')
        weak_blocked = []

        if weak_blocked_elem is not None:
            for protocol_elem in weak_blocked_elem.findall('protocol'):
                if protocol_elem.text:
                    weak_blocked.append(protocol_elem.text.strip())

        result['weak_blocked'] = weak_blocked

        # Parse top-level simple fields using ET
        simple_fields = [
            'cert_authority',
            'cert_expiry',
            'qualys_grade',
            'forward_secrecy',
        ]

        for field in simple_fields:
            elem = root.find(field)
            if elem is not None and elem.text:
                value = elem.text.strip()
                result[field] = _convert_value(value)
            else:
                result[field] = None

    except ET.ParseError as e:
        # If XML parsing fails, return empty structure
        result = {
            'tls_versions': [],
            'weak_blocked': [],
            'cert_authority': None,
            'cert_expiry': None,
            'qualys_grade': None,
            'forward_secrecy': None,
        }

    return result


def _parse_logging_config(content: str) -> Dict[str, Any]:
    """
    Parse logging configuration XML structure with nested log_types array.

    Handles:
    - <log_types> array with multiple <type> elements
    - Top-level fields: retention_period, monitoring_tool, logs_immutable, centralized_logging

    Args:
        content: Content inside <logging_config> tags

    Returns:
        Dictionary with parsed logging configuration data including log types array

    Examples:
        >>> content = "<log_types><type>security</type><type>audit</type></log_types>"
        >>> result = _parse_logging_config(content)
        >>> 'security' in result['log_types_collected']
        True
    """
    result = {}

    # Parse arrays using ElementTree - wrap content in a root tag for ET parsing
    try:
        wrapped_xml = f"<root>{content}</root>"
        root = ET.fromstring(wrapped_xml)

        # Extract log_types array
        log_types_elem = root.find('log_types')
        log_types = []

        if log_types_elem is not None:
            for type_elem in log_types_elem.findall('type'):
                if type_elem.text:
                    log_types.append(type_elem.text.strip())

        result['log_types_collected'] = log_types

        # Parse top-level simple fields using ET
        simple_fields = [
            'retention_period',
            'monitoring_tool',
            'logs_immutable',
            'centralized_logging',
        ]

        for field in simple_fields:
            elem = root.find(field)
            if elem is not None and elem.text:
                value = elem.text.strip()
                result[field] = _convert_value(value)
            else:
                result[field] = None

    except ET.ParseError as e:
        # If XML parsing fails, return empty structure
        result = {
            'log_types_collected': [],
            'retention_period': None,
            'monitoring_tool': None,
            'logs_immutable': None,
            'centralized_logging': None,
        }

    return result
