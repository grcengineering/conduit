"""
Training examples for CONDUIT evidence extraction.

All examples work with ANY text source (compliance reports, emails, trust centers, etc.)
All examples use XML format for consistency.
All examples are GENERIC and SANITIZED - no real vendor data.
"""

BCPDR_EXAMPLES = """
Extract BCP/DR (Business Continuity / Disaster Recovery) testing evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Trust center websites
- Vendor email responses
- Policy documents
- Manual entry

Look for evidence of:
- When the most recent BCP/DR test was conducted
- What type of test it was (tabletop, partial failover, full failover)
- Whether the test passed or failed
- What systems/services were tested
- Whether Recovery Time Objectives (RTO) were met

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - Successful test from compliance report:
Input: "Control: Business Continuity Testing. The organization's business continuity and disaster recovery plan was tested on August 15, 2025. The test included a partial failover of the production database and application servers to the secondary datacenter. All recovery time objectives were successfully met during the test."

Output:
<bcpdr>
- test_date: 2025-08-15
- test_result: pass
- test_type: partial_failover
- scope: production database and application servers
- recovery_time_objective_met: true
</bcpdr>

Example 2 - Tabletop exercise from email:
Input: "Hi, regarding your BCP question - we ran a tabletop exercise in Q3 2024 to review our DR procedures. The exercise identified some gaps in our runbook documentation that we're working to address."

Output:
<bcpdr>
- test_date: 2024-09-30
- test_result: pass_with_findings
- test_type: tabletop
- scope: disaster recovery runbook review
- recovery_time_objective_met: null
</bcpdr>

Example 3 - Failed test from trust center:
Input: "Our last DR test was in December 2023. We performed a full datacenter failover. Unfortunately, the test was unsuccessful as we did not meet our recovery time objective of 4 hours (actual recovery time: 6.5 hours)."

Output:
<bcpdr>
- test_date: 2023-12-15
- test_result: fail
- test_type: full_failover
- scope: complete datacenter failover
- recovery_time_objective_met: false
</bcpdr>

EXTRACTION RULES:
- test_date: YYYY-MM-DD format. Convert fuzzy dates:
  * "Q3 2024" → 2024-09-30 (end of quarter)
  * "August 2024" → 2024-08-31 (end of month)
  * "Last year" → Use current year - 1, estimate month
- test_result: Must be exactly "pass", "fail", or "pass_with_findings"
- test_type: Must be exactly "tabletop", "partial_failover", or "full_failover"
- scope: Brief description of what was tested
- recovery_time_objective_met: true/false/null (null if not mentioned)
- If NO BCP/DR evidence found in text, return null for all fields

Output format: Wrap all fields in <bcpdr></bcpdr> tags as shown above.
"""

VULNERABILITY_EXAMPLES = """
Extract Vulnerability Management evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Pentest reports
- Vulnerability scan summaries
- Security assessment emails
- Trust center pages

Look for:
- Vulnerability scans (last 3 months)
- Penetration test results
- Remediation SLA compliance

IMPORTANT: Output must use XML format with nested structure.

TRAINING EXAMPLES:

Example 1 - From compliance report:
Input: "Vulnerability Management: The organization performs quarterly authenticated vulnerability scans using Qualys. Recent scans: August 15, 2024 (0 critical, 2 high, 5 medium, 12 low), September 22, 2024 (0 critical, 1 high, 3 medium, 8 low). Annual penetration test conducted by Generic Security Firm on June 10, 2024 identified 1 high and 3 medium findings. All high severity findings were remediated within 30 days per SLA."

Output:
<vulnerability>
  <scans>
    <scan>
    - date: 2024-08-15
    - tool: Qualys
    - type: authenticated
    - critical: 0
    - high: 2
    - medium: 5
    - low: 12
    </scan>
    <scan>
    - date: 2024-09-22
    - tool: Qualys
    - type: authenticated
    - critical: 0
    - high: 1
    - medium: 3
    - low: 8
    </scan>
  </scans>

  <pentest>
  - date: 2024-06-10
  - firm: Generic Security Firm
  - type: external_black_box
  - critical: 0
  - high: 1
  - medium: 3
  - low: 0
  - all_remediated: true
  </pentest>

  <sla>
  - vulnerability_sla_met: true
  </sla>
</vulnerability>

Example 2 - From email (minimal info):
Input: "We run Tenable scans monthly. Last scan was July 2024, found 3 highs. We had a pentest in Q2 2024, no criticals found."

Output:
<vulnerability>
  <scans>
    <scan>
    - date: 2024-07-31
    - tool: Tenable
    - type: authenticated
    - critical: 0
    - high: 3
    - medium: null
    - low: null
    </scan>
  </scans>

  <pentest>
  - date: 2024-06-30
  - firm: Not specified
  - type: Not specified
  - critical: 0
  - high: null
  - medium: null
  - low: null
  - all_remediated: null
  </pentest>

  <sla>
  - vulnerability_sla_met: null
  </sla>
</vulnerability>

EXTRACTION RULES:
- Dates: YYYY-MM-DD format (convert "Q2 2024" → 2024-06-30, "July 2024" → 2024-07-31)
- scan_type: Must be exactly "authenticated" or "unauthenticated" (default to "authenticated" if unclear)
- Findings: Integers only (0, 1, 2, etc. NOT "zero", "one", "two")
- all_remediated: true if explicitly stated all critical/high fixed, false if open issues mentioned, null if unclear
- If fewer than 3 scans found, include only what exists
- Use null for any field not found in text
"""

SSO_MFA_EXAMPLES = """
Extract SSO/MFA implementation details from ANY text source.

This extractor works with:
- Compliance reports
- Trust center pages
- Product documentation
- Vendor emails
- Security questionnaires

Look for:
- SSO support and protocols
- MFA enforcement
- Cost/paywall for SSO
- Phishing-resistant MFA

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - From trust center (full support):
Input: "Authentication & Access: Our platform supports single sign-on using SAML 2.0, OAuth 2.0, and OpenID Connect protocols. SSO is available to all customers at no additional cost. Multi-factor authentication is enforced for all users and supports time-based one-time passwords (TOTP), SMS codes, and hardware security keys (WebAuthn/FIDO2)."

Output:
<sso_mfa>
- sso_supported: true
- sso_protocols: SAML 2.0; OAuth 2.0; OpenID Connect
- mfa_enforced: true
- mfa_types: TOTP; SMS; hardware_security_key
- sso_paywall: false
- mfa_phishing_resistant: true
</sso_mfa>

Example 2 - From email (SSO enterprise only):
Input: "RE: SSO question - Single sign-on is available as an enterprise add-on feature. Our basic accounts include username/password authentication with optional SMS-based two-factor authentication."

Output:
<sso_mfa>
- sso_supported: true
- sso_protocols: Not specified
- mfa_enforced: false
- mfa_types: SMS
- sso_paywall: true
- mfa_phishing_resistant: false
</sso_mfa>

Example 3 - From questionnaire (no SSO):
Input: "Q: Do you support SSO? A: No, we currently only offer username/password authentication. Q: MFA available? A: Yes, TOTP authenticator apps are supported."

Output:
<sso_mfa>
- sso_supported: false
- sso_protocols: None
- mfa_enforced: false
- mfa_types: TOTP
- sso_paywall: false
- mfa_phishing_resistant: false
</sso_mfa>

EXTRACTION RULES:
- mfa_types: Semicolon-separated list (e.g., "TOTP; SMS; hardware_security_key")
- mfa_phishing_resistant: true ONLY if hardware keys, WebAuthn, FIDO2, or biometric mentioned
- mfa_phishing_resistant: false for SMS, email codes, TOTP alone
- sso_paywall: true if requires enterprise plan, upgrade, or extra payment
- sso_paywall: false if included in base offering or available to all
"""

ENCRYPTION_AT_REST_EXAMPLES = """
Extract Encryption at Rest evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Trust center websites
- Security documentation
- Vendor questionnaires
- Policy documents

Look for evidence of:
- Whether databases are encrypted at rest
- Whether file storage is encrypted at rest
- Whether backups are encrypted
- Encryption algorithm used (AES-256, AES-128, etc.)
- Key management system (AWS KMS, Azure Key Vault, HSM, etc.)
- Key rotation practices

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Control CC6.7: Encryption. All customer data is encrypted at rest using AES-256 encryption. The production PostgreSQL database uses AWS RDS with encryption enabled. Amazon S3 buckets storing customer files use server-side encryption with AWS KMS. Database backups are automatically encrypted using the same AWS KMS keys. Key rotation is performed automatically every 365 days."

Output:
<encryption_at_rest>
<stores>
  <store>
    <type>database</type>
    <name>PostgreSQL production database</name>
    <encrypted>yes</encrypted>
    <algorithm>aes_256</algorithm>
    <key_mgmt>aws_kms</key_mgmt>
  </store>
  <store>
    <type>file_storage</type>
    <name>S3 customer files</name>
    <encrypted>yes</encrypted>
    <algorithm>aes_256</algorithm>
    <key_mgmt>aws_kms</key_mgmt>
  </store>
  <store>
    <type>backups</type>
    <name>Database backups</name>
    <encrypted>yes</encrypted>
    <algorithm>aes_256</algorithm>
    <key_mgmt>aws_kms</key_mgmt>
  </store>
</stores>
<key_rotation>yes</key_rotation>
<rotation_days>365</rotation_days>
<fips_compliant>unknown</fips_compliant>
</encryption_at_rest>

Example 2 - From trust center:
Input: "Data Security: We take data security seriously. All data stored in our MongoDB databases is encrypted using industry-standard encryption. Our file storage uses Azure Blob Storage with encryption enabled. We use Azure Key Vault for managing encryption keys."

Output:
<encryption_at_rest>
<stores>
  <store>
    <type>database</type>
    <name>MongoDB databases</name>
    <encrypted>yes</encrypted>
    <algorithm>aes_256</algorithm>
    <key_mgmt>azure_key_vault</key_mgmt>
  </store>
  <store>
    <type>file_storage</type>
    <name>Azure Blob Storage</name>
    <encrypted>yes</encrypted>
    <algorithm>aes_256</algorithm>
    <key_mgmt>azure_key_vault</key_mgmt>
  </store>
  <store>
    <type>backups</type>
    <name>none</name>
    <encrypted>unknown</encrypted>
    <algorithm>none</algorithm>
    <key_mgmt>none</key_mgmt>
  </store>
</stores>
<key_rotation>unknown</key_rotation>
<rotation_days>none</rotation_days>
<fips_compliant>unknown</fips_compliant>
</encryption_at_rest>

Example 3 - Missing encryption information:
Input: "Our platform stores customer data in a MySQL database. We follow security best practices and have implemented multiple layers of protection."

Output:
<encryption_at_rest>
<stores>
  <store>
    <type>database</type>
    <name>MySQL database</name>
    <encrypted>unknown</encrypted>
    <algorithm>none</algorithm>
    <key_mgmt>none</key_mgmt>
  </store>
  <store>
    <type>file_storage</type>
    <name>none</name>
    <encrypted>unknown</encrypted>
    <algorithm>none</algorithm>
    <key_mgmt>none</key_mgmt>
  </store>
  <store>
    <type>backups</type>
    <name>none</name>
    <encrypted>unknown</encrypted>
    <algorithm>none</algorithm>
    <key_mgmt>none</key_mgmt>
  </store>
</stores>
<key_rotation>unknown</key_rotation>
<rotation_days>none</rotation_days>
<fips_compliant>unknown</fips_compliant>
</encryption_at_rest>

EXTRACTION RULES:
- Always include all 3 critical store types: database, file_storage, backups
- encrypted: "yes" if explicitly mentioned, "no" if explicitly disabled, "unknown" if not mentioned
- algorithm: Extract specific algorithm (aes_256, aes_128, rsa_2048, rsa_4096) or "none" if not mentioned
- key_mgmt: aws_kms, azure_key_vault, gcp_kms, hsm, internal_kms, third_party_kms, or "none"
- Infer reasonable defaults: If "AWS" mentioned assume aws_kms; if "Azure" assume azure_key_vault
- key_rotation: "yes", "no", or "unknown"
- rotation_days: Numeric value or "none"
- fips_compliant: "yes", "no", or "unknown"
"""

LOGGING_CONFIG_EXAMPLES = """
Extract Logging Configuration evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Trust center websites
- Security documentation
- Vendor email responses
- Policy documents

Look for evidence of:
- Log retention period (ASSURE requires >= 1 year)
- Types of logs collected (security, access, audit, application, system, database)
- SIEM or monitoring tool in use
- Log immutability/tamper-proofing
- Centralized logging implementation

IMPORTANT: Output must use XML format with nested log types.

TRAINING EXAMPLES:

Example 1 - Complete logging setup from SOC 2 report:
Input: "Control CC7.2: System Monitoring. The organization maintains comprehensive logging across all production systems. Security logs, access logs, audit logs, application logs, and system logs are collected centrally using Splunk. All logs are retained for a minimum of 1 year. Logs are stored in write-once storage to ensure immutability and prevent tampering. Automated alerts are configured in Splunk for security events including authentication failures, privilege escalations, and unauthorized access attempts."

Output:
<logging_config>
<retention_period>1_year</retention_period>
<log_types>
  <type>security</type>
  <type>access</type>
  <type>audit</type>
  <type>application</type>
  <type>system</type>
</log_types>
<monitoring_tool>splunk</monitoring_tool>
<logs_immutable>yes</logs_immutable>
<centralized_logging>yes</centralized_logging>
</logging_config>

Example 2 - Partial implementation from trust center:
Input: "Logging & Monitoring: We collect application logs and access logs from all services. Logs are stored in AWS CloudWatch and retained for 90 days. We are working on extending our retention period to meet compliance requirements."

Output:
<logging_config>
<retention_period>90_days</retention_period>
<log_types>
  <type>application</type>
  <type>access</type>
</log_types>
<monitoring_tool>cloudwatch</monitoring_tool>
<logs_immutable>unknown</logs_immutable>
<centralized_logging>yes</centralized_logging>
</logging_config>

Example 3 - Insufficient retention from email:
Input: "RE: Logging question - We log all security events and audit trails using Datadog. Our standard retention is 30 days for all log types. Database query logs are collected separately. All logs are centralized in our Datadog instance."

Output:
<logging_config>
<retention_period>30_days</retention_period>
<log_types>
  <type>security</type>
  <type>audit</type>
  <type>database</type>
</log_types>
<monitoring_tool>datadog</monitoring_tool>
<logs_immutable>no</logs_immutable>
<centralized_logging>yes</centralized_logging>
</logging_config>

EXTRACTION RULES:
- retention_period: Must be exactly "30_days", "90_days", "1_year", "2_years", "7_years", or "indefinite"
  * Convert variations: "12 months" → 1_year, "365 days" → 1_year, "1 year" → 1_year
  * Convert variations: "2 years" → 2_years, "730 days" → 2_years
  * Convert variations: "7 years" → 7_years, "permanent" → indefinite
- log_types: Include all <type> elements mentioned. Types must be exactly:
  * "security" (security events, intrusion detection, threat detection)
  * "access" (authentication, authorization, login/logout, user access)
  * "audit" (audit trail, data changes, configuration changes, compliance audit)
  * "application" (application-level logs, errors, transactions)
  * "system" (OS logs, infrastructure logs, system events)
  * "database" (database queries, data access, DB audit logs)
- monitoring_tool: Must be exactly "splunk", "datadog", "elk", "cloudwatch", "sentinel", "sumo_logic", or "other"
  * Convert variations: "ELK Stack" → elk, "Elastic" → elk, "Elasticsearch" → elk
  * Convert variations: "AWS CloudWatch" → cloudwatch, "Amazon CloudWatch" → cloudwatch
  * Convert variations: "Microsoft Sentinel" → sentinel, "Azure Sentinel" → sentinel
  * Convert variations: "Sumo Logic" → sumo_logic
- logs_immutable: "yes" if write-once storage, immutable storage, or tamper-proof mentioned
- logs_immutable: "no" if explicitly mutable or no protections mentioned
- logs_immutable: "unknown" if not mentioned
- centralized_logging: "yes" if logs aggregated/centralized/collected in single system
- centralized_logging: "no" if distributed/separate logging mentioned
- centralized_logging: "unknown" if not mentioned
"""

ENCRYPTION_IN_TRANSIT_EXAMPLES = """
Extract Encryption in Transit evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Qualys SSL Labs reports
- Trust center websites
- Security documentation
- Network security assessments

Look for evidence of:
- TLS versions supported (TLS 1.3, TLS 1.2)
- Weak/deprecated protocols blocked (TLS 1.1, TLS 1.0, SSL v3, SSL v2)
- Certificate authority and expiration
- Additional security features (Qualys grade, forward secrecy)

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - From Qualys SSL Labs report with full security:
Input: "SSL/TLS Configuration Assessment. The target server supports TLS 1.3 and TLS 1.2 protocols. All weak protocols have been explicitly disabled: TLS 1.1, TLS 1.0, SSL 3.0, and SSL 2.0 are not supported. The server uses a valid certificate issued by Let's Encrypt, expiring on December 15, 2025. Qualys SSL Labs grade: A. Forward secrecy is supported with all major browsers."

Output:
<encryption_in_transit>
<tls_versions>
  <version>tls_1_3</version>
  <version>tls_1_2</version>
</tls_versions>
<weak_blocked>
  <protocol>tls_1_1</protocol>
  <protocol>tls_1_0</protocol>
  <protocol>ssl_v3</protocol>
  <protocol>ssl_v2</protocol>
</weak_blocked>
<cert_authority>letsencrypt</cert_authority>
<cert_expiry>2025-12-15</cert_expiry>
<qualys_grade>A</qualys_grade>
<forward_secrecy>yes</forward_secrecy>
</encryption_in_transit>

Example 2 - From SOC 2 report with partial information:
Input: "Control CC6.7: Data in Transit Encryption. All customer data transmitted over public networks is encrypted using TLS 1.2 or higher. The organization has disabled support for legacy protocols including SSL v3 and SSL v2 across all production systems. SSL certificates are issued by DigiCert and are monitored for expiration."

Output:
<encryption_in_transit>
<tls_versions>
  <version>tls_1_2</version>
</tls_versions>
<weak_blocked>
  <protocol>ssl_v3</protocol>
  <protocol>ssl_v2</protocol>
</weak_blocked>
<cert_authority>digicert</cert_authority>
<cert_expiry>unknown</cert_expiry>
<qualys_grade>unknown</qualys_grade>
<forward_secrecy>unknown</forward_secrecy>
</encryption_in_transit>

Example 3 - Missing critical protocol blocking information:
Input: "Network Security: Our platform uses industry-standard TLS encryption for all data in transit. We maintain valid SSL certificates issued by Sectigo. Our security team regularly reviews and updates our encryption configuration."

Output:
<encryption_in_transit>
<tls_versions>
  <version>tls_1_2</version>
</tls_versions>
<weak_blocked>
</weak_blocked>
<cert_authority>sectigo</cert_authority>
<cert_expiry>unknown</cert_expiry>
<qualys_grade>unknown</qualys_grade>
<forward_secrecy>unknown</forward_secrecy>
</encryption_in_transit>

EXTRACTION RULES:
- tls_versions: Must be exactly "tls_1_3" or "tls_1_2" (extract only supported modern versions)
- weak_blocked: Must be exactly "tls_1_1", "tls_1_0", "ssl_v3", "ssl_v2" (extract only explicitly blocked protocols)
- If text says "disabled legacy protocols" or "deprecated protocols disabled", include all 4 weak protocols
- cert_authority: letsencrypt, digicert, comodo, globalsign, sectigo, internal, other, or "unknown"
  * "Let's Encrypt" → letsencrypt
  * "DigiCert" → digicert
  * "Comodo" → comodo
  * "Sectigo" → sectigo
  * "self-signed" or "internal CA" → internal
- cert_expiry: YYYY-MM-DD format or "unknown" if not mentioned
- qualys_grade: A+, A, B, C, D, F, or "unknown"
- forward_secrecy: "yes", "no", or "unknown"
- If "TLS" or "SSL encryption" mentioned without version, assume tls_1_2 as minimum
- If NO encryption in transit evidence found in text, return all fields as "unknown" or empty arrays
"""

INCIDENT_RESPONSE_EXAMPLES = """
Extract Incident Response (IR) plan evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2, ISO 27001, etc.)
- Trust center websites
- Vendor email responses
- Policy documents
- Security questionnaire responses

Look for evidence of:
- Whether an incident response plan exists
- When the plan was last tested
- Type of test conducted (tabletop, walkthrough, simulation, live drill)
- What incident types are covered (security breach, privacy breach, availability, data integrity, ransomware)
- Notification SLAs for different incident types
- Whether lessons learned are documented
- Whether plan is accessible to employees

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - Complete IR evidence from SOC 2 report:
Input: "Control CC2.2: Incident Response Management. The organization maintains a documented incident response plan that covers security incidents, data breaches, ransomware attacks, and availability issues. The plan was last tested via tabletop exercise on June 15, 2025. The test included all relevant stakeholders and lessons learned were documented in the post-exercise report. The plan requires notification within 24 hours for security incidents and 72 hours for privacy/data breaches. The IR plan is available to all employees via the internal security portal."

Output:
<incident_response>
<plan_exists>yes</plan_exists>
<last_test_date>2025-06-15</last_test_date>
<test_type>tabletop</test_type>
<incident_types_covered>
  <type>security_breach</type>
  <type>privacy_breach</type>
  <type>ransomware</type>
  <type>availability</type>
</incident_types_covered>
<security_breach_sla>24_hours</security_breach_sla>
<privacy_breach_sla>72_hours</privacy_breach_sla>
<lessons_learned_documented>yes</lessons_learned_documented>
<plan_accessible_to_employees>yes</plan_accessible_to_employees>
</incident_response>

Example 2 - IR plan exists but not tested recently (should fail compliance):
Input: "We have an incident response plan that was created in 2022 and covers various security scenarios including data breaches and system outages. The plan defines notification requirements for different incident types. However, we have not conducted a formal test or exercise of the plan yet."

Output:
<incident_response>
<plan_exists>yes</plan_exists>
<last_test_date>null</last_test_date>
<test_type>none</test_type>
<incident_types_covered>
  <type>security_breach</type>
  <type>privacy_breach</type>
  <type>availability</type>
</incident_types_covered>
<security_breach_sla>null</security_breach_sla>
<privacy_breach_sla>null</privacy_breach_sla>
<lessons_learned_documented>no</lessons_learned_documented>
<plan_accessible_to_employees>unknown</plan_accessible_to_employees>
</incident_response>

Example 3 - Partial IR evidence (missing critical SLAs):
Input: "Incident Management: Our security team follows an incident response process that includes identification, containment, and recovery. We conducted a simulation exercise in March 2025 to test our response to a ransomware scenario. The simulation identified several areas for improvement. Our plan covers security incidents, privacy incidents, ransomware, and data integrity issues."

Output:
<incident_response>
<plan_exists>yes</plan_exists>
<last_test_date>2025-03-15</last_test_date>
<test_type>simulation</test_type>
<incident_types_covered>
  <type>security_breach</type>
  <type>privacy_breach</type>
  <type>ransomware</type>
  <type>data_integrity</type>
</incident_types_covered>
<security_breach_sla>none</security_breach_sla>
<privacy_breach_sla>none</privacy_breach_sla>
<lessons_learned_documented>yes</lessons_learned_documented>
<plan_accessible_to_employees>unknown</plan_accessible_to_employees>
</incident_response>

EXTRACTION RULES:
- plan_exists: "yes" if plan is documented/mentioned, "no" if explicitly stated no plan exists
- last_test_date: YYYY-MM-DD format. Convert fuzzy dates:
  * "Q2 2025" → 2025-06-30 (end of quarter)
  * "March 2025" → 2025-03-15 (mid-month if not specified)
  * "2024" → 2024-12-31 (end of year)
  * null if no test ever conducted
- test_type: Must be exactly "tabletop", "walkthrough", "simulation", "live_drill", or "none"
- incident_types_covered: Array of incident types. Map variations:
  * "data breach", "privacy incident", "PII breach" → privacy_breach
  * "security incident", "cyberattack", "intrusion" → security_breach
  * "system outage", "downtime", "service disruption" → availability
  * "data corruption", "integrity issue" → data_integrity
  * "ransomware attack", "crypto attack" → ransomware
- security_breach_sla: Must be exactly "immediate", "1_hour", "4_hours", "24_hours", "72_hours", or "none"
  * "within 24 hours" → 24_hours
  * "within 1 day" → 24_hours
  * "within 72 hours" → 72_hours
  * "within 3 days" → 72_hours
  * "immediately" → immediate
  * null or not mentioned → none
- privacy_breach_sla: Same format as security_breach_sla
- lessons_learned_documented: "yes" if explicitly mentioned, "no" if explicitly not done, "unknown" if unclear
- plan_accessible_to_employees: "yes" if mentioned employees have access, "no" if restricted, "unknown" if not mentioned
- If NO incident response evidence found in text, return null for all fields

Output format: Wrap all fields in <incident_response></incident_response> tags as shown above.
"""


PRODUCTION_ACCESS_EXAMPLES = """
Extract Production Access Controls evidence from ANY text source.

This extractor works with:
- Compliance reports (SOC 2 CC5.2, CC6.1)
- Trust center websites
- Security policy documents
- Access control documentation
- Infrastructure security descriptions

Look for evidence of:
- JIT (just-in-time) access mechanisms
- Default access levels (should be "none" for least privilege)
- MFA requirements for privileged access
- Session duration and expiration policies
- Whether persistent production access is allowed
- Segregation of privileged accounts

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - JIT with bastion (COMPLIANT):
Input: "Control CC6.1: Logical Access - Production Access Controls. The organization implements just-in-time (JIT) access for all production systems. Engineers must request time-limited access through our internal system, which grants temporary credentials via a bastion host. Default access to production is 'none' - all access must be explicitly requested and approved. Multi-factor authentication is mandatory for all privileged access. Session duration is limited to 4 hours maximum, after which credentials automatically expire. All privileged accounts are segregated from standard user accounts and require separate authentication. No persistent production access is granted to any personnel."

Output:
<production_access>
<access_method>jit</access_method>
<default_access>none</default_access>
<mfa_required>yes</mfa_required>
<max_session_duration>4_hours</max_session_duration>
<persistent_access_allowed>no</persistent_access_allowed>
<privileged_accounts_segregated>yes</privileged_accounts_segregated>
</production_access>

Example 2 - Persistent admin access (NON-COMPLIANT):
Input: "Infrastructure Access: Our DevOps team has direct SSH access to production servers using their personal credentials. Senior engineers have persistent administrative privileges. We use VPN for remote access. Multi-factor authentication is optional for administrative users. Production systems are accessible 24/7 without session timeouts."

Output:
<production_access>
<access_method>direct</access_method>
<default_access>vpn</default_access>
<mfa_required>no</mfa_required>
<max_session_duration>persistent</max_session_duration>
<persistent_access_allowed>yes</persistent_access_allowed>
<privileged_accounts_segregated>no</privileged_accounts_segregated>
</production_access>

Example 3 - Missing access controls (NON-COMPLIANT):
Input: "Security Practices: We follow industry best practices for system access. Our team uses secure methods to access infrastructure when needed. Administrative functions are limited to authorized personnel."

Output:
<production_access>
<access_method>direct</access_method>
<default_access>direct</default_access>
<mfa_required>unknown</mfa_required>
<max_session_duration>persistent</max_session_duration>
<persistent_access_allowed>unknown</persistent_access_allowed>
<privileged_accounts_segregated>unknown</privileged_accounts_segregated>
</production_access>

EXTRACTION RULES:
- access_method: Must be exactly "jit", "bastion", "vpn", "direct", or "none"
  * "jit" or "just-in-time" → jit
  * "bastion", "jump box", "jump host" → bastion
  * "vpn" or "virtual private network" → vpn
  * "direct", "ssh", "rdp" → direct
  * "no access by default" → none
- default_access: Same values as access_method (prefer "none" for compliant systems)
- mfa_required: "yes", "no", or "unknown"
  * "required", "mandatory", "enforced" → yes
  * "optional", "not required" → no
  * Not mentioned → unknown
- max_session_duration: Must be exactly "15_min", "30_min", "1_hour", "4_hours", "8_hours", or "persistent"
  * "15 minutes" or "15min" → 15_min
  * "30 minutes" or "30min" → 30_min
  * "1 hour" or "60 minutes" → 1_hour
  * "4 hours" → 4_hours
  * "8 hours" → 8_hours
  * "no timeout", "24/7", "persistent", "permanent" → persistent
- persistent_access_allowed: "yes", "no", or "unknown"
  * "persistent", "permanent", "always available" → yes
  * "temporary", "time-limited", "expires" → no
  * Not mentioned → unknown
- privileged_accounts_segregated: "yes", "no", or "unknown"
  * "segregated", "separated", "distinct accounts" → yes
  * "shared", "same accounts" → no
  * Not mentioned → unknown
- If NO production access evidence found, default to "direct" access with "persistent" duration
- Convert fuzzy descriptions to specific enum values

Output format: Wrap all fields in <production_access></production_access> tags as shown above.
"""

BACKUP_CONFIGURATION_EXAMPLES = """
Extract Backup Configuration evidence from ANY text source.

This extractor works with:
- SOC 2 reports (availability criteria)
- Disaster recovery documentation
- Trust center pages
- Vendor questionnaire responses
- Email responses about backup practices

Look for:
- Backup frequency (how often backups run)
- Retention period (how long backups are kept)
- Last backup test date and results
- Backup scope (what is backed up)
- Backup storage location
- Encryption of backups

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Backup Configuration: Customer databases are backed up daily at 2 AM UTC with automated snapshots. Backups are retained for 90 days and stored in AWS S3 in a different region than production (us-west-2 for backups, us-east-1 for production). All backups are encrypted using AES-256. The most recent backup restoration test was performed on September 15, 2024 and was successful. Backup monitoring alerts are configured to notify the operations team of any failures."

Output:
<backup>
- frequency: daily
- schedule: 2 AM UTC daily
- retention_days: 90
- last_test_date: 2024-09-15
- test_result: successful
- scope: customer databases
- storage_location: different_region
- encrypted: yes
- automated: yes
- monitoring: yes
</backup>

Example 2 - From email response:
Input: "We back up everything every 6 hours to Azure Blob Storage. We keep backups for 30 days. Last time we tested a restore was in Q2 2024 and it worked fine. Backups are encrypted at rest."

Output:
<backup>
- frequency: every_6_hours
- schedule: every 6 hours
- retention_days: 30
- last_test_date: 2024-06-30
- test_result: successful
- scope: all customer data
- storage_location: different_cloud
- encrypted: yes
- automated: yes
- monitoring: unknown
</backup>

Example 3 - From trust center (gaps identified):
Input: "We perform weekly full backups on Sundays. Backups are kept for 60 days in the same datacenter as production. Our last backup test in January 2024 had some issues - we were able to restore most data but some configuration files were missing."

Output:
<backup>
- frequency: weekly
- schedule: Sunday weekly
- retention_days: 60
- last_test_date: 2024-01-31
- test_result: partial_success
- scope: full system backup
- storage_location: same_region
- encrypted: unknown
- automated: yes
- monitoring: unknown
</backup>

EXTRACTION RULES:
- frequency: Must be "continuous", "hourly", "every_6_hours", "every_12_hours", "daily", "weekly", or "monthly"
- retention_days: Extract number (e.g., "90 days" → 90, "3 months" → 90)
- last_test_date: YYYY-MM-DD format (convert "Q2 2024" → 2024-06-30)
- test_result: Must be "successful", "partial_success", "failed", or "not_tested"
- storage_location: Must be "same_region", "different_region", "different_cloud", "on_premises", or "hybrid"
- encrypted: "yes", "no", or "unknown"
- automated: "yes" or "no"
- monitoring: "yes", "no", or "unknown"

Output format: Wrap all fields in <backup></backup> tags.
"""

ACCESS_REVIEWS_EXAMPLES = """
Extract Access Reviews evidence from ANY text source.

This extractor works with:
- SOC 2 reports (logical access controls)
- ISO 27001 certifications
- Access governance documentation
- Security questionnaire responses
- Email about access review processes

Look for:
- When the last access review was performed
- How often reviews occur (frequency)
- What systems/accounts were reviewed
- How many users/accounts were reviewed
- How many access rights were revoked or modified
- Whether management approved the review

IMPORTANT: Output must use XML format.

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "User Access Review: The organization conducts quarterly access reviews covering all user accounts across production systems. The most recent review was performed on August 20, 2024 and covered 247 user accounts across AWS, GitHub, and production databases. The review identified 12 accounts with excessive permissions, which were downgraded, and 5 terminated user accounts that were deactivated. Reviews are approved by the VP of Engineering. Inappropriate access is remediated within 7 days."

Output:
<access_review>
- last_review_date: 2024-08-20
- frequency: quarterly
- scope: all_users_all_systems
- systems: AWS, GitHub, production databases
- users_reviewed: 247
- privileged_users_reviewed: unknown
- access_revoked: 5
- access_reduced: 12
- management_approved: yes
- remediation_deadline_days: 7
- automated_tools: unknown
</access_review>

Example 2 - From trust center:
Input: "We review admin access monthly. Last review was in September 2024. We checked 34 admin accounts and removed access for 2 people who changed roles."

Output:
<access_review>
- last_review_date: 2024-09-30
- frequency: monthly
- scope: privileged_access_only
- systems: administrative systems
- users_reviewed: 34
- privileged_users_reviewed: 34
- access_revoked: 2
- access_reduced: 0
- management_approved: unknown
- remediation_deadline_days: unknown
- automated_tools: no
</access_review>

Example 3 - From ISO 27001 certification:
Input: "Access rights are reviewed semi-annually. The June 2024 review covered all 450 employees across production, staging, and internal systems. Review utilized SailPoint IGA platform. Management sign-off received from CISO. 8 access rights revoked, 15 modified. Remediation within 30 days."

Output:
<access_review>
- last_review_date: 2024-06-30
- frequency: semi_annual
- scope: all_users_all_systems
- systems: production, staging, internal systems
- users_reviewed: 450
- privileged_users_reviewed: unknown
- access_revoked: 8
- access_reduced: 15
- management_approved: yes
- remediation_deadline_days: 30
- automated_tools: yes
</access_review>

EXTRACTION RULES:
- frequency: Must be "monthly", "quarterly", "semi_annual", "annual", or "ad_hoc"
- scope: Must be "all_users_all_systems", "privileged_access_only", "production_systems_only", "high_risk_systems", or "custom"
- last_review_date: YYYY-MM-DD (convert "Q3 2024" → 2024-09-30, "September 2024" → 2024-09-30)
- users_reviewed: Extract number
- access_revoked: Number of accounts fully removed
- access_reduced: Number of permissions downgraded
- management_approved: "yes", "no", or "unknown"
- automated_tools: "yes" if IGA tools mentioned (SailPoint, Okta, etc.), otherwise "no" or "unknown"

Output format: Wrap all fields in <access_review></access_review> tags.
"""

SECURITY_ALERTS_EXAMPLES = """
Extract Security Alerts Configuration evidence from ANY text source.

This extractor works with:
- SOC 2 reports (monitoring controls)
- Security monitoring documentation
- SIEM configuration details
- Incident response procedures
- Trust center pages

Look for:
- Types of security alerts configured (failed auth, privilege escalation, etc.)
- 24/7 monitoring coverage
- Alert severity levels and response SLAs
- Notification channels (email, PagerDuty, etc.)
- Integration with SIEM systems

IMPORTANT: Output must use XML format with nested structure.

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Security Monitoring: The organization maintains 24/7 security monitoring with the following automated alerts configured: (1) Failed authentication attempts - 5 failures in 10 minutes triggers HIGH severity alert via PagerDuty and email, 1-hour response SLA. (2) Privilege escalation - Any elevation to admin triggers CRITICAL alert via PagerDuty with 15-minute response SLA. (3) Configuration changes to security groups trigger MEDIUM alert via Slack with 4-hour response SLA. All alerts integrated with Splunk SIEM. Incident response plan documented and tested quarterly. Escalation process includes on-call engineer → security lead → CISO."

Output:
<security_alerts>
  <alerts>
    <alert>
    - type: failed_authentication
    - enabled: yes
    - severity: high
    - threshold: 5 failures in 10 minutes
    - channels: pagerduty, email
    - response_sla_hours: 1
    </alert>
    <alert>
    - type: privilege_escalation
    - enabled: yes
    - severity: critical
    - threshold: any elevation to admin
    - channels: pagerduty
    - response_sla_hours: 0.25
    </alert>
    <alert>
    - type: configuration_change
    - enabled: yes
    - severity: medium
    - threshold: security group changes
    - channels: slack
    - response_sla_hours: 4
    </alert>
  </alerts>
  <monitoring>
  - coverage: 24/7
  - team_size: unknown
  - incident_response_plan: yes
  - escalation_defined: yes
  - siem_integrated: yes
  - siem_platform: Splunk
  </monitoring>
</security_alerts>

Example 2 - From trust center:
Input: "We monitor for failed logins, unauthorized access attempts, and malware. Alerts go to our security team via email and are checked during business hours. We use Datadog for monitoring."

Output:
<security_alerts>
  <alerts>
    <alert>
    - type: failed_authentication
    - enabled: yes
    - severity: medium
    - threshold: unknown
    - channels: email
    - response_sla_hours: unknown
    </alert>
    <alert>
    - type: unauthorized_access
    - enabled: yes
    - severity: high
    - threshold: unknown
    - channels: email
    - response_sla_hours: unknown
    </alert>
    <alert>
    - type: malware_detection
    - enabled: yes
    - severity: high
    - threshold: unknown
    - channels: email
    - response_sla_hours: unknown
    </alert>
  </alerts>
  <monitoring>
  - coverage: business_hours
  - team_size: unknown
  - incident_response_plan: unknown
  - escalation_defined: unknown
  - siem_integrated: yes
  - siem_platform: Datadog
  </monitoring>
</security_alerts>

EXTRACTION RULES:
- alert type: Must be "failed_authentication", "privilege_escalation", "unauthorized_access", "data_exfiltration", "configuration_change", "malware_detection", "intrusion_attempt", "account_lockout", "sensitive_data_access", or "system_resource_anomaly"
- severity: Must be "critical", "high", "medium", "low", or "informational"
- channels: Can be "email", "sms", "pagerduty", "slack", "teams", "siem", "webhook", "phone_call"
- coverage: Must be "24/7", "business_hours", "extended_hours", "weekdays_only", or "automated_only"
- response_sla_hours: Extract as number (e.g., "15 minutes" → 0.25, "1 hour" → 1, "4 hours" → 4)

Output format: Wrap in <security_alerts></security_alerts> tags with nested <alerts> and <monitoring> sections.
"""

DATA_MAPPING_EXAMPLES = """
Extract Data Mapping & Subprocessors evidence from ANY text source.

This extractor works with:
- SOC 2 reports (system descriptions)
- Privacy policies / Data Processing Addendums
- Subprocessor lists
- Data flow diagrams
- GDPR documentation

Look for:
- Data mapping documentation and last update
- Subprocessors (third parties with data access)
- Data Processing Agreements (DPAs)
- Types of data processed (PII, financial, health, etc.)
- Geographic data storage locations
- Data retention periods
- SBOM (Software Bill of Materials) availability

IMPORTANT: Output must use XML format with nested structures.

TRAINING EXAMPLES:

Example 1 - From SOC 2 system description:
Input: "Data Mapping: The organization maintains comprehensive data mapping documentation, last updated March 2024 and reviewed by legal counsel. Customer PII (names, emails) is collected via registration forms and stored in PostgreSQL database in AWS us-east-1, encrypted at rest and in transit, retained for 7 years. Financial data (credit cards) is tokenized and stored via Stripe (payment processor, SOC 2 certified, DPA in place). Subprocessors: (1) AWS - cloud infrastructure, access to all data categories, us-east-1 location, SOC 2 certified, DPA executed. (2) Datadog - analytics/monitoring, access to telemetry only, multi-region, SOC 2 certified, DPA executed. (3) SendGrid - email delivery, access to PII for transactional emails, US location, SOC 2 certified, DPA executed. GDPR Article 28 compliant. Data subject rights (access, deletion, portability) supported. SBOM available in CycloneDX format, updated quarterly."

Output:
<data_mapping>
  <attestation>
  - last_updated: 2024-03-31
  - document_exists: yes
  - legal_reviewed: yes
  - gdpr_article_28: yes
  - data_subject_rights: yes
  </attestation>

  <data_flows>
    <flow>
    - category: pii
    - sensitivity: highly_sensitive
    - source: registration forms
    - storage: PostgreSQL AWS us-east-1
    - region: us
    - retention_days: 2555
    - encrypted_at_rest: yes
    - encrypted_in_transit: yes
    </flow>
    <flow>
    - category: financial
    - sensitivity: highly_sensitive
    - source: payment API
    - storage: Stripe tokenized
    - region: us
    - retention_days: unknown
    - encrypted_at_rest: yes
    - encrypted_in_transit: yes
    </flow>
  </data_flows>

  <subprocessors>
    <subprocessor>
    - name: AWS
    - role: cloud_infrastructure
    - data_categories: pii, financial, telemetry, customer_content
    - location: us
    - contract: yes
    - soc2: yes
    - url: https://aws.amazon.com
    </subprocessor>
    <subprocessor>
    - name: Datadog
    - role: analytics
    - data_categories: telemetry
    - location: multi_region
    - contract: yes
    - soc2: yes
    - url: https://datadoghq.com
    </subprocessor>
    <subprocessor>
    - name: SendGrid
    - role: email_delivery
    - data_categories: pii
    - location: us
    - contract: yes
    - soc2: yes
    - url: https://sendgrid.com
    </subprocessor>
  </subprocessors>

  <sbom>
  - available: yes
  - format: CycloneDX
  - last_updated: 2024-09-30
  </sbom>
</data_mapping>

Example 2 - From privacy policy (minimal):
Input: "We use third-party services: Amazon Web Services for hosting and Mailchimp for marketing emails. Customer data is stored in US datacenters. We comply with GDPR and honor data subject requests."

Output:
<data_mapping>
  <attestation>
  - last_updated: unknown
  - document_exists: yes
  - legal_reviewed: unknown
  - gdpr_article_28: yes
  - data_subject_rights: yes
  </attestation>

  <data_flows>
    <flow>
    - category: customer_content
    - sensitivity: sensitive
    - source: application
    - storage: AWS US
    - region: us
    - retention_days: unknown
    - encrypted_at_rest: unknown
    - encrypted_in_transit: unknown
    </flow>
  </data_flows>

  <subprocessors>
    <subprocessor>
    - name: Amazon Web Services
    - role: cloud_infrastructure
    - data_categories: customer_content
    - location: us
    - contract: unknown
    - soc2: unknown
    - url: https://aws.amazon.com
    </subprocessor>
    <subprocessor>
    - name: Mailchimp
    - role: email_delivery
    - data_categories: pii
    - location: us
    - contract: unknown
    - soc2: unknown
    - url: https://mailchimp.com
    </subprocessor>
  </subprocessors>

  <sbom>
  - available: no
  - format: unknown
  - last_updated: unknown
  </sbom>
</data_mapping>

EXTRACTION RULES:
- data category: Must be "pii", "financial", "health", "credentials", "telemetry", "customer_content", "metadata", or "public"
- sensitivity: Must be "highly_sensitive", "sensitive", "internal", or "public"
- region: Must be "us", "eu", "uk", "apac", "canada", "australia", "multi_region", or "global"
- subprocessor role: Must be "cloud_infrastructure", "database_hosting", "cdn", "analytics", "customer_support", "email_delivery", "payment_processing", "authentication", "backup_storage", or "security_scanning"
- retention_days: Extract number ("7 years" → 2555, "90 days" → 90)
- Convert fuzzy dates for last_updated ("Q1 2024" → 2024-03-31, "March 2024" → 2024-03-31)

Output format: Wrap in <data_mapping></data_mapping> with nested sections.
"""

ARCHITECTURE_EXAMPLES = """
Extract Architecture & Segmentation evidence from ANY text source.

This extractor works with:
- SOC 2 reports (system descriptions)
- Architecture documentation
- Network diagrams
- Security architecture reviews
- Infrastructure questionnaires

Look for:
- Network segmentation strategy
- Security zones (DMZ, application tier, database tier, etc.)
- Multi-tenancy isolation approach
- Cloud provider and regions
- Production vs non-production separation
- Firewall rules and default-deny policies
- Infrastructure components and their security zones

IMPORTANT: Output must use XML format with nested structures.

TRAINING EXAMPLES:

Example 1 - From SOC 2 system description:
Input: "System Architecture: The application is hosted on AWS in us-east-1 with VPC-based network segmentation. Architecture diagram maintained and updated Q1 2024. The environment uses the following security zones: (1) Public DMZ - Application Load Balancers only, internet-facing. (2) Application Tier - EC2 instances running application servers in private subnets, accessible only from ALB. (3) Database Tier - RDS PostgreSQL in isolated private subnets with no public access, accessible only from application tier. Production and non-production environments are in separate VPCs. All network segments have default-deny security group rules requiring explicit allow. Multi-tenancy uses logical isolation with separate database schemas per customer. Bastion host (jump box) required for administrative access. High availability configured with multi-AZ deployment. Disaster recovery region in us-west-2."

Output:
<architecture>
  <documentation>
  - diagram_available: yes
  - diagram_url: unknown
  - last_updated: 2024-Q1
  </documentation>

  <segmentation>
  - strategy: vpc_based
  - description: VPC-based segmentation with separate subnets for DMZ, application, and database tiers. Default-deny security groups.
  - multi_tenancy: shared_logical_isolation
  - tenant_isolation_tested: unknown
  </segmentation>

  <infrastructure>
  - provider: aws
  - high_availability: yes
  - dr_region: us-west-2
  - prod_nonprod_separated: yes
  - jump_box_required: yes
  - ids_ips_deployed: unknown
  </infrastructure>

  <segments>
    <segment>
    - name: Public DMZ
    - zone: public_dmz
    - inbound: public_internet
    - outbound: application_tier
    - firewall: yes
    - default_deny: yes
    </segment>
    <segment>
    - name: Application Tier
    - zone: application_tier
    - inbound: public_dmz
    - outbound: database_tier
    - firewall: yes
    - default_deny: yes
    </segment>
    <segment>
    - name: Database Tier
    - zone: database_tier
    - inbound: application_tier
    - outbound: backup_zone
    - firewall: yes
    - default_deny: yes
    </segment>
  </segments>

  <components>
    <component>
    - name: Application Load Balancer
    - type: load_balancer
    - zone: public_dmz
    - publicly_accessible: yes
    - data_classification: public
    - has_customer_data: no
    </component>
    <component>
    - name: Application Servers
    - type: api_server
    - zone: application_tier
    - publicly_accessible: no
    - data_classification: internal
    - has_customer_data: yes
    </component>
    <component>
    - name: PostgreSQL Database
    - type: database
    - zone: database_tier
    - publicly_accessible: no
    - data_classification: highly_sensitive
    - has_customer_data: yes
    </component>
  </components>
</architecture>

Example 2 - From trust center (basic):
Input: "We use Microsoft Azure for hosting. Production and development are in different resource groups. Our databases are not exposed to the internet. We use network security groups to control traffic."

Output:
<architecture>
  <documentation>
  - diagram_available: unknown
  - diagram_url: unknown
  - last_updated: unknown
  </documentation>

  <segmentation>
  - strategy: subnet_based
  - description: Azure resource groups with network security groups controlling traffic.
  - multi_tenancy: shared_logical_isolation
  - tenant_isolation_tested: no
  </segmentation>

  <infrastructure>
  - provider: azure
  - high_availability: unknown
  - dr_region: unknown
  - prod_nonprod_separated: yes
  - jump_box_required: unknown
  - ids_ips_deployed: unknown
  </infrastructure>

  <segments>
    <segment>
    - name: Production Resource Group
    - zone: application_tier
    - inbound: public_internet
    - outbound: database_tier
    - firewall: yes
    - default_deny: unknown
    </segment>
  </segments>

  <components>
    <component>
    - name: Database
    - type: database
    - zone: database_tier
    - publicly_accessible: no
    - data_classification: sensitive
    - has_customer_data: yes
    </component>
  </components>
</architecture>

EXTRACTION RULES:
- segmentation strategy: Must be "full_isolation", "vlan_based", "vpc_based", "subnet_based", "micro_segmentation", "zero_trust", or "flat_network"
- security zone: Must be "public_dmz", "application_tier", "database_tier", "management_zone", "customer_zone", "monitoring_zone", or "backup_zone"
- multi_tenancy: Must be "dedicated_infrastructure", "shared_logical_isolation", "containerized", "database_schemas", "hybrid", or "single_tenant"
- cloud provider: Must be "aws", "azure", "gcp", "alibaba_cloud", "oracle_cloud", "on_premises", "hybrid_cloud", or "multi_cloud"
- Convert fuzzy dates ("Q1 2024" → "2024-Q1", "January 2024" → "2024-01")

Output format: Wrap in <architecture></architecture> with nested sections.
"""


# =============================================================================
# BATCH 3: TECHNICAL ACCESS & CHANGE CONTROLS (6 evidence types)
# =============================================================================

ADMIN_2FA_EXAMPLES = """
Extract Admin 2FA evidence from ANY text source (SOC 2, security docs, emails, trust centers).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "All administrative accounts require multi-factor authentication (MFA) for access to production systems.
Island enforces MFA using YubiKey hardware tokens or biometric authentication for all infrastructure administrators.
As of June 2024, 100% of 47 administrative accounts have MFA enabled with no exceptions. MFA enforcement is
technically controlled through AWS IAM policies and cannot be disabled by individual users. Admin MFA compliance
is reviewed monthly by the Security team."

Output:
<admin_2fa>
- mfa_enforced: yes
- scope: all_admins
- scope_description: All administrative accounts including infrastructure, application, and production admins
- mfa_types: hardware_token, biometric
- phishing_resistant: yes
- technically_enforced: yes
- enforcement_mechanism: AWS IAM policies with conditional access
- exceptions_allowed: no
- exceptions_documented: no
- exception_count: 0
- review_frequency: monthly
- last_review: 2024-06
- total_admin_accounts: 47
- admin_accounts_with_mfa: 47
- extraction_confidence: 0.95
</admin_2fa>

Example 2 - From email/trust center:
Input: "Our security policy requires MFA for production access. Admin users can use Google Authenticator or SMS codes.
We have 3 emergency break-glass accounts that don't have MFA for disaster recovery purposes, which are documented
in our runbook."

Output:
<admin_2fa>
- mfa_enforced: yes
- scope: production_admins_only
- scope_description: Production environment administrators only
- mfa_types: authenticator_app, sms
- phishing_resistant: no
- technically_enforced: unknown
- enforcement_mechanism: Security policy requirement
- exceptions_allowed: yes
- exceptions_documented: yes
- exception_count: 3
- review_frequency: unknown
- last_review: unknown
- total_admin_accounts: unknown
- admin_accounts_with_mfa: unknown
- extraction_confidence: 0.70
</admin_2fa>

Example 3 - Non-compliant vendor:
Input: "Administrators are encouraged to enable two-factor authentication, but it's not mandatory for all accounts."

Output:
<admin_2fa>
- mfa_enforced: no
- scope: custom
- scope_description: Optional MFA for administrators
- mfa_types: authenticator_app
- phishing_resistant: no
- technically_enforced: no
- enforcement_mechanism: Not enforced, optional only
- exceptions_allowed: yes
- exceptions_documented: no
- exception_count: unknown
- review_frequency: unknown
- last_review: unknown
- total_admin_accounts: unknown
- admin_accounts_with_mfa: unknown
- extraction_confidence: 0.75
</admin_2fa>

EXTRACTION RULES:
- mfa_enforced: "yes" if required/enforced/mandatory, "no" if optional/encouraged/recommended
- scope: Must be "all_admins", "production_admins_only", "infrastructure_admins", "application_admins", or "custom"
- mfa_types: Can include multiple from: "authenticator_app", "sms", "email", "hardware_token", "push_notification", "biometric", "certificate_based"
- phishing_resistant: "yes" if hardware_token, biometric, or certificate_based available
- technically_enforced: "yes" if IAM/SSO/VPN enforced, "no" if just policy, "unknown" if unclear
- exceptions_allowed: "yes" if any accounts exempt from MFA
- exception_count: Extract number if mentioned (e.g., "3 break-glass accounts" → 3)
- review_frequency: Extract as "monthly", "quarterly", "annually" or verbatim
- last_review: Extract date (YYYY-MM-DD or YYYY-MM or YYYY-QN format)
- total_admin_accounts: Extract number if mentioned
- admin_accounts_with_mfa: Extract number if mentioned

Output format: Wrap in <admin_2fa></admin_2fa> tags.
"""

CODE_REVIEW_EXAMPLES = """
Extract Code Review evidence from ANY text source (SOC 2, development docs, GitHub policies).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "All production code changes require peer review before deployment. Island uses GitHub Enterprise with
branch protection rules requiring minimum 2 approvals from qualified reviewers. Security-focused code reviews
include SAST scanning (SonarQube), dependency vulnerability checks (Snyk), and manual security review for
authentication/authorization changes. Reviews are enforced at the technical level - direct commits to main branch
are blocked. Code reviewers must have 'Senior Engineer' or 'Security Engineer' role and complete annual secure
coding training. Average review turnaround is 4 hours."

Output:
<code_review>
- peer_review_required: yes
- review_tool: github
- technically_enforced: yes
- branch_protection: yes
- minimum_reviewers: 2
- security_checks_included: yes
- security_check_types: sast, dependency_scanning, manual_security_review
- reviewer_qualifications: senior_engineer, security_engineer, secure_coding_training
- automated_checks_block_merge: yes
- review_coverage_percentage: 100
- average_review_turnaround_hours: 4
- extraction_confidence: 0.95
</code_review>

Example 2 - From development documentation:
Input: "We use GitLab for code review. All merge requests need at least one approval before merging. We run
automated linting and unit tests in CI/CD pipeline."

Output:
<code_review>
- peer_review_required: yes
- review_tool: gitlab
- technically_enforced: yes
- branch_protection: yes
- minimum_reviewers: 1
- security_checks_included: yes
- security_check_types: linting, unit_tests
- reviewer_qualifications: developer
- automated_checks_block_merge: yes
- review_coverage_percentage: unknown
- average_review_turnaround_hours: unknown
- extraction_confidence: 0.75
</code_review>

Example 3 - Non-compliant vendor:
Input: "Developers review each other's code informally before deploying to production."

Output:
<code_review>
- peer_review_required: no
- review_tool: informal_process
- technically_enforced: no
- branch_protection: no
- minimum_reviewers: 0
- security_checks_included: no
- security_check_types: none
- reviewer_qualifications: developer
- automated_checks_block_merge: no
- review_coverage_percentage: unknown
- average_review_turnaround_hours: unknown
- extraction_confidence: 0.80
</code_review>

EXTRACTION RULES:
- peer_review_required: "yes" if mandatory/required/enforced, "no" if optional/informal
- review_tool: Must be "github", "gitlab", "bitbucket", "azure_devops", "gerrit", "phabricator", "informal_process", or "other"
- technically_enforced: "yes" if branch protection/blocking, "no" if policy-only
- branch_protection: "yes" if main/master branch protected from direct commits
- minimum_reviewers: Extract number (e.g., "2 approvals" → 2, "one approval" → 1)
- security_checks_included: "yes" if any security scanning mentioned
- security_check_types: Can include: "sast", "dast", "dependency_scanning", "secret_scanning", "linting", "unit_tests", "manual_security_review", "none"
- reviewer_qualifications: Can include: "senior_engineer", "security_engineer", "lead_developer", "architect", "secure_coding_training", "domain_expert", "developer"
- automated_checks_block_merge: "yes" if failures prevent merge
- review_coverage_percentage: Extract if mentioned (e.g., "100% of production code" → 100)

Output format: Wrap in <code_review></code_review> tags.
"""

PATCH_MANAGEMENT_EXAMPLES = """
Extract Patch Management evidence from ANY text source (SOC 2, vulnerability reports, IT policies).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Island maintains a documented patch management process for all production systems. Security patches are
classified by severity (Critical/High/Medium/Low) with defined SLAs: Critical patches within 7 days, High within
15 days, Medium within 30 days. Patching is performed monthly during scheduled maintenance windows on the second
Tuesday of each month. The most recent patching cycle was September 10, 2024, with 47 security patches applied
across production infrastructure. Automated patch deployment is enabled for non-critical patches using AWS Systems
Manager. Patch compliance is monitored using Qualys and reviewed weekly by the Security Operations team."

Output:
<patch_management>
- documented_process: yes
- patch_frequency: monthly
- critical_patch_sla: 7
- high_patch_sla: 15
- medium_patch_sla: 30
- last_patch_date: 2024-09-10
- automated_patching: yes
- automated_tool: aws_systems_manager
- patch_testing_environment: yes
- monitoring_enabled: yes
- monitoring_tool: qualys
- compliance_review_frequency: weekly
- patch_success_rate: unknown
- extraction_confidence: 0.95
</patch_management>

Example 2 - From IT policy document:
Input: "We patch servers quarterly following vendor recommendations. Critical security vulnerabilities are patched
within 30 days of disclosure. Last patching was in June 2024."

Output:
<patch_management>
- documented_process: yes
- patch_frequency: quarterly
- critical_patch_sla: 30
- high_patch_sla: unknown
- medium_patch_sla: unknown
- last_patch_date: 2024-06-30
- automated_patching: unknown
- automated_tool: unknown
- patch_testing_environment: unknown
- monitoring_enabled: unknown
- monitoring_tool: unknown
- compliance_review_frequency: unknown
- patch_success_rate: unknown
- extraction_confidence: 0.70
</patch_management>

Example 3 - Non-compliant vendor:
Input: "We apply security updates as they become available from vendors. Last major update was in January 2024."

Output:
<patch_management>
- documented_process: no
- patch_frequency: ad_hoc
- critical_patch_sla: unknown
- high_patch_sla: unknown
- medium_patch_sla: unknown
- last_patch_date: 2024-01-31
- automated_patching: no
- automated_tool: unknown
- patch_testing_environment: unknown
- monitoring_enabled: no
- monitoring_tool: unknown
- compliance_review_frequency: unknown
- patch_success_rate: unknown
- extraction_confidence: 0.75
</patch_management>

EXTRACTION RULES:
- documented_process: "yes" if formal policy/procedure mentioned, "no" if ad-hoc/informal
- patch_frequency: Must be "continuous", "weekly", "monthly", "quarterly", "annually", or "ad_hoc"
- critical_patch_sla: Extract days (e.g., "within 7 days" → 7, "one week" → 7)
- high_patch_sla: Extract days (e.g., "within 15 days" → 15)
- medium_patch_sla: Extract days (e.g., "within 30 days" → 30)
- last_patch_date: Extract date (YYYY-MM-DD format preferred, or YYYY-MM-DD from "June 2024" → "2024-06-30")
- automated_patching: "yes" if automation mentioned, "no" if manual, "unknown" if unclear
- automated_tool: Extract tool name (e.g., "AWS Systems Manager", "WSUS", "Ansible", "Chef")
- patch_testing_environment: "yes" if staging/test environment mentioned
- monitoring_enabled: "yes" if compliance monitoring mentioned
- monitoring_tool: Extract tool name (e.g., "Qualys", "Nessus", "Rapid7")
- compliance_review_frequency: Extract as "daily", "weekly", "monthly", "quarterly"

Output format: Wrap in <patch_management></patch_management> tags.
"""

SECURITY_TESTING_EXAMPLES = """
Extract Security Testing evidence from ANY text source (SOC 2, DevSecOps docs, AppSec reports).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Island integrates multiple security testing tools into the CI/CD pipeline. Static Application Security
Testing (SAST) is performed using SonarQube and Semgrep on every commit. Dynamic Application Security Testing (DAST)
scans run nightly using OWASP ZAP against staging environments. Software Composition Analysis (SCA) for dependency
vulnerabilities is performed using Snyk with automated PR creation for high-severity findings. Security tests must
pass before production deployment - builds fail if Critical or High severity vulnerabilities are detected. The
security testing program includes: 87% SAST coverage, 92% SCA coverage, DAST scans covering all public APIs.
Critical findings have 24-hour remediation SLA, High findings 7 days, Medium 30 days."

Output:
<security_testing>
- sast_enabled: yes
- sast_tools: sonarqube, semgrep
- dast_enabled: yes
- dast_tools: owasp_zap
- sca_enabled: yes
- sca_tools: snyk
- container_scanning_enabled: unknown
- container_scanning_tools: unknown
- ci_cd_integrated: yes
- automated_blocking: yes
- blocking_severity_threshold: high
- sast_coverage_percentage: 87
- dast_coverage_percentage: 100
- sca_coverage_percentage: 92
- critical_remediation_sla_days: 1
- high_remediation_sla_days: 7
- medium_remediation_sla_days: 30
- extraction_confidence: 0.95
</security_testing>

Example 2 - From DevSecOps documentation:
Input: "We use GitHub Advanced Security for code scanning (SAST) and Dependabot for dependency scanning (SCA).
Scans run on pull requests. Developers are notified of findings but can merge with vulnerabilities if needed."

Output:
<security_testing>
- sast_enabled: yes
- sast_tools: github_advanced_security
- dast_enabled: no
- dast_tools: none
- sca_enabled: yes
- sca_tools: dependabot
- container_scanning_enabled: unknown
- container_scanning_tools: unknown
- ci_cd_integrated: yes
- automated_blocking: no
- blocking_severity_threshold: none
- sast_coverage_percentage: unknown
- dast_coverage_percentage: 0
- sca_coverage_percentage: unknown
- critical_remediation_sla_days: unknown
- high_remediation_sla_days: unknown
- medium_remediation_sla_days: unknown
- extraction_confidence: 0.80
</security_testing>

Example 3 - Non-compliant vendor:
Input: "We perform annual penetration testing by a third-party security firm. Code is manually reviewed for security issues."

Output:
<security_testing>
- sast_enabled: no
- sast_tools: none
- dast_enabled: no
- dast_tools: none
- sca_enabled: no
- sca_tools: none
- container_scanning_enabled: no
- container_scanning_tools: none
- ci_cd_integrated: no
- automated_blocking: no
- blocking_severity_threshold: none
- sast_coverage_percentage: 0
- dast_coverage_percentage: 0
- sca_coverage_percentage: 0
- critical_remediation_sla_days: unknown
- high_remediation_sla_days: unknown
- medium_remediation_sla_days: unknown
- extraction_confidence: 0.85
</security_testing>

EXTRACTION RULES:
- sast_enabled: "yes" if static analysis mentioned, "no" otherwise
- sast_tools: Extract tool names (e.g., "SonarQube", "Semgrep", "Checkmarx", "Veracode", "GitHub Advanced Security", "none")
- dast_enabled: "yes" if dynamic scanning mentioned
- dast_tools: Extract tool names (e.g., "OWASP ZAP", "Burp Suite", "Acunetix", "none")
- sca_enabled: "yes" if dependency/composition analysis mentioned
- sca_tools: Extract tool names (e.g., "Snyk", "Dependabot", "WhiteSource", "Black Duck", "none")
- container_scanning_enabled: "yes" if container/image scanning mentioned
- container_scanning_tools: Extract tool names (e.g., "Trivy", "Clair", "Anchore", "none")
- ci_cd_integrated: "yes" if runs in pipeline/automated
- automated_blocking: "yes" if builds fail on findings
- blocking_severity_threshold: "critical", "high", "medium", "low", or "none"
- coverage_percentage: Extract numbers (e.g., "87% coverage" → 87)
- remediation_sla_days: Extract days (e.g., "24 hours" → 1, "7 days" → 7, "one month" → 30)

Output format: Wrap in <security_testing></security_testing> tags.
"""

NETWORK_ACL_EXAMPLES = """
Extract Network ACL evidence from ANY text source (SOC 2, network policies, infrastructure docs).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Island implements network-level access controls using AWS Security Groups and Network ACLs. All network
segments follow a default-deny policy requiring explicit allow rules for all traffic. Production network is
segmented into separate VPCs for application tier, database tier, and management systems. Network ACL rules are
documented in Terraform configuration files stored in version control. Changes to network rules require Security
Architecture team approval through Jira tickets. Network segmentation and ACL compliance is reviewed quarterly by
the Cloud Infrastructure team. Last review completed August 15, 2024. Automated monitoring alerts on any ACL
rule changes."

Output:
<network_acl>
- default_deny_policy: yes
- network_segmentation: yes
- segmentation_method: vpc_based
- acl_tool: aws_security_groups
- rules_documented: yes
- documentation_location: terraform_version_control
- change_approval_required: yes
- approval_authority: security_architecture_team
- review_frequency: quarterly
- last_review_date: 2024-08-15
- automated_monitoring: yes
- extraction_confidence: 0.95
</network_acl>

Example 2 - From infrastructure documentation:
Input: "We use firewall rules to control traffic between network zones. Rules are managed by the IT team and
reviewed annually. All inbound traffic from internet is blocked by default except for web servers on port 443."

Output:
<network_acl>
- default_deny_policy: yes
- network_segmentation: yes
- segmentation_method: firewall_zones
- acl_tool: firewall
- rules_documented: unknown
- documentation_location: unknown
- change_approval_required: unknown
- approval_authority: it_team
- review_frequency: annually
- last_review_date: unknown
- automated_monitoring: unknown
- extraction_confidence: 0.70
</network_acl>

Example 3 - Non-compliant vendor:
Input: "Network access is controlled through our firewall. The network team manages firewall rules as needed."

Output:
<network_acl>
- default_deny_policy: unknown
- network_segmentation: unknown
- segmentation_method: unknown
- acl_tool: firewall
- rules_documented: no
- documentation_location: unknown
- change_approval_required: no
- approval_authority: network_team
- review_frequency: ad_hoc
- last_review_date: unknown
- automated_monitoring: no
- extraction_confidence: 0.65
</network_acl>

EXTRACTION RULES:
- default_deny_policy: "yes" if explicit mention of default-deny/deny-all/allowlist approach
- network_segmentation: "yes" if multiple zones/tiers/segments mentioned
- segmentation_method: Must be "vpc_based", "vlan_based", "subnet_based", "firewall_zones", "zero_trust", or "unknown"
- acl_tool: Extract tool name (e.g., "AWS Security Groups", "firewall", "Palo Alto", "Cisco ASA", "iptables")
- rules_documented: "yes" if documentation/IaC/version control mentioned
- documentation_location: Extract location (e.g., "Terraform version control", "wiki", "spreadsheet", "IaC")
- change_approval_required: "yes" if approval process mentioned
- approval_authority: Extract team/role (e.g., "Security Architecture team", "IT team", "Network team", "CISO")
- review_frequency: Must be "monthly", "quarterly", "semi_annually", "annually", or "ad_hoc"
- last_review_date: Extract date (YYYY-MM-DD format)
- automated_monitoring: "yes" if monitoring/alerting mentioned

Output format: Wrap in <network_acl></network_acl> tags.
"""

CHANGE_MANAGEMENT_EXAMPLES = """
Extract Change Management evidence from ANY text source (SOC 2, ITIL docs, change policies).

TRAINING EXAMPLES:

Example 1 - From SOC 2 report:
Input: "Island follows a formal change management process for all production infrastructure and application changes.
Changes are categorized as Emergency, Standard, or Normal. All changes require: (1) RFC (Request for Change) ticket
in Jira, (2) Impact assessment and rollback plan, (3) Testing in staging environment, (4) Approval from Change
Advisory Board (CAB) for Normal changes or VP Engineering for Emergency changes, (5) Post-implementation review.
Standard changes (e.g., routine patches) follow pre-approved templates. Emergency changes require post-facto review
within 24 hours. Change success rate for Q2 2024: 98.5% (3 rollbacks out of 200 changes). All changes are logged
in centralized change management system with full audit trail. CAB meets weekly to review upcoming changes."

Output:
<change_management>
- documented_process: yes
- change_categories: emergency, standard, normal
- approval_required: yes
- approval_authority: change_advisory_board, vp_engineering
- testing_required: yes
- testing_environment: staging
- rollback_plan_required: yes
- change_logging_enabled: yes
- change_logging_tool: jira
- post_implementation_review: yes
- emergency_change_process: yes
- change_success_rate_percentage: 98.5
- cab_meeting_frequency: weekly
- extraction_confidence: 0.95
</change_management>

Example 2 - From IT policy:
Input: "Production changes must be approved by team lead and tested before deployment. We use ServiceNow for
change tickets. Emergency changes can be deployed immediately but must be documented after."

Output:
<change_management>
- documented_process: yes
- change_categories: standard, emergency
- approval_required: yes
- approval_authority: team_lead
- testing_required: yes
- testing_environment: unknown
- rollback_plan_required: unknown
- change_logging_enabled: yes
- change_logging_tool: servicenow
- post_implementation_review: no
- emergency_change_process: yes
- change_success_rate_percentage: unknown
- cab_meeting_frequency: unknown
- extraction_confidence: 0.75
</change_management>

Example 3 - Non-compliant vendor:
Input: "Engineers can deploy changes to production after peer review. Changes are tracked in our deployment log."

Output:
<change_management>
- documented_process: no
- change_categories: standard
- approval_required: no
- approval_authority: peer_review
- testing_required: no
- testing_environment: none
- rollback_plan_required: no
- change_logging_enabled: yes
- change_logging_tool: deployment_log
- post_implementation_review: no
- emergency_change_process: no
- change_success_rate_percentage: unknown
- cab_meeting_frequency: none
- extraction_confidence: 0.80
</change_management>

EXTRACTION RULES:
- documented_process: "yes" if formal policy/ITIL process mentioned
- change_categories: Can include "emergency", "standard", "normal", "routine" (comma-separated)
- approval_required: "yes" if approval needed before implementation
- approval_authority: Extract role/body (e.g., "Change Advisory Board", "VP Engineering", "team lead", "manager", "CISO")
- testing_required: "yes" if testing mandatory before production
- testing_environment: Extract environment name (e.g., "staging", "UAT", "pre-production", "none")
- rollback_plan_required: "yes" if rollback/backout plans mandatory
- change_logging_enabled: "yes" if changes tracked in system
- change_logging_tool: Extract tool name (e.g., "Jira", "ServiceNow", "Remedy", "spreadsheet", "deployment log")
- post_implementation_review: "yes" if PIR/retrospective required
- emergency_change_process: "yes" if expedited emergency process exists
- change_success_rate_percentage: Extract percentage (e.g., "98.5% success" → 98.5, "3 rollbacks out of 200" → 98.5)
- cab_meeting_frequency: Extract frequency (e.g., "weekly", "bi-weekly", "monthly", "none")

Output format: Wrap in <change_management></change_management> tags.
"""


# =============================================================================
# BATCH 4: CONTRACTS & INFRASTRUCTURE (4 evidence types)
# =============================================================================

SLA_EXAMPLES = """
Extract Service Level Agreement (SLA) evidence from ANY text source (contracts, MSAs, SLAs, trust centers).

TRAINING EXAMPLES:

Example 1 - From contract/MSA:
Input: "Island guarantees 99.95% uptime measured monthly. For Critical incidents (Severity 1), Island will respond within 1 hour and resolve within 4 hours. For High priority incidents (Severity 2), response within 4 hours and resolution within 24 hours. If uptime falls below 99.95%, Customer receives service credits: 10% for 99.5-99.95%, 25% for 99.0-99.5%, 50% for below 99.0%. SLA performance is published on status.island.io and reported quarterly."

Output:
<sla>
- sla_documented: yes
- sla_location: Service Level Agreement Exhibit A
- availability_sla_exists: yes
- availability_percentage: 99.95
- availability_measurement_period: monthly
- response_time_sla_exists: yes
- critical_incident_response_hours: 1
- high_incident_response_hours: 4
- resolution_time_sla_exists: yes
- critical_incident_resolution_hours: 4
- violation_remedies_defined: yes
- violation_remedy_type: service_credits
- service_credits_available: yes
- service_credit_percentage: 50
- sla_performance_monitored: yes
- sla_reporting_frequency: quarterly
- public_status_page: yes
- sla_covers_critical_services: yes
- extraction_confidence: 0.95
</sla>

Example 2 - From trust center:
Input: "We maintain 99.9% uptime and provide 24/7 support. Our support team responds to urgent issues within 2 hours."

Output:
<sla>
- sla_documented: yes
- sla_location: Trust Center
- availability_sla_exists: yes
- availability_percentage: 99.9
- availability_measurement_period: unknown
- response_time_sla_exists: yes
- critical_incident_response_hours: 2
- high_incident_response_hours: unknown
- resolution_time_sla_exists: no
- critical_incident_resolution_hours: unknown
- violation_remedies_defined: no
- violation_remedy_type: no_remedy
- service_credits_available: no
- service_credit_percentage: unknown
- sla_performance_monitored: unknown
- sla_reporting_frequency: unknown
- public_status_page: no
- sla_covers_critical_services: yes
- extraction_confidence: 0.70
</sla>

EXTRACTION RULES:
- sla_documented: "yes" if any SLAs mentioned
- availability_percentage: Extract percentage (e.g., "99.95%" → 99.95, "three nines" → 99.9, "four nines" → 99.99)
- response/resolution hours: Extract numbers (e.g., "1 hour" → 1, "within 24 hours" → 24)
- service_credit_percentage: Extract highest credit percentage mentioned
- violation_remedy_type: Must be "service_credits", "refund", "contract_termination", "no_remedy", or "other"

Output format: Wrap in <sla></sla> tags.
"""

DATA_RETENTION_EXAMPLES = """
Extract Data Retention & Deletion evidence from ANY text source (privacy policies, DPAs, SOC 2, contracts).

TRAINING EXAMPLES:

Example 1 - From Data Processing Agreement:
Input: "Customer data is retained for the duration of the subscription plus 90 days. Upon termination or deletion request, Island deletes all Customer data within 30 days using secure deletion methods (crypto-erasure). Deletion includes all backup copies within 60 days. Island provides written certification of deletion upon request. Log data is retained for 1 year. Island is GDPR and CCPA compliant and supports data subject rights including right to erasure and right to access."

Output:
<data_retention>
- retention_policy_documented: yes
- retention_policy_location: Data Processing Agreement Section 4
- retention_policy_last_updated: 2024-06
- retention_periods_defined: yes
- default_retention_period_days: 90
- customer_data_retention_days: 90
- log_data_retention_days: 365
- backup_data_retention_days: 60
- deletion_process_documented: yes
- deletion_on_request_supported: yes
- deletion_request_timeframe_days: 30
- deletion_method: crypto_erasure
- deletion_verification_available: yes
- deletion_certificate_provided: yes
- backups_included_in_deletion: yes
- backup_deletion_timeframe_days: 60
- gdpr_compliant: yes
- ccpa_compliant: yes
- data_subject_rights: right_to_erasure, right_to_access
- extraction_confidence: 0.95
</data_retention>

Example 2 - From privacy policy:
Input: "We keep your data for as long as you use our service. You can request deletion of your account at any time."

Output:
<data_retention>
- retention_policy_documented: yes
- retention_policy_location: Privacy Policy
- retention_policy_last_updated: unknown
- retention_periods_defined: no
- default_retention_period_days: unknown
- customer_data_retention_days: unknown
- log_data_retention_days: unknown
- backup_data_retention_days: unknown
- deletion_process_documented: no
- deletion_on_request_supported: yes
- deletion_request_timeframe_days: unknown
- deletion_method: unknown
- deletion_verification_available: no
- deletion_certificate_provided: no
- backups_included_in_deletion: unknown
- backup_deletion_timeframe_days: unknown
- gdpr_compliant: no
- ccpa_compliant: no
- data_subject_rights: right_to_erasure
- extraction_confidence: 0.60
</data_retention>

EXTRACTION RULES:
- retention periods: Extract days (e.g., "90 days" → 90, "1 year" → 365, "7 years" → 2555)
- deletion_method: Must be "secure_deletion", "crypto_erasure", "physical_destruction", "logical_deletion", or "anonymization"
- data_subject_rights: Extract list (e.g., "right_to_erasure", "right_to_access", "right_to_portability")

Output format: Wrap in <data_retention></data_retention> tags.
"""

INSURANCE_EXAMPLES = """
Extract Insurance Coverage evidence from ANY text source (insurance certificates, vendor questionnaires, contracts).

TRAINING EXAMPLES:

Example 1 - From Certificate of Insurance:
Input: "Island Technologies Inc. maintains Cyber Liability Insurance with Chubb Insurance Company, Policy #CYB-2024-5891, coverage amount $5,000,000, effective June 1, 2024 to June 1, 2025. Professional Liability (E&O) Insurance with Hartford, Policy #PL-2024-3421, coverage $2,000,000, same effective dates. Certificate of Insurance available upon request. Customer can be named as additional insured with 30 days notice."

Output:
<insurance>
- cyber_insurance_exists: yes
- cyber_insurance_carrier: Chubb Insurance Company
- cyber_coverage_amount: 5000000
- cyber_policy_number: CYB-2024-5891
- cyber_policy_expiry_date: 2025-06-01
- eo_insurance_exists: yes
- eo_insurance_carrier: Hartford
- eo_coverage_amount: 2000000
- eo_policy_expiry_date: 2025-06-01
- combined_coverage_amount: 7000000
- certificate_of_insurance_available: yes
- certificate_provided_to_customer: no
- customer_named_as_additional_insured: yes
- policy_is_current: yes
- extraction_confidence: 0.95
</insurance>

Example 2 - From vendor questionnaire:
Input: "Yes, we have cyber insurance with $1M coverage. Policy expires next year."

Output:
<insurance>
- cyber_insurance_exists: yes
- cyber_insurance_carrier: unknown
- cyber_coverage_amount: 1000000
- cyber_policy_number: unknown
- cyber_policy_expiry_date: unknown
- eo_insurance_exists: unknown
- eo_insurance_carrier: unknown
- eo_coverage_amount: unknown
- eo_policy_expiry_date: unknown
- combined_coverage_amount: 1000000
- certificate_of_insurance_available: unknown
- certificate_provided_to_customer: no
- customer_named_as_additional_insured: unknown
- policy_is_current: yes
- extraction_confidence: 0.65
</insurance>

EXTRACTION RULES:
- coverage_amount: Extract USD amount (e.g., "$5M" → 5000000, "$1 million" → 1000000, "$5,000,000" → 5000000)
- policy_expiry_date: Extract date in YYYY-MM-DD format
- policy_is_current: "yes" if date is future or "current" mentioned, "no" if expired

Output format: Wrap in <insurance></insurance> tags.
"""

AUDIT_RIGHTS_EXAMPLES = """
Extract Right to Audit evidence from ANY text source (contracts, MSAs, SOC 2).

TRAINING EXAMPLES:

Example 1 - From MSA contract:
Input: "Section 8.4 - Right to Audit: Customer may audit Island's security controls and data handling practices annually upon 30 days written notice. Customer may engage a third-party auditor. Audit scope includes security policies, access controls, data processing activities, and compliance with this Agreement. Island will provide reasonable cooperation including access to relevant systems, documentation, and personnel. Customer bears audit costs unless material non-compliance is found, in which case Island reimburses costs. Island will provide remediation plan within 30 days of audit findings."

Output:
<audit_rights>
- audit_rights_granted: yes
- audit_clause_location: Section 8.4
- audit_frequency: annual
- audit_frequency_description: Once per year upon 30 days notice
- advance_notice_required: yes
- advance_notice_days: 30
- audit_scope_defined: yes
- audit_scope_includes_security: yes
- audit_scope_includes_data_handling: yes
- audit_scope_description: Security policies, access controls, data processing, compliance
- third_party_auditor_allowed: yes
- auditor_qualifications_required: no
- vendor_cooperation_required: yes
- access_to_systems_granted: yes
- access_to_documentation_granted: yes
- access_to_personnel_granted: yes
- cost_allocation: customer_unless_issues
- cost_cap_amount: unknown
- audit_report_to_customer: yes
- remediation_plan_required: yes
- extraction_confidence: 0.95
</audit_rights>

Example 2 - From SOC 2 report:
Input: "Upon reasonable notice, customers may request audit of our security controls. We cooperate with customer audits."

Output:
<audit_rights>
- audit_rights_granted: yes
- audit_clause_location: SOC 2 Type II Report
- audit_frequency: upon_request
- audit_frequency_description: Upon reasonable notice
- advance_notice_required: yes
- advance_notice_days: unknown
- audit_scope_defined: yes
- audit_scope_includes_security: yes
- audit_scope_includes_data_handling: no
- audit_scope_description: Security controls
- third_party_auditor_allowed: yes
- auditor_qualifications_required: no
- vendor_cooperation_required: yes
- access_to_systems_granted: unknown
- access_to_documentation_granted: unknown
- access_to_personnel_granted: unknown
- cost_allocation: not_specified
- cost_cap_amount: unknown
- audit_report_to_customer: yes
- remediation_plan_required: no
- extraction_confidence: 0.70
</audit_rights>

EXTRACTION RULES:
- audit_frequency: Must be "annual", "semi_annual", "quarterly", "upon_request", or "upon_cause"
- advance_notice_days: Extract days (e.g., "30 days" → 30, "two weeks" → 14)
- cost_allocation: Must be "customer", "vendor", "shared", "customer_unless_issues", or "not_specified"
- cost_cap_amount: Extract USD amount if mentioned

Output format: Wrap in <audit_rights></audit_rights> tags.
"""


# =============================================================================
# BATCH 5: AI GOVERNANCE (1 evidence type)
# =============================================================================

AI_GOVERNANCE_EXAMPLES = """
Extract AI/ML Security Controls evidence from ANY text source (AI governance docs, model cards, vendor questionnaires, trust centers).

TRAINING EXAMPLES:

Example 1 - From AI governance documentation:
Input: "Island uses AI for content recommendations (Medium risk) and fraud detection (High risk). We maintain an AI system inventory and perform quarterly risk assessments using NIST AI RMF. Training data provenance is tracked and validated for quality. We conduct bias testing quarterly on all high-risk models with fairness metrics. Model cards are published for all AI systems. Critical fraud detection decisions require human review by our Risk team. We perform monthly adversarial testing and red team exercises. AI incidents are monitored in real-time with automated drift detection. We use OpenAI GPT-4 and have assessed third-party AI risks."

Output:
<ai_governance>
- ai_systems_used: yes
- ai_inventory_maintained: yes
- ai_use_cases: recommendation, fraud_detection
- ai_use_case_descriptions: Content recommendations and fraud detection
- ai_risk_assessment_performed: yes
- highest_ai_risk_level: high
- ai_risk_framework_used: NIST AI RMF
- training_data_governance_exists: yes
- training_data_provenance_tracked: yes
- training_data_quality_validated: yes
- customer_data_used_for_training: no
- customer_data_training_opt_out: no
- model_validation_performed: yes
- bias_testing_performed: yes
- bias_testing_frequency: quarterly
- accuracy_metrics_tracked: yes
- explainability_provided: yes
- model_cards_published: yes
- ai_transparency_report: no
- human_oversight_exists: yes
- human_review_for_critical_decisions: yes
- ai_decision_appeal_process: no
- adversarial_testing_performed: yes
- red_team_testing_performed: yes
- ai_incident_response_plan: yes
- ai_incident_monitoring: yes
- third_party_ai_models_used: yes
- third_party_ai_risk_assessed: yes
- third_party_ai_vendors: OpenAI
- extraction_confidence: 0.95
</ai_governance>

Example 2 - From vendor questionnaire:
Input: "We use AI chatbot for customer support. The AI is trained on our documentation and doesn't use customer data. We monitor the chatbot's responses."

Output:
<ai_governance>
- ai_systems_used: yes
- ai_inventory_maintained: no
- ai_use_cases: conversational_ai
- ai_use_case_descriptions: Customer support chatbot
- ai_risk_assessment_performed: no
- highest_ai_risk_level: low
- ai_risk_framework_used: unknown
- training_data_governance_exists: no
- training_data_provenance_tracked: no
- training_data_quality_validated: no
- customer_data_used_for_training: no
- customer_data_training_opt_out: no
- model_validation_performed: no
- bias_testing_performed: no
- bias_testing_frequency: unknown
- accuracy_metrics_tracked: no
- explainability_provided: no
- model_cards_published: no
- ai_transparency_report: no
- human_oversight_exists: yes
- human_review_for_critical_decisions: no
- ai_decision_appeal_process: no
- adversarial_testing_performed: no
- red_team_testing_performed: no
- ai_incident_response_plan: no
- ai_incident_monitoring: yes
- third_party_ai_models_used: unknown
- third_party_ai_risk_assessed: no
- third_party_ai_vendors: unknown
- extraction_confidence: 0.65
</ai_governance>

Example 3 - No AI used:
Input: "We do not use any AI or machine learning in our product."

Output:
<ai_governance>
- ai_systems_used: no
- ai_inventory_maintained: no
- ai_use_cases: none
- ai_use_case_descriptions: No AI systems in use
- ai_risk_assessment_performed: no
- highest_ai_risk_level: minimal
- ai_risk_framework_used: N/A
- training_data_governance_exists: no
- training_data_provenance_tracked: no
- training_data_quality_validated: no
- customer_data_used_for_training: no
- customer_data_training_opt_out: no
- model_validation_performed: no
- bias_testing_performed: no
- bias_testing_frequency: N/A
- accuracy_metrics_tracked: no
- explainability_provided: no
- model_cards_published: no
- ai_transparency_report: no
- human_oversight_exists: no
- human_review_for_critical_decisions: no
- ai_decision_appeal_process: no
- adversarial_testing_performed: no
- red_team_testing_performed: no
- ai_incident_response_plan: no
- ai_incident_monitoring: no
- third_party_ai_models_used: no
- third_party_ai_risk_assessed: no
- third_party_ai_vendors: none
- extraction_confidence: 0.90
</ai_governance>

EXTRACTION RULES:
- ai_systems_used: "yes" if any AI/ML mentioned, "no" if explicitly stated no AI
- ai_use_cases: Can include multiple from: "content_generation", "decision_making", "recommendation", "fraud_detection", "personalization", "prediction", "classification", "conversational_ai", "automation", "other"
- highest_ai_risk_level: Must be "critical", "high", "medium", "low", or "minimal"
- ai_risk_framework_used: Extract framework name (e.g., "NIST AI RMF", "EU AI Act", "ISO 42001")
- third_party_ai_vendors: Extract vendor names (e.g., "OpenAI", "Anthropic", "Google", "Azure OpenAI")

Output format: Wrap in <ai_governance></ai_governance> tags.
"""
