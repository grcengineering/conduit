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
