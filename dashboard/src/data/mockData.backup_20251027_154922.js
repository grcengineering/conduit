/**
 * Mock CONDUIT Evidence Data
 *
 * Demonstrates percentage-based compliance with 3 vendors × 3 controls
 * Uses actual CONDUIT format matching our Pydantic backend
 */

const mockEvidence = {
  vendors: [
    {
      id: 'v1',
      name: 'Acme SaaS',
      criticality: 'high',
      riskScore: 0.38,  // 38% risk
      subprocessors: ['v3'],
      controls: [
        {
          id: 7,
          name: 'BCP/DR Testing',
          passed: 2,
          total: 3,
          percentage: 66.7,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'Test within 12 months',
              passed: true,
              detail: 'Last test: 2025-08-15 (2 months ago)'
            },
            {
              name: 'Test passed or passed with findings',
              passed: false,
              detail: 'Test FAILED: RTO exceeded by 2 hours (target: 4h, actual: 6h)'
            },
            {
              name: 'Scope documented',
              passed: true,
              detail: 'Scope: Production database and application servers'
            }
          ],
          risks: [
            'Service disruption if DR fails',
            'RTO not met - customer impact > 4 hours'
          ],
          source_document: 'acme_soc2_report.pdf, page 45-47',
          extraction_confidence: 0.92,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_007_bcpdr_testing',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            test_date: '2025-08-15',
            test_result: 'fail',
            test_type: 'partial_failover',
            scope: 'Production database and application servers',
            findings: [
              {
                finding: 'RTO exceeded by 2 hours',
                severity: 'high',
                remediation_status: 'in_progress'
              }
            ],
            recovery_time_objective_met: false,
            extraction_confidence: 0.92,
            soc2_coverage_percentage: 90
          }
        },
        {
          id: 23,
          name: 'SSO/MFA Requirements',
          passed: 3,
          total: 4,
          percentage: 75.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'SSO supported',
              passed: true,
              detail: 'Supports SAML 2.0 and OIDC'
            },
            {
              name: 'SSO not behind paywall',
              passed: false,
              detail: '⚠️ CRITICAL: SSO requires Enterprise plan ($500/month)'
            },
            {
              name: 'MFA available',
              passed: true,
              detail: 'TOTP, SMS, Push notifications available'
            },
            {
              name: 'Phishing-resistant MFA available',
              passed: true,
              detail: 'Supports hardware tokens (YubiKey, FIDO2)'
            }
          ],
          risks: [
            'SSO paywall violates ASSURE requirements',
            'Smaller customers forced to use passwords'
          ],
          source_document: 'acme_security_docs.pdf, page 12-15',
          extraction_confidence: 0.95,
          soc2_overlap: 50,
          structuredData: {
            evidence_type: 'assure_023_sso_mfa',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            sso_supported: true,
            sso_protocols: ['saml', 'oidc'],
            sso_requires_paid_plan: true,  // CRITICAL ISSUE!
            mfa_enforced_by_default: false,
            mfa_types_supported: ['authenticator_app', 'sms', 'push_notification', 'hardware_token'],
            phishing_resistant_mfa_available: true,
            mfa_coverage_percentage: 78,
            extraction_confidence: 0.95,
            soc2_coverage_percentage: 50
          }
        },
        {
          id: 4,
          name: 'Vulnerability Management',
          passed: 2,
          total: 4,
          percentage: 50.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: '3 monthly scans in last 90 days',
              passed: true,
              detail: 'Scans: 2025-10-01, 2025-09-01, 2025-08-01 (Qualys)'
            },
            {
              name: 'Pentest within 12 months',
              passed: false,
              detail: 'Last pentest: 2024-03-15 (19 months ago) - OVERDUE!'
            },
            {
              name: 'Vulnerability SLAs met',
              passed: true,
              detail: 'SLA: Critical 7d, High 30d, Medium 90d - All met'
            },
            {
              name: 'Critical/high pentest findings remediated',
              passed: false,
              detail: '2 high findings from 2024 pentest still open'
            }
          ],
          risks: [
            'Pentest overdue by 7 months',
            'Unresolved high-severity findings from last pentest',
            'Unknown vulnerabilities may exist'
          ],
          source_document: 'acme_soc2_report.pdf, page 28-35',
          extraction_confidence: 0.88,
          soc2_overlap: 80,
          structuredData: {
            evidence_type: 'assure_004_vulnerability_mgmt',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            scans_last_3_months: [
              { scan_date: '2025-10-01', scanner_tool: 'Qualys', scan_type: 'authenticated', critical_findings: 0, high_findings: 2, medium_findings: 5, low_findings: 12 },
              { scan_date: '2025-09-01', scanner_tool: 'Qualys', scan_type: 'authenticated', critical_findings: 0, high_findings: 3, medium_findings: 7, low_findings: 15 },
              { scan_date: '2025-08-01', scanner_tool: 'Qualys', scan_type: 'authenticated', critical_findings: 1, high_findings: 4, medium_findings: 8, low_findings: 18 }
            ],
            penetration_test: {
              test_date: '2024-03-15',
              tester_firm: 'SecureOps Inc',
              test_type: 'external_black_box',
              critical_findings: 0,
              high_findings: 2,
              medium_findings: 5,
              low_findings: 8,
              all_critical_high_remediated: false
            },
            vulnerability_sla_met: true,
            extraction_confidence: 0.88,
            soc2_coverage_percentage: 80
          }
        },
        {
          id: 9,
          name: 'Production Access Controls',
          passed: 4,
          total: 6,
          percentage: 66.7,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'JIT access method',
              passed: true,
              detail: 'Uses bastion hosts with just-in-time access provisioning'
            },
            {
              name: 'Default access is "none"',
              passed: true,
              detail: 'No default production access granted to any accounts'
            },
            {
              name: 'MFA required for privileged access',
              passed: true,
              detail: 'Hardware tokens (YubiKey) required for all admin operations'
            },
            {
              name: 'Max session duration < 4 hours',
              passed: false,
              detail: '⚠️ Sessions persist for 8 hours (target: 4 hours max)'
            },
            {
              name: 'No persistent access allowed',
              passed: false,
              detail: '⚠️ 3 admin accounts have persistent production access'
            },
            {
              name: 'Privileged accounts segregated',
              passed: true,
              detail: 'Separate admin accounts used for production operations'
            }
          ],
          risks: [
            'Extended session duration increases exposure window',
            'Persistent admin access violates principle of least privilege'
          ],
          source_document: 'acme_soc2_report.pdf, page 51-54',
          extraction_confidence: 0.89,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_009_production_access',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            access_method: 'bastion',
            default_access: 'none',
            mfa_required_for_privileged: true,
            max_session_duration: '8_hours',
            persistent_access_allowed: true,
            privileged_accounts_segregated: true,
            extraction_confidence: 0.89,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC5.2', 'CC6.1']
          }
        },
        {
          id: 12,
          name: 'Encryption at Rest',
          passed: 6,
          total: 8,
          percentage: 75.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'Database encrypted',
              passed: true,
              detail: 'PostgreSQL: AES-256 via AWS KMS'
            },
            {
              name: 'File storage encrypted',
              passed: true,
              detail: 'S3 buckets: Server-side encryption (SSE-KMS)'
            },
            {
              name: 'Object storage encrypted',
              passed: true,
              detail: 'All production S3 buckets have encryption enabled'
            },
            {
              name: 'Backups encrypted',
              passed: true,
              detail: 'RDS snapshots and EBS volumes: AWS-managed encryption'
            },
            {
              name: 'Strong algorithms (AES-256 or equivalent)',
              passed: true,
              detail: 'All stores use AES-256-GCM'
            },
            {
              name: 'Key management via HSM/KMS',
              passed: true,
              detail: 'AWS KMS with automatic key rotation'
            },
            {
              name: 'Key rotation enabled',
              passed: false,
              detail: '⚠️ Manual rotation only (no automatic rotation configured)'
            },
            {
              name: 'FIPS 140-2 compliant',
              passed: false,
              detail: '⚠️ KMS is FIPS 140-2 Level 2, but application code not validated'
            }
          ],
          risks: [
            'Manual key rotation increases risk of key compromise',
            'Non-FIPS compliant application code may have crypto vulnerabilities'
          ],
          source_document: 'acme_soc2_report.pdf, page 38-42',
          extraction_confidence: 0.91,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_012_encryption_at_rest',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            encrypted_stores: [
              {
                store_type: 'database',
                store_name: 'PostgreSQL RDS (production)',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_kms',
                key_rotation_enabled: false
              },
              {
                store_type: 'file_storage',
                store_name: 'S3 production buckets',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_kms',
                key_rotation_enabled: false
              },
              {
                store_type: 'object_storage',
                store_name: 'S3 customer data',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_kms',
                key_rotation_enabled: false
              },
              {
                store_type: 'backups',
                store_name: 'RDS snapshots + EBS volumes',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_kms',
                key_rotation_enabled: false
              }
            ],
            key_rotation_enabled: false,
            fips_140_2_compliant: false,
            extraction_confidence: 0.91,
            soc2_coverage_percentage: 90,
            soc2_section_4_criteria: ['CC6.1', 'CC6.6']
          }
        },
        {
          id: 13,
          name: 'Encryption in Transit',
          passed: 5,
          total: 7,
          percentage: 71.4,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'TLS 1.2 or higher supported',
              passed: true,
              detail: 'TLS 1.2 and TLS 1.3 enabled on all endpoints'
            },
            {
              name: 'Weak protocols disabled (SSL v2/v3, TLS 1.0/1.1)',
              passed: true,
              detail: 'All legacy SSL/TLS versions explicitly disabled'
            },
            {
              name: 'Valid certificate from trusted CA',
              passed: true,
              detail: "Let's Encrypt certificate, auto-renewed, expires 2026-01-15"
            },
            {
              name: 'Certificate not expired',
              passed: true,
              detail: 'Certificate valid for 3 months (auto-renewal configured)'
            },
            {
              name: 'Qualys SSL Labs grade A or higher',
              passed: false,
              detail: '⚠️ Grade: B (cipher suite ordering needs improvement)'
            },
            {
              name: 'Forward secrecy enabled',
              passed: true,
              detail: 'ECDHE cipher suites configured for perfect forward secrecy'
            },
            {
              name: 'HSTS enabled',
              passed: false,
              detail: '⚠️ HTTP Strict Transport Security not configured'
            }
          ],
          risks: [
            'SSL Labs grade B indicates potential cipher suite vulnerabilities',
            'Missing HSTS allows potential downgrade attacks'
          ],
          source_document: 'acme_soc2_report.pdf, page 43-45',
          extraction_confidence: 0.90,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_013_encryption_in_transit',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            tls_versions_supported: ['tls_1_2', 'tls_1_3'],
            weak_protocols_blocked: ['ssl_v2', 'ssl_v3', 'tls_1_0', 'tls_1_1'],
            certificate_authority: 'letsencrypt',
            certificate_expiry_date: '2026-01-15',
            qualys_ssl_grade: 'B',
            forward_secrecy_enabled: true,
            hsts_enabled: false,
            extraction_confidence: 0.90,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC6.1', 'CC6.7']
          }
        },
        {
          id: 5,
          name: 'Incident Response',
          passed: 5,
          total: 8,
          percentage: 62.5,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'IR plan exists and documented',
              passed: true,
              detail: 'Incident response plan documented in security policy v3.2'
            },
            {
              name: 'IR plan tested annually',
              passed: false,
              detail: '⚠️ Last test: 2023-09-10 (15 months ago) - OVERDUE'
            },
            {
              name: 'Security breach SLA defined',
              passed: true,
              detail: 'Critical incidents: 1 hour notification SLA'
            },
            {
              name: 'Privacy breach SLA defined',
              passed: true,
              detail: 'PII breaches: 4 hour notification SLA (meets GDPR 72hr)'
            },
            {
              name: 'Incident types covered',
              passed: true,
              detail: 'Covers: security breach, privacy, availability, data integrity'
            },
            {
              name: 'Lessons learned documented',
              passed: false,
              detail: '⚠️ Post-mortem process exists but not consistently followed'
            },
            {
              name: 'Plan accessible to employees',
              passed: true,
              detail: 'IR runbooks available in internal wiki + Slack channel'
            },
            {
              name: 'Contact information current',
              passed: false,
              detail: '⚠️ On-call rotation outdated (missing 2 team members)'
            }
          ],
          risks: [
            'Overdue IR testing may result in ineffective response',
            'Outdated contact info could delay incident escalation'
          ],
          source_document: 'acme_soc2_report.pdf, page 55-58',
          extraction_confidence: 0.87,
          soc2_overlap: 80,
          structuredData: {
            evidence_type: 'assure_005_incident_response',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            ir_plan_exists: true,
            last_test_date: '2023-09-10',
            test_type: 'tabletop',
            incident_types_covered: ['security_breach', 'privacy_breach', 'availability', 'data_integrity'],
            security_breach_sla: '1_hour',
            privacy_breach_sla: '4_hours',
            lessons_learned_documented: false,
            plan_accessible_to_employees: true,
            extraction_confidence: 0.87,
            soc2_coverage_percentage: 80,
            soc2_section_4_criteria: ['CC2.2', 'CC7.3', 'CC7.4']
          }
        },
        {
          id: 14,
          name: 'Logging Configuration',
          passed: 4,
          total: 6,
          percentage: 66.7,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'Log retention ≥ 90 days',
              passed: true,
              detail: 'Retention: 1 year for security logs, 90 days for application logs'
            },
            {
              name: 'Security logs collected',
              passed: true,
              detail: 'Collecting: authentication, authorization, admin actions, config changes'
            },
            {
              name: 'Centralized logging',
              passed: true,
              detail: 'Splunk SIEM aggregates logs from all production systems'
            },
            {
              name: 'Logs immutable',
              passed: false,
              detail: '⚠️ Logs stored in S3 but bucket versioning not enabled'
            },
            {
              name: 'Log monitoring/alerting configured',
              passed: true,
              detail: 'Real-time alerts for failed auth, privilege escalation, data access'
            },
            {
              name: 'Access logs protected',
              passed: false,
              detail: '⚠️ Log access not restricted to security team only'
            }
          ],
          risks: [
            'Mutable logs could be altered to hide attacker activity',
            'Unrest ricted log access may expose sensitive information'
          ],
          source_document: 'acme_soc2_report.pdf, page 48-50',
          extraction_confidence: 0.89,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_014_logging_config',
            vendor_name: 'Acme SaaS',
            evidence_date: '2025-10-16',
            retention_period: '1_year',
            log_types_collected: ['security', 'access', 'audit', 'application'],
            monitoring_tool: 'splunk',
            logs_immutable: false,
            centralized_logging: true,
            extraction_confidence: 0.89,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC7.2', 'CC7.3']
          }
        }
      ]
    },
    {
      id: 'v2',
      name: 'DataFlow Inc',
      criticality: 'medium',
      riskScore: 0.52,  // 52% risk
      subprocessors: [],
      controls: [
        {
          id: 7,
          name: 'BCP/DR Testing',
          passed: 1,
          total: 3,
          percentage: 33.3,
          status: 'non_compliant',
          requirements: [
            {
              name: 'Test within 12 months',
              passed: false,
              detail: 'Last test: 2023-11-20 (23 months ago) - OVERDUE!'
            },
            {
              name: 'Test passed or passed with findings',
              passed: false,
              detail: 'Test result unavailable (test too old)'
            },
            {
              name: 'Scope documented',
              passed: true,
              detail: 'Scope: Core databases only (limited)'
            }
          ],
          risks: [
            'BCP/DR test severely overdue (23 months)',
            'No recent DR validation',
            'Unknown recovery capability'
          ],
          source_document: 'dataflow_vendor_questionnaire.xlsx, tab "BCP"',
          extraction_confidence: 0.75,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_007_bcpdr_testing',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            test_date: '2023-11-20',
            test_result: 'pass_with_findings',
            test_type: 'tabletop',
            scope: 'Core databases only',
            findings: [],
            extraction_confidence: 0.75,
            soc2_coverage_percentage: 90
          }
        },
        {
          id: 23,
          name: 'SSO/MFA Requirements',
          passed: 2,
          total: 4,
          percentage: 50.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'SSO supported',
              passed: true,
              detail: 'Supports SAML 2.0'
            },
            {
              name: 'SSO not behind paywall',
              passed: true,
              detail: 'SSO available on all plans (compliant!)'
            },
            {
              name: 'MFA available',
              passed: true,
              detail: 'TOTP and SMS available'
            },
            {
              name: 'Phishing-resistant MFA available',
              passed: false,
              detail: 'Only SMS and TOTP - NO hardware token support'
            }
          ],
          risks: [
            'No phishing-resistant MFA (no hardware tokens)',
            'Vulnerable to MFA phishing attacks'
          ],
          source_document: 'dataflow_trust_center.html',
          extraction_confidence: 0.91,
          soc2_overlap: 50,
          structuredData: {
            evidence_type: 'assure_023_sso_mfa',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            sso_supported: true,
            sso_protocols: ['saml'],
            sso_requires_paid_plan: false,
            mfa_enforced_by_default: true,
            mfa_types_supported: ['authenticator_app', 'sms'],
            phishing_resistant_mfa_available: false,
            mfa_coverage_percentage: 100,
            extraction_confidence: 0.91,
            soc2_coverage_percentage: 50
          }
        },
        {
          id: 4,
          name: 'Vulnerability Management',
          passed: 3,
          total: 4,
          percentage: 75.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: '3 monthly scans in last 90 days',
              passed: true,
              detail: 'Scans: 2025-10-05, 2025-09-05, 2025-08-05 (Tenable)'
            },
            {
              name: 'Pentest within 12 months',
              passed: true,
              detail: 'Last pentest: 2025-05-10 (5 months ago)'
            },
            {
              name: 'Vulnerability SLAs met',
              passed: true,
              detail: 'SLA: Critical 5d, High 30d - All met'
            },
            {
              name: 'Critical/high pentest findings remediated',
              passed: false,
              detail: '1 high finding pending (SQL injection in reporting API)'
            }
          ],
          risks: [
            'Unresolved high-severity SQL injection vulnerability',
            'Potential data breach vector'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 22-28',
          extraction_confidence: 0.94,
          soc2_overlap: 80,
          structuredData: {
            evidence_type: 'assure_004_vulnerability_mgmt',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            scans_last_3_months: [
              { scan_date: '2025-10-05', scanner_tool: 'Tenable', scan_type: 'authenticated', critical_findings: 0, high_findings: 1, medium_findings: 3, low_findings: 8 },
              { scan_date: '2025-09-05', scanner_tool: 'Tenable', scan_type: 'authenticated', critical_findings: 0, high_findings: 1, medium_findings: 4, low_findings: 10 },
              { scan_date: '2025-08-05', scanner_tool: 'Tenable', scan_type: 'authenticated', critical_findings: 0, high_findings: 2, medium_findings: 5, low_findings: 11 }
            ],
            penetration_test: {
              test_date: '2025-05-10',
              tester_firm: 'CyberShield Labs',
              test_type: 'web_application',
              critical_findings: 0,
              high_findings: 1,
              medium_findings: 3,
              low_findings: 5,
              all_critical_high_remediated: false
            },
            bug_bounty: {
              active: false
            },
            vulnerability_sla_met: true,
            extraction_confidence: 0.94,
            soc2_coverage_percentage: 80
          }
        },
        {
          id: 9,
          name: 'Production Access Controls',
          passed: 5,
          total: 6,
          percentage: 83.3,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'JIT access method',
              passed: true,
              detail: 'Just-in-time (JIT) access with temporary credentials via AWS SSM'
            },
            {
              name: 'Default access is "none"',
              passed: true,
              detail: 'Zero standing access - all production access is request-based'
            },
            {
              name: 'MFA required for privileged access',
              passed: true,
              detail: 'Enforced MFA for all production access requests'
            },
            {
              name: 'Max session duration < 4 hours',
              passed: true,
              detail: 'Sessions automatically expire after 2 hours'
            },
            {
              name: 'No persistent access allowed',
              passed: false,
              detail: '⚠️ 1 break-glass account has persistent access for emergencies'
            },
            {
              name: 'Privileged accounts segregated',
              passed: true,
              detail: 'Dedicated admin accounts separate from regular user accounts'
            }
          ],
          risks: [
            'Break-glass account should be monitored more closely'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 48-51',
          extraction_confidence: 0.93,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_009_production_access',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            access_method: 'jit',
            default_access: 'none',
            mfa_required_for_privileged: true,
            max_session_duration: '2_hours',
            persistent_access_allowed: true,
            privileged_accounts_segregated: true,
            extraction_confidence: 0.93,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC5.2', 'CC6.1']
          }
        },
        {
          id: 12,
          name: 'Encryption at Rest',
          passed: 7,
          total: 8,
          percentage: 87.5,
          status: 'compliant',
          requirements: [
            {
              name: 'Database encrypted',
              passed: true,
              detail: 'MySQL: AES-256 via GCP Cloud KMS'
            },
            {
              name: 'File storage encrypted',
              passed: true,
              detail: 'GCS buckets: Customer-managed encryption keys'
            },
            {
              name: 'Object storage encrypted',
              passed: true,
              detail: 'All GCS buckets encrypted with CMEK'
            },
            {
              name: 'Backups encrypted',
              passed: true,
              detail: 'Cloud SQL automated backups encrypted at rest'
            },
            {
              name: 'Strong algorithms (AES-256 or equivalent)',
              passed: true,
              detail: 'AES-256-GCM for all data stores'
            },
            {
              name: 'Key management via HSM/KMS',
              passed: true,
              detail: 'GCP Cloud HSM (FIPS 140-2 Level 3)'
            },
            {
              name: 'Key rotation enabled',
              passed: true,
              detail: 'Automatic key rotation every 90 days'
            },
            {
              name: 'FIPS 140-2 compliant',
              passed: false,
              detail: '⚠️ Cloud HSM is FIPS certified, but app layer not formally validated'
            }
          ],
          risks: [
            'Application-layer crypto libraries should undergo FIPS validation'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 32-37',
          extraction_confidence: 0.94,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_012_encryption_at_rest',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            encrypted_stores: [
              {
                store_type: 'database',
                store_name: 'Cloud SQL (MySQL)',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'gcp_kms',
                key_rotation_enabled: true
              },
              {
                store_type: 'file_storage',
                store_name: 'GCS production buckets',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'gcp_kms',
                key_rotation_enabled: true
              },
              {
                store_type: 'object_storage',
                store_name: 'GCS customer data',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'gcp_kms',
                key_rotation_enabled: true
              },
              {
                store_type: 'backups',
                store_name: 'Cloud SQL automated backups',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'gcp_kms',
                key_rotation_enabled: true
              }
            ],
            key_rotation_enabled: true,
            fips_140_2_compliant: false,
            extraction_confidence: 0.94,
            soc2_coverage_percentage: 90,
            soc2_section_4_criteria: ['CC6.1', 'CC6.6']
          }
        },
        {
          id: 13,
          name: 'Encryption in Transit',
          passed: 6,
          total: 7,
          percentage: 85.7,
          status: 'compliant',
          requirements: [
            {
              name: 'TLS 1.2 or higher supported',
              passed: true,
              detail: 'TLS 1.3 only (TLS 1.2 deprecated for new connections)'
            },
            {
              name: 'Weak protocols disabled (SSL v2/v3, TLS 1.0/1.1)',
              passed: true,
              detail: 'All legacy protocols blocked at load balancer level'
            },
            {
              name: 'Valid certificate from trusted CA',
              passed: true,
              detail: 'DigiCert EV certificate, expires 2026-06-20'
            },
            {
              name: 'Certificate not expired',
              passed: true,
              detail: 'Certificate valid for 8 months'
            },
            {
              name: 'Qualys SSL Labs grade A or higher',
              passed: true,
              detail: 'Grade: A+ (perfect cipher suite configuration)'
            },
            {
              name: 'Forward secrecy enabled',
              passed: true,
              detail: 'All connections use ECDHE-based cipher suites'
            },
            {
              name: 'HSTS enabled',
              passed: false,
              detail: '⚠️ HSTS header configured but max-age only 30 days (recommended: 1 year)'
            }
          ],
          risks: [
            'Short HSTS max-age may allow brief downgrade window'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 38-40',
          extraction_confidence: 0.93,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_013_encryption_in_transit',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            tls_versions_supported: ['tls_1_3'],
            weak_protocols_blocked: ['ssl_v2', 'ssl_v3', 'tls_1_0', 'tls_1_1', 'tls_1_2'],
            certificate_authority: 'digicert',
            certificate_expiry_date: '2026-06-20',
            qualys_ssl_grade: 'A+',
            forward_secrecy_enabled: true,
            hsts_enabled: true,
            extraction_confidence: 0.93,
            soc2_coverage_percentage: 90,
            soc2_section_4_criteria: ['CC6.1', 'CC6.7']
          }
        },
        {
          id: 5,
          name: 'Incident Response',
          passed: 6,
          total: 8,
          percentage: 75.0,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'IR plan exists and documented',
              passed: true,
              detail: 'Comprehensive IR playbook maintained in Confluence'
            },
            {
              name: 'IR plan tested annually',
              passed: true,
              detail: 'Last test: 2025-03-15 (7 months ago) via tabletop exercise'
            },
            {
              name: 'Security breach SLA defined',
              passed: true,
              detail: 'Critical: immediate, High: 1 hour, Medium: 4 hours'
            },
            {
              name: 'Privacy breach SLA defined',
              passed: true,
              detail: 'All PII breaches: 2 hour internal notification, 24hr customer notification'
            },
            {
              name: 'Incident types covered',
              passed: true,
              detail: 'Covers all major categories including ransomware scenarios'
            },
            {
              name: 'Lessons learned documented',
              passed: true,
              detail: 'Post-incident reviews required for all P1/P2 incidents'
            },
            {
              name: 'Plan accessible to employees',
              passed: false,
              detail: '⚠️ Runbooks accessible but require VPN (not available during network incidents)'
            },
            {
              name: 'Contact information current',
              passed: false,
              detail: '⚠️ Contact list includes 2 former employees'
            }
          ],
          risks: [
            'VPN dependency could block IR runbook access during network incidents',
            'Outdated contacts may delay escalation'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 52-56',
          extraction_confidence: 0.91,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_005_incident_response',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            ir_plan_exists: true,
            last_test_date: '2025-03-15',
            test_type: 'tabletop',
            incident_types_covered: ['security_breach', 'privacy_breach', 'availability', 'data_integrity', 'ransomware'],
            security_breach_sla: 'immediate',
            privacy_breach_sla: '2_hours',
            lessons_learned_documented: true,
            plan_accessible_to_employees: false,
            extraction_confidence: 0.91,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC2.2', 'CC7.3', 'CC7.4']
          }
        },
        {
          id: 14,
          name: 'Logging Configuration',
          passed: 5,
          total: 6,
          percentage: 83.3,
          status: 'partially_compliant',
          requirements: [
            {
              name: 'Log retention ≥ 90 days',
              passed: true,
              detail: 'Retention: 2 years for audit logs, 6 months for application logs'
            },
            {
              name: 'Security logs collected',
              passed: true,
              detail: 'Comprehensive logging: auth, authz, admin, network, file access'
            },
            {
              name: 'Centralized logging',
              passed: true,
              detail: 'Datadog aggregates all logs with full-text search capability'
            },
            {
              name: 'Logs immutable',
              passed: true,
              detail: 'S3 Object Lock enabled with compliance mode (WORM)'
            },
            {
              name: 'Log monitoring/alerting configured',
              passed: true,
              detail: 'Automated anomaly detection + 50+ security alert rules'
            },
            {
              name: 'Access logs protected',
              passed: false,
              detail: '⚠️ Developers have read access to production logs (should be security team only)'
            }
          ],
          risks: [
            'Developer access to logs may expose customer PII'
          ],
          source_document: 'dataflow_soc2_report.pdf, page 41-44',
          extraction_confidence: 0.92,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_014_logging_config',
            vendor_name: 'DataFlow Inc',
            evidence_date: '2025-10-16',
            retention_period: '2_years',
            log_types_collected: ['security', 'access', 'audit', 'application', 'system', 'database'],
            monitoring_tool: 'datadog',
            logs_immutable: true,
            centralized_logging: true,
            extraction_confidence: 0.92,
            soc2_coverage_percentage: 90,
            soc2_section_4_criteria: ['CC7.2', 'CC7.3']
          }
        }
      ]
    },
    {
      id: 'v3',
      name: 'CloudStore Pro',
      criticality: 'critical',
      riskScore: 0.08,  // 8% risk - VERY LOW!
      subprocessors: [],
      controls: [
        {
          id: 7,
          name: 'BCP/DR Testing',
          passed: 3,
          total: 3,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            {
              name: 'Test within 12 months',
              passed: true,
              detail: 'Last test: 2025-09-20 (less than 1 month ago)'
            },
            {
              name: 'Test passed or passed with findings',
              passed: true,
              detail: 'Test PASSED with no findings'
            },
            {
              name: 'Scope documented',
              passed: true,
              detail: 'Scope: Full production environment including databases, applications, and failover systems'
            }
          ],
          risks: [],
          source_document: 'cloudstore_soc2_type2.pdf, page 52-58',
          extraction_confidence: 0.98,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_007_bcpdr_testing',
            vendor_name: 'CloudStore Pro',
            evidence_date: '2025-10-16',
            test_date: '2025-09-20',
            test_result: 'pass',
            test_type: 'full_failover',
            scope: 'Full production environment including databases, applications, and failover systems',
            findings: [],
            recovery_time_objective_met: true,
            recovery_point_objective_met: true,
            extraction_confidence: 0.98,
            soc2_coverage_percentage: 90
          }
        },
        {
          id: 23,
          name: 'SSO/MFA Requirements',
          passed: 4,
          total: 4,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            {
              name: 'SSO supported',
              passed: true,
              detail: 'Supports SAML 2.0, OIDC, and OAuth 2.0'
            },
            {
              name: 'SSO not behind paywall',
              passed: true,
              detail: 'SSO included in all plans (compliant!)'
            },
            {
              name: 'MFA available',
              passed: true,
              detail: 'Multiple MFA options available'
            },
            {
              name: 'Phishing-resistant MFA available',
              passed: true,
              detail: 'Supports YubiKey, FIDO2, and biometric authentication'
            }
          ],
          risks: [],
          source_document: 'cloudstore_security_whitepaper.pdf, page 8-12',
          extraction_confidence: 0.99,
          soc2_overlap: 50,
          structuredData: {
            evidence_type: 'assure_023_sso_mfa',
            vendor_name: 'CloudStore Pro',
            evidence_date: '2025-10-16',
            sso_supported: true,
            sso_protocols: ['saml', 'oidc', 'oauth2'],
            sso_requires_paid_plan: false,
            mfa_enforced_by_default: true,
            mfa_types_supported: ['authenticator_app', 'hardware_token', 'biometric'],
            phishing_resistant_mfa_available: true,
            mfa_coverage_percentage: 100,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 50
          }
        },
        {
          id: 4,
          name: 'Vulnerability Management',
          passed: 4,
          total: 4,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            {
              name: '3 monthly scans in last 90 days',
              passed: true,
              detail: 'Weekly scans (12 in last 90 days) - Exceeds requirement!'
            },
            {
              name: 'Pentest within 12 months',
              passed: true,
              detail: 'Last pentest: 2025-07-01 (3 months ago), next scheduled 2026-01-01'
            },
            {
              name: 'Vulnerability SLAs met',
              passed: true,
              detail: 'SLA: Critical 24h, High 7d, Medium 30d - All met'
            },
            {
              name: 'Critical/high pentest findings remediated',
              passed: true,
              detail: 'All findings remediated within 48 hours'
            }
          ],
          risks: [],
          source_document: 'cloudstore_soc2_type2.pdf, page 35-45',
          extraction_confidence: 0.97,
          soc2_overlap: 80,
          structuredData: {
            evidence_type: 'assure_004_vulnerability_mgmt',
            vendor_name: 'CloudStore Pro',
            evidence_date: '2025-10-16',
            scans_last_3_months: [
              { scan_date: '2025-10-08', scanner_tool: 'Wiz', scan_type: 'authenticated', critical_findings: 0, high_findings: 0, medium_findings: 1, low_findings: 3 },
              { scan_date: '2025-10-01', scanner_tool: 'Wiz', scan_type: 'authenticated', critical_findings: 0, high_findings: 0, medium_findings: 2, low_findings: 4 },
              { scan_date: '2025-09-24', scanner_tool: 'Wiz', scan_type: 'authenticated', critical_findings: 0, high_findings: 0, medium_findings: 1, low_findings: 5 }
            ],
            penetration_test: {
              test_date: '2025-07-01',
              tester_firm: 'Bishop Fox',
              test_type: 'comprehensive',
              critical_findings: 0,
              high_findings: 0,
              medium_findings: 2,
              low_findings: 4,
              all_critical_high_remediated: true
            },
            bug_bounty: {
              active: true,
              platform: 'HackerOne',
              program_url: 'https://hackerone.com/cloudstore'
            },
            vulnerability_sla_met: true,
            extraction_confidence: 0.97,
            soc2_coverage_percentage: 80
          }
        },
        {
          id: 9,
          name: 'Production Access Controls',
          passed: 6,
          total: 6,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            {
              name: 'JIT access method',
              passed: true,
              detail: 'Teleport-based just-in-time access with certificate-based authentication'
            },
            {
              name: 'Default access is "none"',
              passed: true,
              detail: 'Zero standing privileges - all access requires approval + justification'
            },
            {
              name: 'MFA required for privileged access',
              passed: true,
              detail: 'WebAuthn/FIDO2 required for all production operations'
            },
            {
              name: 'Max session duration < 4 hours',
              passed: true,
              detail: 'Sessions expire after 1 hour with automatic credential rotation'
            },
            {
              name: 'No persistent access allowed',
              passed: true,
              detail: 'All access is ephemeral - no standing access to any account'
            },
            {
              name: 'Privileged accounts segregated',
              passed: true,
              detail: 'Dedicated privileged access workstations (PAWs) for admin tasks'
            }
          ],
          risks: [],
          source_document: 'cloudstore_soc2_type2.pdf, page 60-65',
          extraction_confidence: 0.99,
          soc2_overlap: 95,
          structuredData: {
            evidence_type: 'assure_009_production_access',
            vendor_name: 'CloudStore Pro',
            evidence_date: '2025-10-16',
            access_method: 'jit',
            default_access: 'none',
            mfa_required_for_privileged: true,
            max_session_duration: '1_hour',
            persistent_access_allowed: false,
            privileged_accounts_segregated: true,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 95,
            soc2_section_4_criteria: ['CC5.2', 'CC6.1', 'CC6.2']
          }
        },
        {
          id: 12,
          name: 'Encryption at Rest',
          passed: 8,
          total: 8,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            {
              name: 'Database encrypted',
              passed: true,
              detail: 'Aurora PostgreSQL: AES-256 with AWS KMS + Nitro Enclaves'
            },
            {
              name: 'File storage encrypted',
              passed: true,
              detail: 'S3: SSE-KMS with customer-managed keys (CMK)'
            },
            {
              name: 'Object storage encrypted',
              passed: true,
              detail: 'All object stores use envelope encryption with CMKs'
            },
            {
              name: 'Backups encrypted',
              passed: true,
              detail: 'Automated backups encrypted with separate backup-specific keys'
            },
            {
              name: 'Strong algorithms (AES-256 or equivalent)',
              passed: true,
              detail: 'AES-256-GCM uniformly across all infrastructure'
            },
            {
              name: 'Key management via HSM/KMS',
              passed: true,
              detail: 'AWS CloudHSM (FIPS 140-2 Level 3 certified)'
            },
            {
              name: 'Key rotation enabled',
              passed: true,
              detail: 'Automatic rotation every 30 days for all CMKs'
            },
            {
              name: 'FIPS 140-2 compliant',
              passed: true,
              detail: 'Full stack validated: HSM + application crypto libraries'
            }
          ],
          risks: [],
          source_document: 'cloudstore_soc2_type2.pdf, page 45-52',
          extraction_confidence: 0.99,
          soc2_overlap: 95,
          structuredData: {
            evidence_type: 'assure_012_encryption_at_rest',
            vendor_name: 'CloudStore Pro',
            evidence_date: '2025-10-16',
            encrypted_stores: [
              {
                store_type: 'database',
                store_name: 'Aurora PostgreSQL (production)',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_cloudhsm',
                key_rotation_enabled: true
              },
              {
                store_type: 'file_storage',
                store_name: 'S3 production buckets',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_cloudhsm',
                key_rotation_enabled: true
              },
              {
                store_type: 'object_storage',
                store_name: 'S3 customer content',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_cloudhsm',
                key_rotation_enabled: true
              },
              {
                store_type: 'backups',
                store_name: 'Aurora automated backups',
                is_encrypted: true,
                encryption_algorithm: 'aes_256',
                key_management: 'aws_cloudhsm',
                key_rotation_enabled: true
              }
            ],
            key_rotation_enabled: true,
            fips_140_2_compliant: true,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 95,
            soc2_section_4_criteria: ['CC6.1', 'CC6.6', 'CC6.7']
          }
        },
        {
          id: 13,
          name: 'Encryption in Transit',
          passed: 7,
          total: 7,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            { name: 'TLS 1.2 or higher supported', passed: true, detail: 'TLS 1.3 only (1.2 disabled)' },
            { name: 'Weak protocols disabled', passed: true, detail: 'SSL v2/v3, TLS 1.0/1.1/1.2 all disabled' },
            { name: 'Valid certificate from trusted CA', passed: true, detail: 'DigiCert EV SSL, expires 2026-08-30' },
            { name: 'Certificate not expired', passed: true, detail: 'Valid for 10 months' },
            { name: 'Qualys SSL Labs grade A+', passed: true, detail: 'Grade A+ achieved' },
            { name: 'Forward secrecy enabled', passed: true, detail: 'All cipher suites use ECDHE' },
            { name: 'HSTS enabled', passed: true, detail: 'max-age=31536000; includeSubDomains; preload' }
          ],
          risks: [],
          source_document: 'cloudstore_network_security_2024.pdf',
          extraction_confidence: 0.99,
          soc2_overlap: 85,
          structuredData: {
            evidence_type: 'assure_013_encryption_in_transit',
            tls_versions_supported: ['tls_1_3'],
            weak_protocols_blocked: ['ssl_v2', 'ssl_v3', 'tls_1_0', 'tls_1_1', 'tls_1_2'],
            certificate_authority: 'digicert_ev',
            certificate_expiry_date: '2026-08-30',
            qualys_ssl_grade: 'A+',
            forward_secrecy_enabled: true,
            hsts_enabled: true,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 85,
            soc2_section_4_criteria: ['CC6.1', 'CC6.6', 'CC6.7']
          }
        },
        {
          id: 5,
          name: 'Incident Response',
          passed: 8,
          total: 8,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            { name: 'IR plan exists and documented', passed: true, detail: 'Comprehensive IR playbook v5.1, ISO 27035 aligned' },
            { name: 'IR plan tested annually', passed: true, detail: 'Last tested: 2024-09-15 (red team exercise)' },
            { name: 'Security breach SLA defined', passed: true, detail: '30 minute notification SLA' },
            { name: 'Privacy breach SLA defined', passed: true, detail: '2 hour notification (exceeds GDPR requirements)' },
            { name: 'Incident types covered', passed: true, detail: 'All types: security, privacy, availability, integrity, compliance' },
            { name: 'Lessons learned documented', passed: true, detail: 'Post-incident reviews mandatory, tracked in Jira' },
            { name: 'Plan accessible to employees', passed: true, detail: 'Available in wiki, Slack, PagerDuty runbooks' },
            { name: 'Contact information current', passed: true, detail: 'Automated on-call rotation via PagerDuty' }
          ],
          risks: [],
          source_document: 'cloudstore_incident_response_plan_2024.pdf',
          extraction_confidence: 0.99,
          soc2_overlap: 90,
          structuredData: {
            evidence_type: 'assure_005_incident_response',
            ir_plan_exists: true,
            last_test_date: '2024-09-15',
            test_type: 'red_team',
            incident_types_covered: ['security_breach', 'privacy_breach', 'availability', 'data_integrity', 'compliance'],
            security_breach_sla: '30_minutes',
            privacy_breach_sla: '2_hours',
            lessons_learned_documented: true,
            plan_accessible_to_employees: true,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 90,
            soc2_section_4_criteria: ['CC7.3', 'CC7.4', 'CC7.5']
          }
        },
        {
          id: 14,
          name: 'Logging Configuration',
          passed: 6,
          total: 6,
          percentage: 100.0,
          status: 'compliant',
          requirements: [
            { name: 'Log retention ≥ 90 days', passed: true, detail: '7 years for security logs (compliance requirement)' },
            { name: 'Security logs collected', passed: true, detail: 'Comprehensive: auth, authz, admin, config, network, data access' },
            { name: 'Centralized logging', passed: true, detail: 'Splunk Enterprise Security with SIEM capabilities' },
            { name: 'Logs immutable', passed: true, detail: 'S3 Object Lock (Governance mode) + WORM storage' },
            { name: 'Log monitoring/alerting configured', passed: true, detail: 'Real-time ML-based anomaly detection' },
            { name: 'Access logs protected', passed: true, detail: 'Security team only, audit trail of all log access' }
          ],
          risks: [],
          source_document: 'cloudstore_logging_architecture_2024.pdf',
          extraction_confidence: 0.99,
          soc2_overlap: 88,
          structuredData: {
            evidence_type: 'assure_014_logging_config',
            retention_period: '7_years',
            log_types_collected: ['security', 'access', 'audit', 'application', 'network', 'data_access'],
            monitoring_tool: 'splunk_es',
            logs_immutable: true,
            centralized_logging: true,
            extraction_confidence: 0.99,
            soc2_coverage_percentage: 88,
            soc2_section_4_criteria: ['CC7.2', 'CC8.1']
          }
        }
      ]
    }
  ],

  // ASSURE Control definitions (full 24, but we only have evidence for 3)
  controls: [
    { id: 1, name: 'Architecture & Segmentation', category: 'infrastructure', criticality: 'high' },
    { id: 2, name: 'Data Mapping', category: 'data', criticality: 'high' },
    { id: 3, name: 'Risk Assessment', category: 'governance', criticality: 'high' },
    { id: 4, name: 'Vulnerability Management', category: 'security', criticality: 'critical' },
    { id: 5, name: 'Incident Response', category: 'security', criticality: 'high' },
    { id: 6, name: 'Backup Configuration', category: 'continuity', criticality: 'medium' },
    { id: 7, name: 'BCP/DR Testing', category: 'continuity', criticality: 'high' },
    { id: 8, name: 'Access Reviews', category: 'access', criticality: 'medium' },
    { id: 9, name: 'Production Access Controls', category: 'access', criticality: 'critical' },
    { id: 10, name: 'Network ACLs', category: 'network', criticality: 'high' },
    { id: 11, name: '2FA Validation', category: 'access', criticality: 'high' },
    { id: 12, name: 'Encryption at Rest', category: 'encryption', criticality: 'critical' },
    { id: 13, name: 'Encryption in Transit', category: 'encryption', criticality: 'critical' },
    { id: 14, name: 'Logging Configuration', category: 'monitoring', criticality: 'high' },
    { id: 15, name: 'Security Alerts', category: 'monitoring', criticality: 'high' },
    { id: 16, name: 'Branch Protections', category: 'change', criticality: 'medium' },
    { id: 17, name: 'Change Control', category: 'change', criticality: 'medium' },
    { id: 18, name: 'Checksums/FIM', category: 'integrity', criticality: 'medium' },
    { id: 19, name: 'CIS Scan', category: 'compliance', criticality: 'medium' },
    { id: 20, name: 'Hosting Verification', category: 'infrastructure', criticality: 'low' },
    { id: 21, name: 'Confidentiality Contract', category: 'legal', criticality: 'high' },
    { id: 22, name: 'Compliance Contract', category: 'legal', criticality: 'high' },
    { id: 23, name: 'SSO/MFA Requirements', category: 'access', criticality: 'critical' },
    { id: 24, name: 'AI Controls', category: 'emerging', criticality: 'medium' }
  ],

  // Risk definitions
  risks: [
    {
      id: 'r1',
      name: 'Data Breach',
      severity: 'critical',
      affectedControls: [4, 7, 9, 12, 13, 23],
      description: 'Unauthorized access to sensitive customer data'
    },
    {
      id: 'r2',
      name: 'Service Disruption',
      severity: 'high',
      affectedControls: [3, 6, 7, 14],
      description: 'Extended downtime affecting business operations'
    },
    {
      id: 'r3',
      name: 'Unauthorized Access',
      severity: 'high',
      affectedControls: [1, 9, 10, 23],
      description: 'Compromised credentials or authentication bypass'
    },
    {
      id: 'r4',
      name: 'Data Loss',
      severity: 'high',
      affectedControls: [6, 7, 12],
      description: 'Permanent loss of customer data'
    },
    {
      id: 'r5',
      name: 'Compliance Violation',
      severity: 'medium',
      affectedControls: [2, 19, 21, 22],
      description: 'Failure to meet regulatory requirements'
    }
  ]
};

/**
 * Helper functions for dashboard calculations
 */

// Calculate vendor overall compliance percentage
function getVendorCompliance(vendor) {
  const totalRequirements = vendor.controls.reduce((sum, c) => sum + c.total, 0);
  const passedRequirements = vendor.controls.reduce((sum, c) => sum + c.passed, 0);
  return ((passedRequirements / totalRequirements) * 100).toFixed(1);
}

// Calculate average compliance across all vendors for a specific control
function getControlAvgCompliance(controlId) {
  const vendorsWithControl = mockEvidence.vendors.filter(v =>
    v.controls.some(c => c.id === controlId)
  );

  if (vendorsWithControl.length === 0) return 0;

  const totalPassed = vendorsWithControl.reduce((sum, v) => {
    const ctrl = v.controls.find(c => c.id === controlId);
    return sum + ctrl.passed;
  }, 0);

  const totalRequirements = vendorsWithControl.reduce((sum, v) => {
    const ctrl = v.controls.find(c => c.id === controlId);
    return sum + ctrl.total;
  }, 0);

  return ((totalPassed / totalRequirements) * 100).toFixed(1);
}

// Get compliance status from percentage
function getComplianceStatus(percentage) {
  if (percentage >= 85) return 'compliant';
  if (percentage >= 50) return 'partially_compliant';
  return 'non_compliant';
}

// Get edge color based on percentage
function getEdgeColor(percentage) {
  if (percentage >= 85) return '#10b981';  // Green
  if (percentage >= 70) return '#f59e0b';  // Orange
  return '#ef4444';  // Red
}

// Get edge style (solid or dashed)
function getEdgeStyle(percentage) {
  return percentage >= 70 ? 'solid' : 'dash';
}

// Count total risks across all vendors
function getTotalRisks() {
  const allRisks = new Set();
  mockEvidence.vendors.forEach(v => {
    v.controls.forEach(c => {
      c.risks.forEach(r => allRisks.add(r));
    });
  });
  return allRisks.size;
}

// Export for use in React app (ES6 modules)
export {
  mockEvidence,
  getVendorCompliance,
  getControlAvgCompliance,
  getComplianceStatus,
  getEdgeColor,
  getEdgeStyle,
  getTotalRisks
}

// Also export as default for convenience
export default mockEvidence
