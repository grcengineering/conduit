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
      ,
// Evidence #1: Architecture & Segmentation
  {
    id: 1,
    name: 'Architecture & Segmentation',
    passed: 7,
    total: 10,
    percentage: 70.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Network segmentation documented', passed: true, detail: 'VPC-based segmentation with public/private subnets' },
      { name: 'Default deny firewall rules', passed: true, detail: 'AWS Security Groups configured with default deny' },
      { name: 'Customer data isolation', passed: true, detail: 'Separate databases per customer tenant' },
      { name: 'DMZ for public services', passed: false, detail: 'No DMZ - all services in same VPC' },
      { name: 'Production/non-prod separation', passed: true, detail: 'Separate AWS accounts for prod vs staging' },
      { name: 'Network diagram available', passed: true, detail: 'Architecture diagram in SOC 2 Section 3' },
      { name: 'Zero trust architecture', passed: false, detail: 'Traditional VPN-based access, not zero trust' },
      { name: 'Micro-segmentation implemented', passed: false, detail: 'Macro-segmentation only (VPC level)' },
      { name: 'Subprocessor list maintained', passed: true, detail: '8 subprocessors documented (AWS, SendGrid, Stripe, etc.)' },
      { name: 'SBOM available', passed: true, detail: 'Software Bill of Materials provided in trust center' }
    ],
    risks: [
      'Lack of DMZ increases attack surface for public APIs',
      'No zero trust increases lateral movement risk'
    ],
    source_document: 'acme_soc2_report.pdf, page 12-18',
    extraction_confidence: 0.88,
    soc2_overlap: 75,
    structuredData: {
      evidence_type: 'assure_001_architecture',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      network_segmentation_exists: true,
      segmentation_method: 'vpc',
      default_deny_configured: true,
      customer_data_isolated: true,
      dmz_implemented: false,
      production_nonprod_separated: true,
      zero_trust_architecture: false,
      network_diagram_available: true,
      subprocessors_documented: true,
      subprocessor_count: 8,
      sbom_available: true,
      extraction_confidence: 0.88,
      soc2_coverage_percentage: 75
    }
  },

  // Evidence #2: Data Mapping & Subprocessors
  {
    id: 2,
    name: 'Data Mapping & Subprocessors',
    passed: 6,
    total: 10,
    percentage: 60.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Data mapping exercise performed', passed: true, detail: 'Last performed: Q2 2025' },
      { name: 'Data types documented', passed: true, detail: 'Customer data, transaction data, analytics data documented' },
      { name: 'Data purposes documented', passed: true, detail: 'Purposes: Service delivery, analytics, support' },
      { name: 'Data flows mapped', passed: false, detail: 'Data flows not comprehensively mapped' },
      { name: 'Subprocessor list complete', passed: true, detail: '8 subprocessors listed with data access details' },
      { name: 'Subprocessor data types documented', passed: false, detail: 'Not all subprocessors have data types specified' },
      { name: 'Data retention periods defined', passed: true, detail: 'Retention: 30 days after termination' },
      { name: 'Data deletion process documented', passed: false, detail: 'Deletion process not fully documented' },
      { name: 'SBOM maintained', passed: true, detail: 'SBOM includes 45 dependencies' },
      { name: 'Data residency disclosed', passed: false, detail: 'Data residency (US-East-1) not explicitly disclosed' }
    ],
    risks: [
      'Incomplete data flow mapping creates blind spots',
      'Undefined data deletion process may violate GDPR'
    ],
    source_document: 'acme_data_mapping.pdf, acme_dpa.pdf',
    extraction_confidence: 0.82,
    soc2_overlap: 40,
    structuredData: {
      evidence_type: 'assure_002_data_mapping',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      data_mapping_performed: true,
      data_mapping_date: '2025-06-15',
      data_types_documented: true,
      data_types: ['customer_data', 'transaction_data', 'analytics_data'],
      data_purposes_documented: true,
      data_flows_mapped: false,
      subprocessors_documented: true,
      subprocessor_count: 8,
      sbom_maintained: true,
      sbom_dependency_count: 45,
      data_residency_disclosed: false,
      extraction_confidence: 0.82,
      soc2_coverage_percentage: 40
    }
  },

  // Evidence #6: Backup Configuration
  {
    id: 6,
    name: 'Backup Configuration',
    passed: 6,
    total: 8,
    percentage: 75.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Automated backups enabled', passed: true, detail: 'Daily automated backups at 2 AM UTC' },
      { name: 'Backup frequency ≥ daily', passed: true, detail: 'Daily full backups, hourly incremental' },
      { name: 'Backup retention ≥ 30 days', passed: true, detail: '90-day retention for production backups' },
      { name: 'Backup encryption enabled', passed: true, detail: 'AES-256 encryption for all backups' },
      { name: 'Backup testing performed', passed: false, detail: 'Last backup restore test: 8 months ago (overdue)' },
      { name: 'Offsite/geographic redundancy', passed: true, detail: 'Backups replicated to us-west-2' },
      { name: 'Backup monitoring/alerts', passed: false, detail: 'No automated alerts for backup failures' },
      { name: 'Immutable backups', passed: true, detail: 'WORM storage for 90-day retention tier' }
    ],
    risks: [
      'Backup test overdue - restore capability unverified',
      'No backup failure alerts may cause silent data loss'
    ],
    source_document: 'acme_soc2_report.pdf, page 52-54',
    extraction_confidence: 0.91,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_006_backup_configuration',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      automated_backups: true,
      backup_frequency: 'daily',
      backup_retention_days: 90,
      backup_encrypted: true,
      backup_encryption_algorithm: 'aes_256',
      backup_testing_performed: false,
      last_backup_test_date: '2025-02-15',
      offsite_backups: true,
      backup_monitoring: false,
      immutable_backups: true,
      extraction_confidence: 0.91,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #8: Access Reviews
  {
    id: 8,
    name: 'Access Reviews',
    passed: 5,
    total: 8,
    percentage: 62.5,
    status: 'partially_compliant',
    requirements: [
      { name: 'Access reviews performed', passed: true, detail: 'Last review: 2025-09-01 (45 days ago)' },
      { name: 'Review frequency ≤ 90 days', passed: true, detail: 'Quarterly access reviews' },
      { name: 'All systems in scope', passed: false, detail: 'Only production systems reviewed, not internal tools' },
      { name: 'Review includes privileged accounts', passed: true, detail: 'Admin and root accounts reviewed' },
      { name: 'Terminated users removed', passed: true, detail: 'All terminated users removed within 24 hours' },
      { name: 'Stale accounts detected', passed: false, detail: '12 accounts inactive >90 days not flagged' },
      { name: 'Review approval documented', passed: true, detail: 'VP Engineering approved last review' },
      { name: 'Remediation tracking', passed: false, detail: 'No tracking for access review findings' }
    ],
    risks: [
      'Stale accounts create unauthorized access risk',
      'Incomplete scope misses internal tool access'
    ],
    source_document: 'acme_access_review_q3_2025.pdf',
    extraction_confidence: 0.86,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_008_access_reviews',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      access_reviews_performed: true,
      last_review_date: '2025-09-01',
      review_frequency_days: 90,
      all_systems_in_scope: false,
      privileged_accounts_reviewed: true,
      terminated_users_removed: true,
      stale_accounts_detected: false,
      review_approval_documented: true,
      remediation_tracking: false,
      extraction_confidence: 0.86,
      soc2_coverage_percentage: 85
    }
  },

  // Evidence #15: Security Alerts
  {
    id: 15,
    name: 'Security Alerts',
    passed: 7,
    total: 10,
    percentage: 70.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Security alerting configured', passed: true, detail: 'AWS GuardDuty + Datadog Security Monitoring' },
      { name: 'Failed login alerts', passed: true, detail: 'Alert after 5 failed attempts in 10 minutes' },
      { name: 'Privilege escalation alerts', passed: true, detail: 'IAM policy changes trigger alerts' },
      { name: 'Malware detection alerts', passed: false, detail: 'No endpoint malware detection configured' },
      { name: 'Data exfiltration alerts', passed: true, detail: 'Unusual data transfer volume alerts' },
      { name: 'Security tool tampering alerts', passed: false, detail: 'No alerts for logging/monitoring service disruption' },
      { name: 'Alert routing to SOC/SIEM', passed: true, detail: 'All alerts route to Datadog + PagerDuty' },
      { name: 'Alert response time SLA', passed: true, detail: 'Critical: 15 min, High: 1 hour' },
      { name: 'Alert tuning performed', passed: false, detail: 'No documented alert tuning process' },
      { name: 'Alert effectiveness metrics', passed: true, detail: 'Alert false positive rate tracked (currently 8%)' }
    ],
    risks: [
      'No malware detection creates blind spot',
      'Security tool tampering not detected'
    ],
    source_document: 'acme_security_monitoring.pdf, acme_soc2_report.pdf page 67-69',
    extraction_confidence: 0.89,
    soc2_overlap: 75,
    structuredData: {
      evidence_type: 'assure_015_security_alerts',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      security_alerting_configured: true,
      alerting_tool: 'datadog_security',
      failed_login_alerts: true,
      privilege_escalation_alerts: true,
      malware_detection_alerts: false,
      data_exfiltration_alerts: true,
      security_tool_tampering_alerts: false,
      alert_routing_to_soc: true,
      alert_response_time_sla_exists: true,
      critical_alert_response_minutes: 15,
      alert_tuning_performed: false,
      alert_effectiveness_tracked: true,
      extraction_confidence: 0.89,
      soc2_coverage_percentage: 75
    }
  },
// Evidence #3: Patch Management
  {
    id: 3,
    name: 'Patch Management',
    passed: 6,
    total: 10,
    percentage: 60.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Patch management policy documented', passed: true, detail: 'Policy documented in security handbook' },
      { name: 'Critical patches ≤7 days', passed: false, detail: 'Average: 15 days (SLA breach)' },
      { name: 'High patches ≤30 days', passed: true, detail: 'Average: 22 days' },
      { name: 'Automated patching for non-prod', passed: true, detail: 'Dev/staging auto-patched weekly' },
      { name: 'Automated patching for prod', passed: false, detail: 'Manual approval required, slows deployment' },
      { name: 'Patch testing before prod', passed: true, detail: 'Tested in staging for 48 hours' },
      { name: 'Patch monitoring/tracking', passed: true, detail: 'Tracked via Jira + Qualys' },
      { name: 'Emergency patching process', passed: true, detail: 'Emergency process allows 24h patching' },
      { name: 'OS and application patching', passed: true, detail: 'Both OS and apps patched' },
      { name: 'Patch rollback capability', passed: false, detail: 'Manual rollback only, no automation' }
    ],
    risks: [
      'Critical patches delayed beyond 7 days increases exploit window',
      'No automated prod patching slows response to zero-days',
      'Manual rollback may be slow during incidents'
    ],
    source_document: 'acme_patch_policy.pdf, acme_qualys_report.pdf',
    extraction_confidence: 0.87,
    soc2_overlap: 70,
    structuredData: {
      evidence_type: 'assure_003_patch_management',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      patch_policy_documented: true,
      critical_patch_sla_days: 15,
      high_patch_sla_days: 22,
      automated_patching_nonprod: true,
      automated_patching_prod: false,
      patch_testing_required: true,
      patch_monitoring_enabled: true,
      emergency_patching_process: true,
      os_patching_enabled: true,
      application_patching_enabled: true,
      patch_rollback_capability: false,
      extraction_confidence: 0.87,
      soc2_coverage_percentage: 70
    }
  },

  // Evidence #10: Network ACLs
  {
    id: 10,
    name: 'Network ACLs',
    passed: 6,
    total: 8,
    percentage: 75.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Network ACLs configured', passed: true, detail: 'AWS Security Groups + NACLs configured' },
      { name: 'Default deny policy', passed: true, detail: 'Default deny, explicit allow rules only' },
      { name: 'Least privilege access', passed: true, detail: 'Port 443 only for public services' },
      { name: 'ACL documentation maintained', passed: true, detail: 'Security group documentation in Confluence' },
      { name: 'ACL review frequency ≤90 days', passed: false, detail: 'Quarterly reviews (90 days exactly, should be monthly)' },
      { name: 'No overly permissive rules', passed: false, detail: '3 rules with 0.0.0.0/0 for non-public services' },
      { name: 'ACL change approval', passed: true, detail: 'Security team approval required via Terraform PR' },
      { name: 'ACL monitoring/alerting', passed: true, detail: 'AWS Config monitors rule changes' }
    ],
    risks: [
      'Overly permissive rules increase attack surface',
      'Quarterly ACL reviews may miss unauthorized changes'
    ],
    source_document: 'acme_network_architecture.pdf, aws_security_groups.tf',
    extraction_confidence: 0.89,
    soc2_overlap: 75,
    structuredData: {
      evidence_type: 'assure_010_network_acls',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      network_acls_configured: true,
      default_deny_policy: true,
      least_privilege_access: true,
      acl_documentation_maintained: true,
      acl_review_frequency_days: 90,
      overly_permissive_rules_exist: true,
      acl_change_approval_required: true,
      acl_monitoring_enabled: true,
      extraction_confidence: 0.89,
      soc2_coverage_percentage: 75
    }
  },

  // Evidence #11: 2FA for Admin Access
  {
    id: 11,
    name: '2FA for Admin Access',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: '2FA required for all admins', passed: true, detail: '100% admin accounts have 2FA enforced' },
      { name: '2FA enforced at login', passed: true, detail: 'Okta enforces 2FA before access' },
      { name: 'Multiple 2FA methods available', passed: true, detail: 'TOTP, SMS, push notifications' },
      { name: 'Phishing-resistant 2FA available', passed: false, detail: 'No WebAuthn/FIDO2, SMS is phishable' },
      { name: '2FA recovery process documented', passed: true, detail: 'Recovery codes + helpdesk process' },
      { name: '2FA compliance monitored', passed: true, detail: 'Weekly reports on 2FA adoption' },
      { name: '2FA bypass prohibited', passed: true, detail: 'No emergency bypass, only recovery codes' },
      { name: 'Session timeout after 2FA', passed: true, detail: 'Sessions expire after 8 hours' }
    ],
    risks: [
      'SMS-based 2FA vulnerable to SIM swapping attacks'
    ],
    source_document: 'acme_okta_config.pdf, acme_iam_policy.pdf',
    extraction_confidence: 0.92,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_011_admin_2fa',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      two_fa_required_for_admins: true,
      two_fa_enforced_at_login: true,
      multiple_2fa_methods: true,
      phishing_resistant_2fa_available: false,
      two_fa_recovery_process: true,
      two_fa_compliance_monitored: true,
      two_fa_bypass_prohibited: true,
      session_timeout_configured: true,
      session_timeout_hours: 8,
      extraction_confidence: 0.92,
      soc2_coverage_percentage: 85
    }
  },

  // Evidence #16: Change Management
  {
    id: 16,
    name: 'Change Management',
    passed: 7,
    total: 10,
    percentage: 70.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Change management process documented', passed: true, detail: 'Change policy in handbook' },
      { name: 'Change approval required', passed: true, detail: 'Lead engineer approval for all changes' },
      { name: 'Change testing required', passed: true, detail: 'Staging testing mandatory' },
      { name: 'Change rollback plan', passed: true, detail: 'Rollback documented in change ticket' },
      { name: 'Change logging enabled', passed: true, detail: 'All changes tracked in Jira' },
      { name: 'Emergency change process', passed: false, detail: 'Emergency process not well-defined' },
      { name: 'CAB for high-risk changes', passed: false, detail: 'No Change Advisory Board' },
      { name: 'Change success rate tracked', passed: true, detail: 'Success rate: 94%' },
      { name: 'Post-implementation review', passed: true, detail: 'PIR within 48 hours of change' },
      { name: 'Change communication', passed: false, detail: 'Customer notification inconsistent' }
    ],
    risks: [
      'No CAB increases risk of poorly-reviewed high-impact changes',
      'Emergency change process gaps may cause rushed deployments',
      'Inconsistent customer communication damages trust'
    ],
    source_document: 'acme_change_policy.pdf, jira_change_records.csv',
    extraction_confidence: 0.85,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_016_change_management',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      documented_change_process: true,
      change_approval_required: true,
      change_testing_required: true,
      rollback_plan_required: true,
      change_logging_enabled: true,
      emergency_change_process_exists: false,
      cab_meeting_frequency: null,
      change_success_rate_percentage: 94.0,
      post_implementation_review_required: true,
      change_communication_process: false,
      extraction_confidence: 0.85,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #17: Code Review Requirements
  {
    id: 17,
    name: 'Code Review Requirements',
    passed: 6,
    total: 8,
    percentage: 75.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Code review required', passed: true, detail: 'All PRs require 1+ approvals' },
      { name: 'Peer review process', passed: true, detail: 'Senior engineer must review' },
      { name: 'Branch protection enabled', passed: false, detail: 'Branch protection not enforced on all repos' },
      { name: 'Security review for high-risk', passed: false, detail: 'No dedicated security review process' },
      { name: 'Automated code quality checks', passed: true, detail: 'ESLint, Prettier, SonarQube' },
      { name: 'Code review documentation', passed: true, detail: 'GitHub PR comments serve as docs' },
      { name: 'Review before merge', passed: true, detail: 'No direct commits to main' },
      { name: 'Code review metrics tracked', passed: true, detail: 'Average review time: 4 hours' }
    ],
    risks: [
      'Missing branch protection allows direct commits in some repos',
      'No security review for crypto/auth changes increases vuln risk'
    ],
    source_document: 'acme_sdlc_policy.pdf, github_repo_settings.json',
    extraction_confidence: 0.88,
    soc2_overlap: 70,
    structuredData: {
      evidence_type: 'assure_017_code_review',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      code_review_required: true,
      peer_review_required: true,
      branch_protection_enabled: false,
      security_review_for_high_risk: false,
      automated_code_quality_checks: true,
      code_review_documentation: true,
      review_before_merge_required: true,
      code_review_metrics_tracked: true,
      average_review_time_hours: 4,
      extraction_confidence: 0.88,
      soc2_coverage_percentage: 70
    }
  },

  // Evidence #18: Security Testing
  {
    id: 18,
    name: 'Security Testing',
    passed: 5,
    total: 8,
    percentage: 62.5,
    status: 'partially_compliant',
    requirements: [
      { name: 'SAST enabled', passed: true, detail: 'SonarQube scans on every commit' },
      { name: 'DAST performed', passed: false, detail: 'No dynamic application security testing' },
      { name: 'Dependency scanning', passed: false, detail: 'Ad-hoc dependency audits, not automated' },
      { name: 'Secrets scanning', passed: true, detail: 'GitGuardian monitors for leaked secrets' },
      { name: 'Penetration testing', passed: true, detail: 'Annual pentest (last: Mar 2024)' },
      { name: 'Vulnerability remediation SLA', passed: true, detail: 'Critical: 7d, High: 30d' },
      { name: 'Security testing in CI/CD', passed: true, detail: 'SAST + secrets in GitHub Actions' },
      { name: 'Security testing metrics', passed: false, detail: 'No dashboards for security testing coverage' }
    ],
    risks: [
      'No DAST misses runtime vulnerabilities (SQLi, XSS)',
      'Ad-hoc dependency scanning misses supply chain vulns',
      'No security metrics creates visibility gap'
    ],
    source_document: 'acme_appsec_policy.pdf, sonarqube_config.yml',
    extraction_confidence: 0.84,
    soc2_overlap: 75,
    structuredData: {
      evidence_type: 'assure_018_security_testing',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      sast_enabled: true,
      dast_performed: false,
      dependency_scanning_enabled: false,
      secrets_scanning_enabled: true,
      penetration_testing_performed: true,
      last_pentest_date: '2024-03-15',
      vulnerability_remediation_sla_exists: true,
      security_testing_in_cicd: true,
      security_testing_metrics_tracked: false,
      extraction_confidence: 0.84,
      soc2_coverage_percentage: 75
    }
  },
// Evidence #19: Service Level Agreements
  {
    id: 19,
    name: 'Service Level Agreements',
    passed: 5,
    total: 7,
    percentage: 71.4,
    status: 'partially_compliant',
    requirements: [
      { name: 'SLA documented in contract', passed: true, detail: 'Service Terms, Section 8' },
      { name: 'Availability SLA ≥99.9%', passed: true, detail: '99.9% quarterly uptime commitment' },
      { name: 'Response time SLAs defined', passed: false, detail: 'Response times are internal targets, not contractual' },
      { name: 'Resolution time SLAs defined', passed: false, detail: 'Resolution SLAs not contractually committed' },
      { name: 'Financial remedies for violations', passed: true, detail: 'Service credits up to 25% of monthly fees' },
      { name: 'SLA performance reporting', passed: false, detail: 'No regular SLA reports provided to customers' },
      { name: 'SLA monitoring/public status', passed: true, detail: 'Public status page at status.acme.com' }
    ],
    risks: [
      'Non-contractual response/resolution SLAs lack enforceability',
      'No SLA reporting reduces transparency'
    ],
    source_document: 'acme_service_terms.pdf',
    extraction_confidence: 0.85,
    soc2_overlap: 70,
    structuredData: {
      evidence_type: 'assure_019_sla',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      sla_documented: true,
      availability_percentage: 99.9,
      availability_measurement_period: 'quarterly',
      response_time_sla_exists: false,
      resolution_time_sla_exists: false,
      violation_remedies_defined: true,
      service_credits_available: true,
      service_credit_percentage: 25.0,
      sla_performance_monitored: true,
      sla_reporting_frequency: null,
      public_status_page: true,
      extraction_confidence: 0.85,
      soc2_coverage_percentage: 70
    }
  },

  // Evidence #20: Data Retention & Deletion
  {
    id: 20,
    name: 'Data Retention & Deletion',
    passed: 6,
    total: 8,
    percentage: 75.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Retention policy documented', passed: true, detail: 'DPA Exhibit B: Data Retention Policy' },
      { name: 'Retention periods defined by data type', passed: true, detail: 'Customer data: 30 days, Logs: 1 year' },
      { name: 'Deletion on customer request ≤30 days', passed: true, detail: '30-day deletion SLA documented' },
      { name: 'Secure deletion method', passed: false, detail: 'Deletion method not specified in policy' },
      { name: 'Deletion certificate available', passed: true, detail: 'Certificate provided upon request' },
      { name: 'Backup data included in deletion', passed: true, detail: 'Backups purged within 90 days' },
      { name: 'GDPR/CCPA compliant deletion', passed: true, detail: 'Right to erasure supported' },
      { name: 'Deletion verification process', passed: false, detail: 'No automated deletion verification' }
    ],
    risks: [
      'Unspecified deletion method may not meet secure deletion standards',
      'No verification process may leave residual data'
    ],
    source_document: 'acme_dpa.pdf',
    extraction_confidence: 0.82,
    soc2_overlap: 50,
    structuredData: {
      evidence_type: 'assure_020_data_retention',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      retention_policy_documented: true,
      retention_periods_defined: true,
      customer_data_retention_days: 30,
      log_data_retention_days: 365,
      deletion_on_request_supported: true,
      deletion_request_timeframe_days: 30,
      deletion_method: null,
      deletion_certificate_provided: true,
      backups_included_in_deletion: true,
      backup_deletion_timeframe_days: 90,
      gdpr_compliant: true,
      ccpa_compliant: true,
      extraction_confidence: 0.82,
      soc2_coverage_percentage: 50
    }
  },

  // Evidence #21: Insurance Coverage
  {
    id: 21,
    name: 'Insurance Coverage',
    passed: 5,
    total: 6,
    percentage: 83.3,
    status: 'partially_compliant',
    requirements: [
      { name: 'Cyber liability insurance exists', passed: true, detail: 'Lloyd\'s of London cyber policy' },
      { name: 'Cyber coverage ≥$1M', passed: true, detail: '$2M cyber liability coverage' },
      { name: 'Cyber coverage ≥$5M (preferred)', passed: false, detail: 'Only $2M (below $5M preferred threshold)' },
      { name: 'E&O insurance exists', passed: true, detail: 'AIG professional liability policy' },
      { name: 'E&O coverage ≥$1M', passed: true, detail: '$3M E&O coverage' },
      { name: 'Certificate of Insurance available', passed: true, detail: 'COI available upon request' }
    ],
    risks: [
      '$2M cyber coverage may be insufficient for large breach (preferred: $5M+)'
    ],
    source_document: 'acme_insurance_attestation.pdf',
    extraction_confidence: 0.92,
    soc2_overlap: 30,
    structuredData: {
      evidence_type: 'assure_021_insurance',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      cyber_insurance_exists: true,
      cyber_insurance_carrier: 'Lloyd\'s of London',
      cyber_coverage_amount: 2000000,
      cyber_policy_expiry_date: '2025-12-31',
      eo_insurance_exists: true,
      eo_insurance_carrier: 'AIG',
      eo_coverage_amount: 3000000,
      certificate_of_insurance_available: true,
      policy_is_current: true,
      extraction_confidence: 0.92,
      soc2_coverage_percentage: 30
    }
  },

  // Evidence #22: Right to Audit
  {
    id: 22,
    name: 'Right to Audit',
    passed: 4,
    total: 7,
    percentage: 57.1,
    status: 'partially_compliant',
    requirements: [
      { name: 'Audit rights granted in contract', passed: false, detail: 'No explicit audit rights clause' },
      { name: 'Audit frequency at least annual', passed: false, detail: 'Not applicable - no audit rights' },
      { name: 'Reasonable advance notice (≤30 days)', passed: false, detail: 'Not applicable' },
      { name: 'Audit scope includes security', passed: true, detail: 'SOC 2 covers security controls' },
      { name: 'Third-party auditor allowed', passed: true, detail: 'SOC 2 by independent auditor' },
      { name: 'Vendor cooperation required', passed: true, detail: 'SOC 2 process requires cooperation' },
      { name: 'Reasonable cost allocation', passed: true, detail: 'SOC 2 report provided free to customers' }
    ],
    risks: [
      'No contractual audit rights limits customer validation options',
      'Must rely solely on annual SOC 2 report'
    ],
    source_document: 'acme_msa.pdf, acme_soc2_report.pdf',
    extraction_confidence: 0.78,
    soc2_overlap: 95,
    structuredData: {
      evidence_type: 'assure_022_audit_rights',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      audit_rights_granted: false,
      audit_frequency: null,
      advance_notice_days: null,
      audit_scope_includes_security: true,
      third_party_auditor_allowed: true,
      vendor_cooperation_required: true,
      cost_allocation: 'vendor',
      soc2_alternative_provided: true,
      extraction_confidence: 0.78,
      soc2_coverage_percentage: 95
    }
  },

  // Evidence #24: AI/ML Security Controls
  {
    id: 24,
    name: 'AI/ML Security Controls',
    passed: 4,
    total: 9,
    percentage: 44.4,
    status: 'non_compliant',
    requirements: [
      { name: 'AI systems inventory maintained', passed: false, detail: 'No formal AI inventory' },
      { name: 'AI risk assessment performed', passed: false, detail: 'No AI-specific risk assessment' },
      { name: 'Training data governance exists', passed: false, detail: 'No training data governance policy' },
      { name: 'Model validation/testing performed', passed: false, detail: 'No formal model validation' },
      { name: 'Bias testing performed', passed: false, detail: 'No bias testing conducted' },
      { name: 'Human oversight for critical decisions', passed: true, detail: 'AI recommendations reviewed by humans' },
      { name: 'Adversarial testing performed', passed: true, detail: 'Basic adversarial input testing' },
      { name: 'AI incident response plan', passed: true, detail: 'AI incidents covered by general IR plan' },
      { name: 'Third-party AI risk assessed', passed: true, detail: 'OpenAI assessed as subprocessor' }
    ],
    risks: [
      'No AI governance framework increases model risk',
      'No bias testing may result in discriminatory outcomes',
      'No model validation creates accuracy/reliability concerns'
    ],
    source_document: 'acme_ai_usage_statement.pdf',
    extraction_confidence: 0.68,
    soc2_overlap: 20,
    structuredData: {
      evidence_type: 'assure_024_ai_governance',
      vendor_name: 'Acme SaaS',
      evidence_date: '2025-10-16',
      ai_systems_used: true,
      ai_inventory_maintained: false,
      ai_use_cases: ['content_generation'],
      ai_risk_assessment_performed: false,
      training_data_governance_exists: false,
      model_validation_performed: false,
      bias_testing_performed: false,
      human_oversight_exists: true,
      adversarial_testing_performed: true,
      ai_incident_response_plan: true,
      third_party_ai_models_used: true,
      third_party_ai_risk_assessed: true,
      third_party_ai_vendors: ['OpenAI'],
      extraction_confidence: 0.68,
      soc2_coverage_percentage: 20
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
      ,
// Evidence #1: Architecture & Segmentation
  {
    id: 1,
    name: 'Architecture & Segmentation',
    passed: 8,
    total: 10,
    percentage: 80.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Network segmentation documented', passed: true, detail: 'Multi-tier architecture with app/data/web layers' },
      { name: 'Default deny firewall rules', passed: true, detail: 'Firewall rules follow least privilege' },
      { name: 'Customer data isolation', passed: true, detail: 'Logical separation per customer schema' },
      { name: 'DMZ for public services', passed: true, detail: 'DMZ implemented for public APIs' },
      { name: 'Production/non-prod separation', passed: true, detail: 'Separate environments in different VPCs' },
      { name: 'Network diagram available', passed: true, detail: 'Detailed network diagram provided' },
      { name: 'Zero trust architecture', passed: false, detail: 'Traditional perimeter security model' },
      { name: 'Micro-segmentation implemented', passed: false, detail: 'Macro-segmentation only' },
      { name: 'Subprocessor list maintained', passed: true, detail: '5 subprocessors documented' },
      { name: 'SBOM available', passed: true, detail: 'SBOM includes 62 dependencies' }
    ],
    risks: [
      'Traditional perimeter model vulnerable to lateral movement'
    ],
    source_document: 'dataflow_architecture_doc.pdf',
    extraction_confidence: 0.90,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_001_architecture',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      network_segmentation_exists: true,
      segmentation_method: 'multi_tier',
      default_deny_configured: true,
      customer_data_isolated: true,
      dmz_implemented: true,
      production_nonprod_separated: true,
      zero_trust_architecture: false,
      network_diagram_available: true,
      subprocessors_documented: true,
      subprocessor_count: 5,
      sbom_available: true,
      extraction_confidence: 0.90,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #2: Data Mapping
  {
    id: 2,
    name: 'Data Mapping & Subprocessors',
    passed: 8,
    total: 10,
    percentage: 80.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Data mapping exercise performed', passed: true, detail: 'Annual data mapping Q1 2025' },
      { name: 'Data types documented', passed: true, detail: 'All PII and sensitive data cataloged' },
      { name: 'Data purposes documented', passed: true, detail: 'Data processing purposes documented per GDPR' },
      { name: 'Data flows mapped', passed: true, detail: 'Comprehensive data flow diagrams' },
      { name: 'Subprocessor list complete', passed: true, detail: '5 subprocessors with contracts' },
      { name: 'Subprocessor data types documented', passed: true, detail: 'Data types specified for each subprocessor' },
      { name: 'Data retention periods defined', passed: true, detail: 'Retention: 60 days post-termination' },
      { name: 'Data deletion process documented', passed: true, detail: '30-day deletion SLA documented' },
      { name: 'SBOM maintained', passed: false, detail: 'SBOM not regularly updated' },
      { name: 'Data residency disclosed', passed: false, detail: 'Multi-region deployment not disclosed' }
    ],
    risks: [
      'Outdated SBOM creates supply chain risk'
    ],
    source_document: 'dataflow_dpa.pdf, dataflow_data_inventory.xlsx',
    extraction_confidence: 0.87,
    soc2_overlap: 60,
    structuredData: {
      evidence_type: 'assure_002_data_mapping',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      data_mapping_performed: true,
      data_mapping_date: '2025-03-01',
      data_types_documented: true,
      data_types: ['customer_data', 'pii', 'financial_data'],
      data_purposes_documented: true,
      data_flows_mapped: true,
      subprocessors_documented: true,
      subprocessor_count: 5,
      sbom_maintained: false,
      sbom_dependency_count: 62,
      data_residency_disclosed: false,
      extraction_confidence: 0.87,
      soc2_coverage_percentage: 60
    }
  },

  // Evidence #6: Backup Configuration
  {
    id: 6,
    name: 'Backup Configuration',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Automated backups enabled', passed: true, detail: 'Continuous backups via Azure Backup' },
      { name: 'Backup frequency ≥ daily', passed: true, detail: 'Continuous backup + daily snapshots' },
      { name: 'Backup retention ≥ 30 days', passed: true, detail: '180-day retention for compliance' },
      { name: 'Backup encryption enabled', passed: true, detail: 'AES-256 encryption at rest and in transit' },
      { name: 'Backup testing performed', passed: true, detail: 'Quarterly restore tests (last: 2025-09-15)' },
      { name: 'Offsite/geographic redundancy', passed: true, detail: 'Geo-redundant storage across 3 Azure regions' },
      { name: 'Backup monitoring/alerts', passed: true, detail: 'Automated alerts via Azure Monitor' },
      { name: 'Immutable backups', passed: false, detail: 'Backups not immutable (WORM not enabled)' }
    ],
    risks: [
      'Mutable backups vulnerable to ransomware'
    ],
    source_document: 'dataflow_backup_policy.pdf',
    extraction_confidence: 0.93,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_006_backup_configuration',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      automated_backups: true,
      backup_frequency: 'continuous',
      backup_retention_days: 180,
      backup_encrypted: true,
      backup_encryption_algorithm: 'aes_256',
      backup_testing_performed: true,
      last_backup_test_date: '2025-09-15',
      offsite_backups: true,
      backup_monitoring: true,
      immutable_backups: false,
      extraction_confidence: 0.93,
      soc2_coverage_percentage: 85
    }
  },

  // Evidence #8: Access Reviews
  {
    id: 8,
    name: 'Access Reviews',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Access reviews performed', passed: true, detail: 'Last review: 2025-10-01 (24 days ago)' },
      { name: 'Review frequency ≤ 90 days', passed: true, detail: 'Monthly access reviews' },
      { name: 'All systems in scope', passed: true, detail: 'All production and internal systems reviewed' },
      { name: 'Review includes privileged accounts', passed: true, detail: 'Privileged access reviewed monthly' },
      { name: 'Terminated users removed', passed: true, detail: 'Automated deprovisioning within 1 hour' },
      { name: 'Stale accounts detected', passed: true, detail: 'Accounts >60 days inactive flagged and disabled' },
      { name: 'Review approval documented', passed: true, detail: 'CISO approval on all reviews' },
      { name: 'Remediation tracking', passed: false, detail: 'Manual tracking, no automated system' }
    ],
    risks: [
      'Manual remediation tracking may miss items'
    ],
    source_document: 'dataflow_access_review_oct2025.pdf',
    extraction_confidence: 0.91,
    soc2_overlap: 90,
    structuredData: {
      evidence_type: 'assure_008_access_reviews',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      access_reviews_performed: true,
      last_review_date: '2025-10-01',
      review_frequency_days: 30,
      all_systems_in_scope: true,
      privileged_accounts_reviewed: true,
      terminated_users_removed: true,
      stale_accounts_detected: true,
      review_approval_documented: true,
      remediation_tracking: false,
      extraction_confidence: 0.91,
      soc2_coverage_percentage: 90
    }
  },

  // Evidence #15: Security Alerts
  {
    id: 15,
    name: 'Security Alerts',
    passed: 8,
    total: 10,
    percentage: 80.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Security alerting configured', passed: true, detail: 'Microsoft Sentinel + Azure Security Center' },
      { name: 'Failed login alerts', passed: true, detail: 'Alert after 3 failed attempts' },
      { name: 'Privilege escalation alerts', passed: true, detail: 'Role assignment changes trigger alerts' },
      { name: 'Malware detection alerts', passed: true, detail: 'Microsoft Defender for Endpoint' },
      { name: 'Data exfiltration alerts', passed: true, detail: 'DLP policies with alerting' },
      { name: 'Security tool tampering alerts', passed: true, detail: 'Alerts for security service disruptions' },
      { name: 'Alert routing to SOC/SIEM', passed: true, detail: 'All alerts route to Sentinel SIEM' },
      { name: 'Alert response time SLA', passed: true, detail: 'Critical: 30 min, High: 2 hours' },
      { name: 'Alert tuning performed', passed: false, detail: 'No formal tuning process, 15% false positive rate' },
      { name: 'Alert effectiveness metrics', passed: false, detail: 'Metrics not tracked' }
    ],
    risks: [
      'High false positive rate (15%) may cause alert fatigue'
    ],
    source_document: 'dataflow_security_monitoring_config.pdf',
    extraction_confidence: 0.88,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_015_security_alerts',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      security_alerting_configured: true,
      alerting_tool: 'microsoft_sentinel',
      failed_login_alerts: true,
      privilege_escalation_alerts: true,
      malware_detection_alerts: true,
      data_exfiltration_alerts: true,
      security_tool_tampering_alerts: true,
      alert_routing_to_soc: true,
      alert_response_time_sla_exists: true,
      critical_alert_response_minutes: 30,
      alert_tuning_performed: false,
      alert_effectiveness_tracked: false,
      extraction_confidence: 0.88,
      soc2_coverage_percentage: 80
    }
  },
// Evidence #3: Patch Management
  {
    id: 3,
    name: 'Patch Management',
    passed: 8,
    total: 10,
    percentage: 80.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'Patch management policy documented', passed: true, detail: 'Comprehensive patch policy' },
      { name: 'Critical patches ≤7 days', passed: true, detail: 'Average: 5 days' },
      { name: 'High patches ≤30 days', passed: true, detail: 'Average: 18 days' },
      { name: 'Automated patching for non-prod', passed: true, detail: 'Automated via Ansible' },
      { name: 'Automated patching for prod', passed: true, detail: 'Automated with change window approval' },
      { name: 'Patch testing before prod', passed: true, detail: 'Tested in UAT environment' },
      { name: 'Patch monitoring/tracking', passed: true, detail: 'Tracked via ServiceNow + Qualys' },
      { name: 'Emergency patching process', passed: true, detail: '4-hour emergency patching for critical' },
      { name: 'OS and application patching', passed: false, detail: 'Some legacy apps manually patched' },
      { name: 'Patch rollback capability', passed: false, detail: 'Rollback automation not configured' }
    ],
    risks: [
      'Manual patching for legacy apps creates inconsistency',
      'No automated rollback may delay incident recovery'
    ],
    source_document: 'dataflow_patch_policy.pdf, servicenow_reports.pdf',
    extraction_confidence: 0.91,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_003_patch_management',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      patch_policy_documented: true,
      critical_patch_sla_days: 5,
      high_patch_sla_days: 18,
      automated_patching_nonprod: true,
      automated_patching_prod: true,
      patch_testing_required: true,
      patch_monitoring_enabled: true,
      emergency_patching_process: true,
      os_patching_enabled: true,
      application_patching_enabled: false,
      patch_rollback_capability: false,
      extraction_confidence: 0.91,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #10: Network ACLs
  {
    id: 10,
    name: 'Network ACLs',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Network ACLs configured', passed: true, detail: 'Azure NSGs + Application Gateway WAF' },
      { name: 'Default deny policy', passed: true, detail: 'Strict default deny policy' },
      { name: 'Least privilege access', passed: true, detail: 'Minimal port exposure' },
      { name: 'ACL documentation maintained', passed: true, detail: 'NSG documentation in Azure DevOps wiki' },
      { name: 'ACL review frequency ≤90 days', passed: true, detail: 'Monthly ACL reviews' },
      { name: 'No overly permissive rules', passed: true, detail: 'All rules justified and documented' },
      { name: 'ACL change approval', passed: true, detail: 'Security architect approval required' },
      { name: 'ACL monitoring/alerting', passed: false, detail: 'No automated ACL change alerting' }
    ],
    risks: [
      'Manual ACL change monitoring may miss unauthorized changes'
    ],
    source_document: 'dataflow_network_policy.pdf, azure_nsg_rules.json',
    extraction_confidence: 0.93,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_010_network_acls',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      network_acls_configured: true,
      default_deny_policy: true,
      least_privilege_access: true,
      acl_documentation_maintained: true,
      acl_review_frequency_days: 30,
      overly_permissive_rules_exist: false,
      acl_change_approval_required: true,
      acl_monitoring_enabled: false,
      extraction_confidence: 0.93,
      soc2_coverage_percentage: 85
    }
  },

  // Evidence #11: 2FA for Admin Access
  {
    id: 11,
    name: '2FA for Admin Access',
    passed: 8,
    total: 8,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: '2FA required for all admins', passed: true, detail: '100% admin 2FA enforcement via Azure AD' },
      { name: '2FA enforced at login', passed: true, detail: 'Conditional Access policies enforce 2FA' },
      { name: 'Multiple 2FA methods available', passed: true, detail: 'Authenticator app, phone, hardware token' },
      { name: 'Phishing-resistant 2FA available', passed: true, detail: 'FIDO2 security keys supported' },
      { name: '2FA recovery process documented', passed: true, detail: 'Recovery via helpdesk with manager approval' },
      { name: '2FA compliance monitored', passed: true, detail: 'Daily compliance reports' },
      { name: '2FA bypass prohibited', passed: true, detail: 'No bypass except emergency break-glass' },
      { name: 'Session timeout after 2FA', passed: true, detail: '4-hour session timeout' }
    ],
    risks: [],
    source_document: 'dataflow_azure_ad_config.pdf, conditional_access_policies.json',
    extraction_confidence: 0.96,
    soc2_overlap: 90,
    structuredData: {
      evidence_type: 'assure_011_admin_2fa',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      two_fa_required_for_admins: true,
      two_fa_enforced_at_login: true,
      multiple_2fa_methods: true,
      phishing_resistant_2fa_available: true,
      two_fa_recovery_process: true,
      two_fa_compliance_monitored: true,
      two_fa_bypass_prohibited: true,
      session_timeout_configured: true,
      session_timeout_hours: 4,
      extraction_confidence: 0.96,
      soc2_coverage_percentage: 90
    }
  },

  // Evidence #16: Change Management
  {
    id: 16,
    name: 'Change Management',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Change management process documented', passed: true, detail: 'ITIL-based change process' },
      { name: 'Change approval required', passed: true, detail: 'CAB approval for standard/major changes' },
      { name: 'Change testing required', passed: true, detail: 'UAT testing mandatory' },
      { name: 'Change rollback plan', passed: true, detail: 'Rollback plan required in RFC' },
      { name: 'Change logging enabled', passed: true, detail: 'ServiceNow change records' },
      { name: 'Emergency change process', passed: true, detail: 'Emergency CAB for urgent changes' },
      { name: 'CAB for high-risk changes', passed: true, detail: 'Weekly CAB meetings' },
      { name: 'Change success rate tracked', passed: false, detail: 'Success rate tracked manually, not automated' }
    ],
    risks: [
      'Manual change success tracking may have data quality issues'
    ],
    source_document: 'dataflow_change_policy.pdf, servicenow_change_db.csv',
    extraction_confidence: 0.92,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_016_change_management',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      documented_change_process: true,
      change_approval_required: true,
      change_testing_required: true,
      rollback_plan_required: true,
      change_logging_enabled: true,
      emergency_change_process_exists: true,
      cab_meeting_frequency: 'weekly',
      change_success_rate_percentage: null,
      post_implementation_review_required: true,
      change_communication_process: true,
      extraction_confidence: 0.92,
      soc2_coverage_percentage: 85
    }
  },

  // Evidence #17: Code Review Requirements
  {
    id: 17,
    name: 'Code Review Requirements',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Code review required', passed: true, detail: 'All PRs require 2+ approvals' },
      { name: 'Peer review process', passed: true, detail: 'Tech lead + peer review' },
      { name: 'Branch protection enabled', passed: true, detail: 'Branch protection on all production repos' },
      { name: 'Security review for high-risk', passed: false, detail: 'Security review for high-risk changes only' },
      { name: 'Automated code quality checks', passed: true, detail: 'SonarQube, Checkmarx SAST' },
      { name: 'Code review documentation', passed: true, detail: 'PR templates with review checklist' },
      { name: 'Review before merge', passed: true, detail: 'CI/CD blocks merge without approval' },
      { name: 'Code review metrics tracked', passed: true, detail: 'Metrics dashboard in Azure DevOps' }
    ],
    risks: [
      'Security review not mandatory for all changes increases risk'
    ],
    source_document: 'dataflow_sdlc_standards.pdf, azure_devops_policies.json',
    extraction_confidence: 0.91,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_017_code_review',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      code_review_required: true,
      peer_review_required: true,
      branch_protection_enabled: true,
      security_review_for_high_risk: false,
      automated_code_quality_checks: true,
      code_review_documentation: true,
      review_before_merge_required: true,
      code_review_metrics_tracked: true,
      average_review_time_hours: 3,
      extraction_confidence: 0.91,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #18: Security Testing
  {
    id: 18,
    name: 'Security Testing',
    passed: 6,
    total: 8,
    percentage: 75.0,
    status: 'partially_compliant',
    requirements: [
      { name: 'SAST enabled', passed: true, detail: 'Checkmarx SAST in CI/CD pipeline' },
      { name: 'DAST performed', passed: true, detail: 'Quarterly DAST scans via Burp Suite Enterprise' },
      { name: 'Dependency scanning', passed: true, detail: 'WhiteSource Bolt for dependency scanning' },
      { name: 'Secrets scanning', passed: true, detail: 'GitGuardian + Azure DevOps secret scanning' },
      { name: 'Penetration testing', passed: true, detail: 'Annual pentest + bug bounty program' },
      { name: 'Vulnerability remediation SLA', passed: true, detail: 'Critical: 7d, High: 14d, Medium: 30d' },
      { name: 'Security testing in CI/CD', passed: false, detail: 'SAST in CI/CD, but DAST manual' },
      { name: 'Security testing metrics', passed: false, detail: 'Metrics tracked but not in real-time dashboard' }
    ],
    risks: [
      'Manual DAST creates testing gaps between releases',
      'No real-time security metrics dashboard delays visibility'
    ],
    source_document: 'dataflow_devsecops_policy.pdf, checkmarx_reports.pdf',
    extraction_confidence: 0.89,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_018_security_testing',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      sast_enabled: true,
      dast_performed: true,
      dependency_scanning_enabled: true,
      secrets_scanning_enabled: true,
      penetration_testing_performed: true,
      last_pentest_date: '2025-06-01',
      vulnerability_remediation_sla_exists: true,
      security_testing_in_cicd: false,
      security_testing_metrics_tracked: false,
      extraction_confidence: 0.89,
      soc2_coverage_percentage: 80
    }
  },
// Evidence #19: Service Level Agreements
  {
    id: 19,
    name: 'Service Level Agreements',
    passed: 6,
    total: 7,
    percentage: 85.7,
    status: 'compliant',
    requirements: [
      { name: 'SLA documented in contract', passed: true, detail: 'MSA Section 5: Service Levels' },
      { name: 'Availability SLA ≥99.9%', passed: true, detail: '99.95% monthly uptime commitment' },
      { name: 'Response time SLAs defined', passed: true, detail: 'Critical: 1h, High: 4h, Medium: 24h' },
      { name: 'Resolution time SLAs defined', passed: true, detail: 'Critical: 8h, High: 48h' },
      { name: 'Financial remedies for violations', passed: true, detail: 'Tiered service credits 10-50%' },
      { name: 'SLA performance reporting', passed: false, detail: 'Quarterly reports (monthly preferred)' },
      { name: 'SLA monitoring/public status', passed: true, detail: 'Real-time status at status.dataflow.io' }
    ],
    risks: [
      'Quarterly SLA reporting delays customer visibility (monthly preferred)'
    ],
    source_document: 'dataflow_msa.pdf',
    extraction_confidence: 0.93,
    soc2_overlap: 80,
    structuredData: {
      evidence_type: 'assure_019_sla',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      sla_documented: true,
      availability_percentage: 99.95,
      availability_measurement_period: 'monthly',
      response_time_sla_exists: true,
      critical_incident_response_hours: 1,
      high_incident_response_hours: 4,
      resolution_time_sla_exists: true,
      critical_incident_resolution_hours: 8,
      violation_remedies_defined: true,
      service_credits_available: true,
      service_credit_percentage: 50.0,
      sla_performance_monitored: true,
      sla_reporting_frequency: 'quarterly',
      public_status_page: true,
      extraction_confidence: 0.93,
      soc2_coverage_percentage: 80
    }
  },

  // Evidence #20: Data Retention & Deletion
  {
    id: 20,
    name: 'Data Retention & Deletion',
    passed: 7,
    total: 8,
    percentage: 87.5,
    status: 'compliant',
    requirements: [
      { name: 'Retention policy documented', passed: true, detail: 'Data Retention Policy v2.1' },
      { name: 'Retention periods defined by data type', passed: true, detail: 'Granular periods per data category' },
      { name: 'Deletion on customer request ≤30 days', passed: true, detail: '30-day deletion SLA in DPA' },
      { name: 'Secure deletion method', passed: false, detail: 'Secure deletion but not crypto erasure' },
      { name: 'Deletion certificate available', passed: true, detail: 'Automated certificate generation' },
      { name: 'Backup data included in deletion', passed: true, detail: 'Synchronized backup deletion' },
      { name: 'GDPR/CCPA compliant deletion', passed: true, detail: 'Full GDPR Article 17 compliance' },
      { name: 'Deletion verification process', passed: true, detail: 'Automated verification via audit logs' }
    ],
    risks: [
      'Secure deletion method not crypto erasure (lower assurance)'
    ],
    source_document: 'dataflow_data_retention_policy.pdf, dataflow_dpa.pdf',
    extraction_confidence: 0.94,
    soc2_overlap: 65,
    structuredData: {
      evidence_type: 'assure_020_data_retention',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      retention_policy_documented: true,
      retention_periods_defined: true,
      customer_data_retention_days: 60,
      log_data_retention_days: 395,
      deletion_on_request_supported: true,
      deletion_request_timeframe_days: 30,
      deletion_method: 'secure_deletion',
      deletion_certificate_provided: true,
      backups_included_in_deletion: true,
      backup_deletion_timeframe_days: 30,
      gdpr_compliant: true,
      ccpa_compliant: true,
      extraction_confidence: 0.94,
      soc2_coverage_percentage: 65
    }
  },

  // Evidence #21: Insurance Coverage
  {
    id: 21,
    name: 'Insurance Coverage',
    passed: 6,
    total: 6,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Cyber liability insurance exists', passed: true, detail: 'AIG cyber liability policy' },
      { name: 'Cyber coverage ≥$1M', passed: true, detail: '$10M cyber liability coverage' },
      { name: 'Cyber coverage ≥$5M (preferred)', passed: true, detail: '$10M exceeds $5M threshold' },
      { name: 'E&O insurance exists', passed: true, detail: 'Hartford E&O policy' },
      { name: 'E&O coverage ≥$1M', passed: true, detail: '$5M E&O coverage' },
      { name: 'Certificate of Insurance available', passed: true, detail: 'COI in vendor portal' }
    ],
    risks: [],
    source_document: 'dataflow_certificates_of_insurance.pdf',
    extraction_confidence: 0.98,
    soc2_overlap: 40,
    structuredData: {
      evidence_type: 'assure_021_insurance',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      cyber_insurance_exists: true,
      cyber_insurance_carrier: 'AIG',
      cyber_coverage_amount: 10000000,
      cyber_policy_expiry_date: '2026-03-31',
      eo_insurance_exists: true,
      eo_insurance_carrier: 'Hartford',
      eo_coverage_amount: 5000000,
      certificate_of_insurance_available: true,
      policy_is_current: true,
      extraction_confidence: 0.98,
      soc2_coverage_percentage: 40
    }
  },

  // Evidence #22: Right to Audit
  {
    id: 22,
    name: 'Right to Audit',
    passed: 6,
    total: 7,
    percentage: 85.7,
    status: 'compliant',
    requirements: [
      { name: 'Audit rights granted in contract', passed: true, detail: 'MSA Section 11: Audit Rights' },
      { name: 'Audit frequency at least annual', passed: false, detail: 'Annual audit only (bi-annual preferred)' },
      { name: 'Reasonable advance notice (≤30 days)', passed: true, detail: '30 days advance notice required' },
      { name: 'Audit scope includes security', passed: true, detail: 'Security and data handling in scope' },
      { name: 'Third-party auditor allowed', passed: true, detail: 'Customer or third-party auditor permitted' },
      { name: 'Vendor cooperation required', passed: true, detail: 'Cooperation clause in contract' },
      { name: 'Reasonable cost allocation', passed: true, detail: 'Customer pays (vendor pays if non-compliance found)' }
    ],
    risks: [
      'Annual-only audit frequency limits customer validation options'
    ],
    source_document: 'dataflow_msa.pdf',
    extraction_confidence: 0.91,
    soc2_overlap: 90,
    structuredData: {
      evidence_type: 'assure_022_audit_rights',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      audit_rights_granted: true,
      audit_frequency: 'annual',
      advance_notice_days: 30,
      audit_scope_includes_security: true,
      third_party_auditor_allowed: true,
      vendor_cooperation_required: true,
      cost_allocation: 'customer_unless_issues',
      soc2_alternative_provided: true,
      extraction_confidence: 0.91,
      soc2_coverage_percentage: 90
    }
  },

  // Evidence #24: AI/ML Security Controls
  {
    id: 24,
    name: 'AI/ML Security Controls',
    passed: 6,
    total: 9,
    percentage: 66.7,
    status: 'partially_compliant',
    requirements: [
      { name: 'AI systems inventory maintained', passed: true, detail: 'AI systems documented in tech stack' },
      { name: 'AI risk assessment performed', passed: true, detail: 'Annual AI risk assessment' },
      { name: 'Training data governance exists', passed: false, detail: 'No formal training data governance' },
      { name: 'Model validation/testing performed', passed: false, detail: 'Ad-hoc model testing only' },
      { name: 'Bias testing performed', passed: false, detail: 'Limited bias testing' },
      { name: 'Human oversight for critical decisions', passed: true, detail: 'Human review for high-risk AI outputs' },
      { name: 'Adversarial testing performed', passed: true, detail: 'Adversarial testing in security assessments' },
      { name: 'AI incident response plan', passed: true, detail: 'AI incidents in IR playbook' },
      { name: 'Third-party AI risk assessed', passed: true, detail: 'OpenAI, Azure OpenAI assessed' }
    ],
    risks: [
      'No training data governance creates data quality risk',
      'Limited bias testing may allow discriminatory outputs'
    ],
    source_document: 'dataflow_ai_policy.pdf, dataflow_risk_register.xlsx',
    extraction_confidence: 0.85,
    soc2_overlap: 35,
    structuredData: {
      evidence_type: 'assure_024_ai_governance',
      vendor_name: 'DataFlow Inc',
      evidence_date: '2025-10-16',
      ai_systems_used: true,
      ai_inventory_maintained: true,
      ai_use_cases: ['content_generation', 'recommendation'],
      ai_risk_assessment_performed: true,
      training_data_governance_exists: false,
      model_validation_performed: false,
      bias_testing_performed: false,
      human_oversight_exists: true,
      adversarial_testing_performed: true,
      ai_incident_response_plan: true,
      third_party_ai_models_used: true,
      third_party_ai_risk_assessed: true,
      third_party_ai_vendors: ['OpenAI', 'Microsoft Azure'],
      extraction_confidence: 0.85,
      soc2_coverage_percentage: 35
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
      ,
// Evidence #1: Architecture & Segmentation
  {
    id: 1,
    name: 'Architecture & Segmentation',
    passed: 10,
    total: 10,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Network segmentation documented', passed: true, detail: 'Zero trust architecture with micro-segmentation' },
      { name: 'Default deny firewall rules', passed: true, detail: 'Default deny all, explicit allow rules only' },
      { name: 'Customer data isolation', passed: true, detail: 'Physical isolation per customer tenant' },
      { name: 'DMZ for public services', passed: true, detail: 'Dedicated DMZ with WAF and DDoS protection' },
      { name: 'Production/non-prod separation', passed: true, detail: 'Completely separate infrastructure' },
      { name: 'Network diagram available', passed: true, detail: 'Detailed architecture diagrams with DFDs' },
      { name: 'Zero trust architecture', passed: true, detail: 'BeyondCorp zero trust model implemented' },
      { name: 'Micro-segmentation implemented', passed: true, detail: 'Service mesh with Istio for micro-segmentation' },
      { name: 'Subprocessor list maintained', passed: true, detail: '3 subprocessors (minimal, vetted)' },
      { name: 'SBOM available', passed: true, detail: 'Automated SBOM generation via Syft, updated daily' }
    ],
    risks: [],
    source_document: 'cloudstore_architecture_v3.pdf, cloudstore_soc2_section3.pdf',
    extraction_confidence: 0.98,
    soc2_overlap: 95,
    structuredData: {
      evidence_type: 'assure_001_architecture',
      vendor_name: 'CloudStore Pro',
      evidence_date: '2025-10-16',
      network_segmentation_exists: true,
      segmentation_method: 'zero_trust_micro',
      default_deny_configured: true,
      customer_data_isolated: true,
      dmz_implemented: true,
      production_nonprod_separated: true,
      zero_trust_architecture: true,
      network_diagram_available: true,
      subprocessors_documented: true,
      subprocessor_count: 3,
      sbom_available: true,
      extraction_confidence: 0.98,
      soc2_coverage_percentage: 95
    }
  },

  // Evidence #2: Data Mapping
  {
    id: 2,
    name: 'Data Mapping & Subprocessors',
    passed: 10,
    total: 10,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Data mapping exercise performed', passed: true, detail: 'Continuous data discovery with automated tools' },
      { name: 'Data types documented', passed: true, detail: 'Data catalog with 200+ data types classified' },
      { name: 'Data purposes documented', passed: true, detail: 'Purpose documented per GDPR Article 30 records' },
      { name: 'Data flows mapped', passed: true, detail: 'Real-time data flow visualization dashboard' },
      { name: 'Subprocessor list complete', passed: true, detail: '3 subprocessors with signed DPAs' },
      { name: 'Subprocessor data types documented', passed: true, detail: 'Detailed data type mapping per subprocessor' },
      { name: 'Data retention periods defined', passed: true, detail: 'Granular retention by data type (30-365 days)' },
      { name: 'Data deletion process documented', passed: true, detail: 'Automated deletion within 7 days of request' },
      { name: 'SBOM maintained', passed: true, detail: 'SBOM automatically updated daily' },
      { name: 'Data residency disclosed', passed: true, detail: 'Customer-selectable regions (US, EU, APAC)' }
    ],
    risks: [],
    source_document: 'cloudstore_data_governance.pdf',
    extraction_confidence: 0.98,
    soc2_overlap: 70,
    structuredData: {
      evidence_type: 'assure_002_data_mapping',
      vendor_name: 'CloudStore Pro',
      evidence_date: '2025-10-16',
      data_mapping_performed: true,
      data_mapping_date: '2025-10-16',
      data_types_documented: true,
      data_types: ['customer_data', 'pii', 'phi', 'financial_data', 'transaction_data'],
      data_purposes_documented: true,
      data_flows_mapped: true,
      subprocessors_documented: true,
      subprocessor_count: 3,
      sbom_maintained: true,
      sbom_dependency_count: 127,
      data_residency_disclosed: true,
      extraction_confidence: 0.98,
      soc2_coverage_percentage: 70
    }
  },

  // Evidence #6: Backup Configuration
  {
    id: 6,
    name: 'Backup Configuration',
    passed: 8,
    total: 8,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Automated backups enabled', passed: true, detail: 'Continuous replication + hourly snapshots' },
      { name: 'Backup frequency ≥ daily', passed: true, detail: 'Continuous backup with 5-minute RPO' },
      { name: 'Backup retention ≥ 30 days', passed: true, detail: '365-day retention with tiered storage' },
      { name: 'Backup encryption enabled', passed: true, detail: 'AES-256-GCM encryption with HSM key management' },
      { name: 'Backup testing performed', passed: true, detail: 'Weekly automated restore tests + quarterly DR drills' },
      { name: 'Offsite/geographic redundancy', passed: true, detail: 'Active-active replication across 5 regions' },
      { name: 'Backup monitoring/alerts', passed: true, detail: 'Real-time monitoring with 99.99% SLA' },
      { name: 'Immutable backups', passed: true, detail: 'WORM storage with legal hold support' }
    ],
    risks: [],
    source_document: 'cloudstore_bcpdr_policy.pdf',
    extraction_confidence: 0.99,
    soc2_overlap: 90,
    structuredData: {
      evidence_type: 'assure_006_backup_configuration',
      vendor_name: 'CloudStore Pro',
      evidence_date: '2025-10-16',
      automated_backups: true,
      backup_frequency: 'continuous',
      backup_retention_days: 365,
      backup_encrypted: true,
      backup_encryption_algorithm: 'aes_256_gcm',
      backup_testing_performed: true,
      last_backup_test_date: '2025-10-20',
      offsite_backups: true,
      backup_monitoring: true,
      immutable_backups: true,
      extraction_confidence: 0.99,
      soc2_coverage_percentage: 90
    }
  },

  // Evidence #8: Access Reviews
  {
    id: 8,
    name: 'Access Reviews',
    passed: 8,
    total: 8,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Access reviews performed', passed: true, detail: 'Last review: 2025-10-15 (10 days ago)' },
      { name: 'Review frequency ≤ 90 days', passed: true, detail: 'Bi-weekly automated reviews + quarterly manual attestation' },
      { name: 'All systems in scope', passed: true, detail: 'All systems including shadow IT discovered via CASB' },
      { name: 'Review includes privileged accounts', passed: true, detail: 'PAM with continuous access review' },
      { name: 'Terminated users removed', passed: true, detail: 'Real-time deprovisioning via SCIM' },
      { name: 'Stale accounts detected', passed: true, detail: 'Automated detection and revocation >30 days inactive' },
      { name: 'Review approval documented', passed: true, detail: 'Digital attestation workflow with audit trail' },
      { name: 'Remediation tracking', passed: true, detail: 'Automated remediation workflow with SLA tracking' }
    ],
    risks: [],
    source_document: 'cloudstore_iam_procedures.pdf',
    extraction_confidence: 0.97,
    soc2_overlap: 95,
    structuredData: {
      evidence_type: 'assure_008_access_reviews',
      vendor_name: 'CloudStore Pro',
      evidence_date: '2025-10-16',
      access_reviews_performed: true,
      last_review_date: '2025-10-15',
      review_frequency_days: 14,
      all_systems_in_scope: true,
      privileged_accounts_reviewed: true,
      terminated_users_removed: true,
      stale_accounts_detected: true,
      review_approval_documented: true,
      remediation_tracking: true,
      extraction_confidence: 0.97,
      soc2_coverage_percentage: 95
    }
  },

  // Evidence #15: Security Alerts
  {
    id: 15,
    name: 'Security Alerts',
    passed: 10,
    total: 10,
    percentage: 100.0,
    status: 'compliant',
    requirements: [
      { name: 'Security alerting configured', passed: true, detail: 'Splunk Enterprise Security + CrowdStrike' },
      { name: 'Failed login alerts', passed: true, detail: 'Real-time alerts with threat intelligence correlation' },
      { name: 'Privilege escalation alerts', passed: true, detail: 'UEBA detects anomalous privilege use' },
      { name: 'Malware detection alerts', passed: true, detail: 'CrowdStrike Falcon with AI-powered detection' },
      { name: 'Data exfiltration alerts', passed: true, detail: 'ML-based data exfiltration detection' },
      { name: 'Security tool tampering alerts', passed: true, detail: 'Tamper-proof logging with integrity monitoring' },
      { name: 'Alert routing to SOC/SIEM', passed: true, detail: '24/7 SOC with Tier 1/2/3 escalation' },
      { name: 'Alert response time SLA', passed: true, detail: 'Critical: 5 min, High: 15 min, Medium: 1 hour' },
      { name: 'Alert tuning performed', passed: true, detail: 'Monthly tuning with 2% false positive rate' },
      { name: 'Alert effectiveness metrics', passed: true, detail: 'Real-time dashboards with MTTD/MTTR tracking' }
    ],
    risks: [],
    source_document: 'cloudstore_soc_procedures.pdf',
    extraction_confidence: 0.99,
    soc2_overlap: 85,
    structuredData: {
      evidence_type: 'assure_015_security_alerts',
      vendor_name: 'CloudStore Pro',
      evidence_date: '2025-10-16',
      security_alerting_configured: true,
      alerting_tool: 'splunk_es',
      failed_login_alerts: true,
      privilege_escalation_alerts: true,
      malware_detection_alerts: true,
      data_exfiltration_alerts: true,
      security_tool_tampering_alerts: true,
      alert_routing_to_soc: true,
      alert_response_time_sla_exists: true,
      critical_alert_response_minutes: 5,
      alert_tuning_performed: true,
      alert_effectiveness_tracked: true,
      extraction_confidence: 0.99,
      soc2_coverage_percentage: 85
    }
  },
// All CloudStore Pro Batch 3 controls at 100% compliance
  // Abbreviated for file size - full details would mirror structure above
  // with all requirements passed: true, no risks, excellent extraction confidence

  { id: 3, name: 'Patch Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant' },
  { id: 10, name: 'Network ACLs', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 11, name: '2FA for Admin Access', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 16, name: 'Change Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant' },
  { id: 17, name: 'Code Review Requirements', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 18, name: 'Security Testing', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
// All at 100% except AI Governance (88.9%)
  // Abbreviated for efficiency - full details would follow pattern above

  { id: 19, name: 'Service Level Agreements', passed: 7, total: 7, percentage: 100.0, status: 'compliant' },
  { id: 20, name: 'Data Retention & Deletion', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 21, name: 'Insurance Coverage', passed: 6, total: 6, percentage: 100.0, status: 'compliant' },
  { id: 22, name: 'Right to Audit', passed: 7, total: 7, percentage: 100.0, status: 'compliant' },
  {
    id: 24,
    name: 'AI/ML Security Controls',
    passed: 8,
    total: 9,
    percentage: 88.9,
    status: 'compliant',
    key_issue: 'AI red team testing performed annually (quarterly preferred)'
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
