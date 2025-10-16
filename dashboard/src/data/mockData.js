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
