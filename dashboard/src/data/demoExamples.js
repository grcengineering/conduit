/**
 * Pre-Computed Demo Examples for CONDUIT Interactive Demo
 *
 * These examples simulate the complete CONDUIT workflow without requiring
 * actual API calls - perfect for GitHub Pages static deployment.
 *
 * Each example contains:
 * - Input text (what user would paste)
 * - Extraction results (what Claude would extract via XML)
 * - Validation checks (Pydantic validation results)
 * - Compliance calculation (percentage-based scoring)
 * - Dashboard data (for live integration)
 *
 * NOTE: The actual CONDUIT backend uses XML-based extraction where Claude
 * outputs structured XML that gets parsed and validated against Pydantic models.
 * The extraction fields shown here represent the final validated structure.
 *
 * Example XML extraction format:
 * <assure_007_bcpdr_testing>
 *   <test_date>2025-08-15</test_date>
 *   <test_result>pass</test_result>
 *   <test_type>partial_failover</test_type>
 *   <scope>production database, application servers, and load balancers</scope>
 *   <recovery_time_objective_met>true</recovery_time_objective_met>
 *   <recovery_point_objective_met>true</recovery_point_objective_met>
 * </assure_007_bcpdr_testing>
 */

export const demoExamples = {
  bcpdr_compliant: {
    id: 'bcpdr_compliant',
    title: 'BCP/DR - Compliant ✓',
    category: 'bcpdr',
    description: 'Recent test, all requirements passed',

    inputText: `At Acme Corp, we take business continuity seriously. Our latest disaster recovery test was completed on August 15, 2025. We performed a partial failover test of our production environment, including database and application servers.

The test was successful and met all our objectives. Our recovery time was 3.5 hours, well within our 4-hour RTO target. The test scope covered all production systems including the primary database, application servers, and load balancers.`,

    extraction: {
      test_date: '2025-08-15',
      test_result: 'pass',
      test_type: 'partial_failover',
      scope: 'production database, application servers, and load balancers',
      recovery_time_objective_met: true,
      recovery_point_objective_met: true
    },

    validation: {
      checks: [
        {
          rule: 'Test date within 12 months',
          passed: true,
          detail: 'Test from 2025-08-15 is 2 months old (within 12-month requirement)'
        },
        {
          rule: 'Test result acceptable',
          passed: true,
          detail: 'Result: PASS - meets ASSURE requirements'
        },
        {
          rule: 'Scope documented',
          passed: true,
          detail: 'Scope clearly defined: production systems covered'
        }
      ],
      allPassed: true
    },

    compliance: {
      percentage: 100,
      passed: 3,
      total: 3,
      status: 'compliant'
    },

    dashboardData: {
      vendor_name: 'Acme Corp',
      control_id: 7,
      control_name: 'BCP/DR Testing',
      evidence_type: 'assure_007_bcpdr_testing',
      extraction_confidence: 0.85
    }
  },

  bcpdr_old_test: {
    id: 'bcpdr_old_test',
    title: 'BCP/DR - Old Test ✗',
    category: 'bcpdr',
    description: 'Test older than 12 months - non-compliant',

    inputText: `Our last disaster recovery test was completed in January 2024. It was a full failover test that covered our entire production infrastructure. The test passed successfully with all systems recovered within our RTO targets.`,

    extraction: {
      test_date: '2024-01-15',
      test_result: 'pass',
      test_type: 'full_failover',
      scope: 'entire production infrastructure',
      recovery_time_objective_met: true,
      recovery_point_objective_met: true
    },

    validation: {
      checks: [
        {
          rule: 'Test date within 12 months',
          passed: false,
          detail: 'Test from 2024-01-15 is 21 months old (exceeds 12-month requirement)',
          error: 'ASSURE requires annual BCP/DR testing'
        },
        {
          rule: 'Test result acceptable',
          passed: true,
          detail: 'Result: PASS - meets requirements'
        },
        {
          rule: 'Scope documented',
          passed: true,
          detail: 'Scope clearly defined'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 3,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'OldTest Inc',
      control_id: 7,
      control_name: 'BCP/DR Testing',
      evidence_type: 'assure_007_bcpdr_testing',
      extraction_confidence: 0.90
    }
  },

  bcpdr_failed_test: {
    id: 'bcpdr_failed_test',
    title: 'BCP/DR - Failed Test ✗',
    category: 'bcpdr',
    description: 'Recent test but failed to meet RTO',

    inputText: `At TechStart Inc, we completed our disaster recovery test on September 20, 2025. We performed a partial failover test of our production environment.

While the test was mostly successful, our actual recovery time was 6 hours, which exceeded our 4-hour RTO target. We've identified the bottleneck and are working on improvements for next quarter. The test scope covered production database and application servers.`,

    extraction: {
      test_date: '2025-09-20',
      test_result: 'pass_with_findings',
      test_type: 'partial_failover',
      scope: 'production database and application servers',
      recovery_time_objective_met: false,
      recovery_point_objective_met: true
    },

    validation: {
      checks: [
        {
          rule: 'Test date within 12 months',
          passed: true,
          detail: 'Test from 2025-09-20 is 1 month old'
        },
        {
          rule: 'Test result acceptable',
          passed: true,
          detail: 'Result: PASS WITH FINDINGS - acceptable under ASSURE'
        },
        {
          rule: 'Scope documented',
          passed: true,
          detail: 'Scope clearly defined'
        }
      ],
      allPassed: true
    },

    compliance: {
      percentage: 100,
      passed: 3,
      total: 3,
      status: 'compliant',
      note: 'Compliant but RTO not met - consider as risk'
    },

    dashboardData: {
      vendor_name: 'TechStart Inc',
      control_id: 7,
      control_name: 'BCP/DR Testing',
      evidence_type: 'assure_007_bcpdr_testing',
      extraction_confidence: 0.88
    }
  },

  vuln_compliant: {
    id: 'vuln_compliant',
    title: 'Vulnerability - Compliant ✓',
    category: 'vulnerability',
    description: 'Recent scans and pentest, no critical/high findings',

    inputText: `DataFlow Inc conducts monthly vulnerability scans using Qualys. The most recent scans were:
- October 1, 2025: 0 critical, 0 high, 5 medium, 12 low
- September 1, 2025: 0 critical, 0 high, 7 medium, 15 low
- August 1, 2025: 0 critical, 0 high, 8 medium, 18 low

Our last penetration test was conducted on March 15, 2025 by SecureOps Inc. It was an external black box test that found 0 critical and 0 high severity findings. All medium and low findings have been remediated. We meet our vulnerability SLA targets.`,

    extraction: {
      scans: [
        { date: '2025-10-01', tool: 'Qualys', critical: 0, high: 0, medium: 5, low: 12 },
        { date: '2025-09-01', tool: 'Qualys', critical: 0, high: 0, medium: 7, low: 15 },
        { date: '2025-08-01', tool: 'Qualys', critical: 0, high: 0, medium: 8, low: 18 }
      ],
      pentest: {
        date: '2025-03-15',
        firm: 'SecureOps Inc',
        type: 'external_black_box',
        critical: 0,
        high: 0,
        remediated: true
      }
    },

    validation: {
      checks: [
        {
          rule: '3 vulnerability scans in last 90 days',
          passed: true,
          detail: '3 scans found: Oct 1, Sep 1, Aug 1, 2025'
        },
        {
          rule: 'Penetration test within 12 months',
          passed: true,
          detail: 'Test from 2025-03-15 is 7 months old'
        },
        {
          rule: 'No open critical/high findings',
          passed: true,
          detail: '0 critical, 0 high findings across all scans'
        },
        {
          rule: 'Vulnerability SLA compliance',
          passed: true,
          detail: 'Meets SLA targets'
        }
      ],
      allPassed: true
    },

    compliance: {
      percentage: 100,
      passed: 4,
      total: 4,
      status: 'compliant'
    },

    dashboardData: {
      vendor_name: 'DataFlow Inc',
      control_id: 4,
      control_name: 'Vulnerability Management',
      evidence_type: 'assure_004_vulnerability_mgmt',
      extraction_confidence: 0.92
    }
  },

  vuln_old_pentest: {
    id: 'vuln_old_pentest',
    title: 'Vulnerability - Old Pentest ✗',
    category: 'vulnerability',
    description: 'Recent scans but pentest > 12 months',

    inputText: `CloudSecure Inc conducts monthly vulnerability scans using Nessus:
- October 1, 2025: 0 critical, 1 high, 3 medium, 8 low
- September 1, 2025: 0 critical, 2 high, 4 medium, 10 low
- August 1, 2025: 0 critical, 3 high, 5 medium, 12 low

Our last penetration test was conducted on January 10, 2024 by PentestCo. It was an internal test.`,

    extraction: {
      scans: [
        { date: '2025-10-01', tool: 'Nessus', critical: 0, high: 1, medium: 3, low: 8 },
        { date: '2025-09-01', tool: 'Nessus', critical: 0, high: 2, medium: 4, low: 10 },
        { date: '2025-08-01', tool: 'Nessus', critical: 0, high: 3, medium: 5, low: 12 }
      ],
      pentest: {
        date: '2024-01-10',
        firm: 'PentestCo',
        type: 'internal',
        critical: 0,
        high: 2
      }
    },

    validation: {
      checks: [
        {
          rule: '3 vulnerability scans in last 90 days',
          passed: true,
          detail: '3 scans found'
        },
        {
          rule: 'Penetration test within 12 months',
          passed: false,
          detail: 'Test from 2024-01-10 is 21 months old (exceeds 12-month requirement)',
          error: 'ASSURE requires annual penetration testing'
        },
        {
          rule: 'No open critical/high findings',
          passed: true,
          detail: 'Recent scans show manageable findings'
        },
        {
          rule: 'Vulnerability SLA compliance',
          passed: true,
          detail: 'Meets SLA'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 4,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'CloudSecure Inc',
      control_id: 4,
      control_name: 'Vulnerability Management',
      evidence_type: 'assure_004_vulnerability_mgmt',
      extraction_confidence: 0.85
    }
  },

  vuln_open_high: {
    id: 'vuln_open_high',
    title: 'Vulnerability - Open High ✗',
    category: 'vulnerability',
    description: 'Recent tests but unresolved high findings',

    inputText: `SecureApp Co performs monthly Qualys scans. Latest scans:
- October 1, 2025: 2 critical, 5 high, 10 medium, 20 low
- September 1, 2025: 3 critical, 6 high, 12 medium, 22 low
- August 1, 2025: 4 critical, 8 high, 15 medium, 25 low

Penetration test on May 15, 2025 by SecTest Inc found 1 critical and 3 high findings. Critical has been fixed but high findings remain open.`,

    extraction: {
      scans: [
        { date: '2025-10-01', tool: 'Qualys', critical: 2, high: 5, medium: 10, low: 20 },
        { date: '2025-09-01', tool: 'Qualys', critical: 3, high: 6, medium: 12, low: 22 },
        { date: '2025-08-01', tool: 'Qualys', critical: 4, high: 8, medium: 15, low: 25 }
      ],
      pentest: {
        date: '2025-05-15',
        firm: 'SecTest Inc',
        type: 'external_black_box',
        critical: 0,
        high: 3,
        remediated: false
      }
    },

    validation: {
      checks: [
        {
          rule: '3 vulnerability scans in last 90 days',
          passed: true,
          detail: '3 scans found'
        },
        {
          rule: 'Penetration test within 12 months',
          passed: true,
          detail: 'Test from 2025-05-15 is 5 months old'
        },
        {
          rule: 'No open critical/high findings',
          passed: false,
          detail: '2 critical and 5 high findings remain open',
          error: 'ASSURE requires remediation of all critical/high findings'
        },
        {
          rule: 'Vulnerability SLA compliance',
          passed: false,
          detail: 'SLA exceeded for critical/high findings'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 4,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'SecureApp Co',
      control_id: 4,
      control_name: 'Vulnerability Management',
      evidence_type: 'assure_004_vulnerability_mgmt',
      extraction_confidence: 0.88
    }
  },

  sso_compliant: {
    id: 'sso_compliant',
    title: 'SSO/MFA - Compliant ✓',
    category: 'sso_mfa',
    description: 'Free SSO with phishing-resistant MFA',

    inputText: `AuthFlow Inc provides enterprise SSO at no additional cost using SAML 2.0 and OpenID Connect protocols. SSO is available on all plans including our free tier.

For MFA, we support multiple phishing-resistant methods including hardware security keys (YubiKey, FIDO2), biometric authentication (FaceID, TouchID), and device trust. 98% of our users have MFA enabled. We also support SMS and authenticator apps as fallback options.`,

    extraction: {
      sso_available: true,
      sso_requires_paid_plan: false,
      sso_protocols: ['SAML 2.0', 'OpenID Connect'],
      mfa_available: true,
      mfa_adoption_percentage: 98,
      phishing_resistant_mfa_available: true,
      phishing_resistant_types: ['hardware_token', 'biometric', 'device_trust']
    },

    validation: {
      checks: [
        {
          rule: 'SSO available',
          passed: true,
          detail: 'SAML 2.0 and OpenID Connect supported'
        },
        {
          rule: 'SSO free (no paywall)',
          passed: true,
          detail: 'Available on all plans including free tier'
        },
        {
          rule: 'MFA available',
          passed: true,
          detail: '98% user adoption'
        },
        {
          rule: 'Phishing-resistant MFA available',
          passed: true,
          detail: 'Hardware keys, biometric, device trust supported'
        }
      ],
      allPassed: true
    },

    compliance: {
      percentage: 100,
      passed: 4,
      total: 4,
      status: 'compliant'
    },

    dashboardData: {
      vendor_name: 'AuthFlow Inc',
      control_id: 23,
      control_name: 'SSO/MFA Requirements',
      evidence_type: 'assure_023_sso_mfa',
      extraction_confidence: 0.95
    }
  },

  sso_paywall: {
    id: 'sso_paywall',
    title: 'SSO/MFA - SSO Paywall ✗',
    category: 'sso_mfa',
    description: 'SSO requires paid enterprise plan',

    inputText: `At BasicSaaS Inc, SSO is available as an enterprise add-on feature. Our Enterprise plan ($500/month) includes SAML SSO integration. SSO is not available on our Starter or Professional plans.

We provide MFA through authenticator apps (Google Authenticator, Authy) and SMS. Hardware token support is available on Enterprise plans.`,

    extraction: {
      sso_available: true,
      sso_requires_paid_plan: true,
      sso_protocols: ['SAML'],
      mfa_available: true,
      mfa_adoption_percentage: 75,
      phishing_resistant_mfa_available: true,
      phishing_resistant_types: ['hardware_token']
    },

    validation: {
      checks: [
        {
          rule: 'SSO available',
          passed: true,
          detail: 'SAML supported'
        },
        {
          rule: 'SSO free (no paywall)',
          passed: false,
          detail: 'SSO requires Enterprise plan ($500/month)',
          error: 'ASSURE requires SSO without additional cost'
        },
        {
          rule: 'MFA available',
          passed: true,
          detail: '75% adoption'
        },
        {
          rule: 'Phishing-resistant MFA available',
          passed: true,
          detail: 'Hardware tokens supported'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 4,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'BasicSaaS Inc',
      control_id: 23,
      control_name: 'SSO/MFA Requirements',
      evidence_type: 'assure_023_sso_mfa',
      extraction_confidence: 0.90
    }
  },

  sso_no_phishing_resistant: {
    id: 'sso_no_phishing_resistant',
    title: 'SSO/MFA - No Phishing-Resistant MFA ✗',
    category: 'sso_mfa',
    description: 'Only SMS/TOTP MFA, no hardware keys',

    inputText: `LegacyApp Co provides free SSO using SAML 2.0 on all plans. For MFA, we support SMS codes and TOTP authenticator apps (Google Authenticator, Microsoft Authenticator). 90% of users have MFA enabled.`,

    extraction: {
      sso_available: true,
      sso_requires_paid_plan: false,
      sso_protocols: ['SAML 2.0'],
      mfa_available: true,
      mfa_adoption_percentage: 90,
      phishing_resistant_mfa_available: false,
      phishing_resistant_types: []
    },

    validation: {
      checks: [
        {
          rule: 'SSO available',
          passed: true,
          detail: 'SAML 2.0 supported'
        },
        {
          rule: 'SSO free (no paywall)',
          passed: true,
          detail: 'Available on all plans'
        },
        {
          rule: 'MFA available',
          passed: true,
          detail: '90% adoption'
        },
        {
          rule: 'Phishing-resistant MFA available',
          passed: false,
          detail: 'Only SMS and TOTP available - both vulnerable to phishing',
          error: 'ASSURE requires hardware keys, biometric, or device trust'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 4,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'LegacyApp Co',
      control_id: 23,
      control_name: 'SSO/MFA Requirements',
      evidence_type: 'assure_023_sso_mfa',
      extraction_confidence: 0.87
    }
  },

  edge_case_missing_data: {
    id: 'edge_case_missing_data',
    title: 'Edge Case - Incomplete Data',
    category: 'bcpdr',
    description: 'Shows graceful handling of missing information',

    inputText: `We conduct regular DR testing. Our last test was successful.`,

    extraction: {
      test_date: null,
      test_result: 'pass',
      test_type: null,
      scope: null,
      recovery_time_objective_met: null,
      recovery_point_objective_met: null
    },

    validation: {
      checks: [
        {
          rule: 'Test date within 12 months',
          passed: false,
          detail: 'Test date not provided',
          error: 'Cannot validate without test date'
        },
        {
          rule: 'Test result acceptable',
          passed: true,
          detail: 'Result: PASS (but lacks detail)'
        },
        {
          rule: 'Scope documented',
          passed: false,
          detail: 'Scope not provided',
          error: 'Test scope must be documented'
        }
      ],
      allPassed: false
    },

    compliance: {
      percentage: 0,
      passed: 0,
      total: 3,
      status: 'non_compliant'
    },

    dashboardData: {
      vendor_name: 'Incomplete Inc',
      control_id: 7,
      control_name: 'BCP/DR Testing',
      evidence_type: 'assure_007_bcpdr_testing',
      extraction_confidence: 0.40
    }
  }
}

/**
 * Get examples by category
 */
export function getExamplesByCategory(category) {
  return Object.values(demoExamples).filter(ex => ex.category === category)
}

/**
 * Get all example categories
 */
export function getCategories() {
  return [...new Set(Object.values(demoExamples).map(ex => ex.category))]
}
