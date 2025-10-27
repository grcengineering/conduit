// BATCH 3 EXPANDED: Technical Access & Change Controls
// Evidence #3, #10, #11, #16, #17, #18 for all 3 vendors

// ============================================================================
// ACME SAAS - Batch 3 Controls
// ============================================================================

const acmeBatch3 = [
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
  }
];

// ============================================================================
// DATAFLOW INC - Batch 3 Controls
// ============================================================================

const dataflowBatch3 = [
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
  }
];

// ============================================================================
// CLOUDSTORE PRO - Batch 3 Controls (All 100%)
// ============================================================================

const cloudstoreBatch3 = [
  // All CloudStore Pro Batch 3 controls at 100% compliance
  // Abbreviated for file size - full details would mirror structure above
  // with all requirements passed: true, no risks, excellent extraction confidence

  { id: 3, name: 'Patch Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant' },
  { id: 10, name: 'Network ACLs', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 11, name: '2FA for Admin Access', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 16, name: 'Change Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant' },
  { id: 17, name: 'Code Review Requirements', passed: 8, total: 8, percentage: 100.0, status: 'compliant' },
  { id: 18, name: 'Security Testing', passed: 8, total: 8, percentage: 100.0, status: 'compliant' }
];

export { acmeBatch3, dataflowBatch3, cloudstoreBatch3 };
