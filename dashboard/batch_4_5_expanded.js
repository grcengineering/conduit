// BATCH 4-5 EXPANDED: Contracts, Infrastructure & AI (5 evidence types)
// Evidence #19 (SLA), #20 (Data Retention), #21 (Insurance), #22 (Audit Rights), #24 (AI Governance)

// ============================================================================
// ACME SAAS - Batch 4-5 Controls
// ============================================================================

const acmeBatch45 = [
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
];

// ============================================================================
// DATAFLOW INC - Batch 4-5 Controls
// ============================================================================

const dataflowBatch45 = [
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
];

// ============================================================================
// CLOUDSTORE PRO - Batch 4-5 Controls (Near-perfect compliance)
// ============================================================================

const cloudstoreBatch45 = [
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
];

export { acmeBatch45, dataflowBatch45, cloudstoreBatch45 };
