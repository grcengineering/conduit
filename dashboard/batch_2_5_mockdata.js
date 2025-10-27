// BATCH 2: Data, Access & Infrastructure (5 evidence types)
// Evidence #1: Architecture & Segmentation
// Evidence #2: Data Mapping & Subprocessors
// Evidence #6: Backup Configuration
// Evidence #8: Access Reviews
// Evidence #15: Security Alerts

// ACME SAAS - Batch 2 Controls
const acmeBatch2 = [
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
  }
];

// DATAFLOW INC - Batch 2 Controls (Medium compliance: 75-87%)
const dataflowBatch2 = [
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
  }
];

// CLOUDSTORE PRO - Batch 2 Controls (High compliance: 95-100%)
const cloudstoreBatch2 = [
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
  }
];

// BATCH 3: Technical Access & Change Controls (6 evidence types)
// Evidence #3: Patch Management
// Evidence #10: Network ACLs
// Evidence #11: 2FA for Admin Access
// Evidence #16: Change Management
// Evidence #17: Code Review
// Evidence #18: Security Testing

// For efficiency, creating condensed Batch 3-5 data
// Each vendor × 11 remaining evidence types = 33 controls

const batch3to5Summary = {
  acme: [
    // #3: Patch Management - 60% (partial)
    { id: 3, name: 'Patch Management', passed: 6, total: 10, percentage: 60.0, status: 'partially_compliant',
      key_issues: ['Critical patches SLA missed (15 days vs 7 days)', 'No automated patching for prod'] },

    // #10: Network ACLs - 75% (partial)
    { id: 10, name: 'Network ACLs', passed: 6, total: 8, percentage: 75.0, status: 'partially_compliant',
      key_issues: ['Some overly permissive rules', 'ACL review quarterly vs monthly'] },

    // #11: 2FA for Admin - 87.5% (compliant)
    { id: 11, name: '2FA for Admin Access', passed: 7, total: 8, percentage: 87.5, status: 'compliant',
      key_issues: ['SMS-based 2FA allowed (not phishing-resistant)'] },

    // #16: Change Management - 70% (partial)
    { id: 16, name: 'Change Management', passed: 7, total: 10, percentage: 70.0, status: 'partially_compliant',
      key_issues: ['Emergency change process not well-defined', 'No CAB for high-risk changes'] },

    // #17: Code Review - 75% (partial)
    { id: 17, name: 'Code Review Requirements', passed: 6, total: 8, percentage: 75.0, status: 'partially_compliant',
      key_issues: ['Code review not enforced via branch protection', 'Security review not required'] },

    // #18: Security Testing - 62.5% (partial)
    { id: 18, name: 'Security Testing', passed: 5, total: 8, percentage: 62.5, status: 'partially_compliant',
      key_issues: ['DAST not performed', 'Dependency scanning ad-hoc'] },

    // #19: SLA - 71% (partial) - from Phase 1 testing
    { id: 19, name: 'Service Level Agreements', passed: 5, total: 7, percentage: 71.4, status: 'partially_compliant',
      key_issues: ['Response time SLAs not contractual', 'No SLA reporting to customers'] },

    // #20: Data Retention - 75% (partial)
    { id: 20, name: 'Data Retention & Deletion', passed: 6, total: 8, percentage: 75.0, status: 'partially_compliant',
      key_issues: ['Deletion method not specified', 'Backup deletion timeframe unclear'] },

    // #21: Insurance - 83% (partial)
    { id: 21, name: 'Insurance Coverage', passed: 5, total: 6, percentage: 83.3, status: 'partially_compliant',
      key_issues: ['Only $2M cyber coverage (below $5M preferred)'] },

    // #22: Audit Rights - 57% (partial)
    { id: 22, name: 'Right to Audit', passed: 4, total: 7, percentage: 57.1, status: 'partially_compliant',
      key_issues: ['No audit rights in contract', 'Must rely on SOC 2 report'] },

    // #24: AI Governance - 44% (non-compliant)
    { id: 24, name: 'AI/ML Security Controls', passed: 4, total: 9, percentage: 44.4, status: 'non_compliant',
      key_issues: ['No AI governance policy', 'No bias testing', 'No model validation'] }
  ],

  dataflow: [
    // #3: Patch Management - 80% (partial)
    { id: 3, name: 'Patch Management', passed: 8, total: 10, percentage: 80.0, status: 'partially_compliant',
      key_issues: ['Patching SLA met but automated rollback not configured'] },

    // #10: Network ACLs - 87.5% (compliant)
    { id: 10, name: 'Network ACLs', passed: 7, total: 8, percentage: 87.5, status: 'compliant',
      key_issues: ['ACL documentation could be more detailed'] },

    // #11: 2FA for Admin - 100% (compliant)
    { id: 11, name: '2FA for Admin Access', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #16: Change Management - 87.5% (compliant)
    { id: 16, name: 'Change Management', passed: 7, total: 8, percentage: 87.5, status: 'compliant',
      key_issues: ['Post-implementation review not always completed'] },

    // #17: Code Review - 87.5% (compliant)
    { id: 17, name: 'Code Review Requirements', passed: 7, total: 8, percentage: 87.5, status: 'compliant',
      key_issues: ['Security review for high-risk changes only'] },

    // #18: Security Testing - 80% (partial)
    { id: 18, name: 'Security Testing', passed: 6, total: 8, percentage: 75.0, status: 'partially_compliant',
      key_issues: ['IAST not implemented', 'API security testing manual'] },

    // #19: SLA - 85.7% (compliant)
    { id: 19, name: 'Service Level Agreements', passed: 6, total: 7, percentage: 85.7, status: 'compliant',
      key_issues: ['SLA reporting could be more frequent'] },

    // #20: Data Retention - 87.5% (compliant)
    { id: 20, name: 'Data Retention & Deletion', passed: 7, total: 8, percentage: 87.5, status: 'compliant',
      key_issues: ['Deletion method not crypto erasure'] },

    // #21: Insurance - 100% (compliant)
    { id: 21, name: 'Insurance Coverage', passed: 6, total: 6, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #22: Audit Rights - 85.7% (compliant)
    { id: 22, name: 'Right to Audit', passed: 6, total: 7, percentage: 85.7, status: 'compliant',
      key_issues: ['Audit frequency annual (bi-annual preferred)'] },

    // #24: AI Governance - 66.7% (partial)
    { id: 24, name: 'AI/ML Security Controls', passed: 6, total: 9, percentage: 66.7, status: 'partially_compliant',
      key_issues: ['No formal AI governance framework', 'Limited bias testing'] }
  ],

  cloudstore: [
    // #3: Patch Management - 100% (compliant)
    { id: 3, name: 'Patch Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #10: Network ACLs - 100% (compliant)
    { id: 10, name: 'Network ACLs', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #11: 2FA for Admin - 100% (compliant)
    { id: 11, name: '2FA for Admin Access', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #16: Change Management - 100% (compliant)
    { id: 16, name: 'Change Management', passed: 10, total: 10, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #17: Code Review - 100% (compliant)
    { id: 17, name: 'Code Review Requirements', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #18: Security Testing - 100% (compliant)
    { id: 18, name: 'Security Testing', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #19: SLA - 100% (compliant)
    { id: 19, name: 'Service Level Agreements', passed: 7, total: 7, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #20: Data Retention - 100% (compliant)
    { id: 20, name: 'Data Retention & Deletion', passed: 8, total: 8, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #21: Insurance - 100% (compliant)
    { id: 21, name: 'Insurance Coverage', passed: 6, total: 6, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #22: Audit Rights - 100% (compliant)
    { id: 22, name: 'Right to Audit', passed: 7, total: 7, percentage: 100.0, status: 'compliant',
      key_issues: [] },

    // #24: AI Governance - 88.9% (compliant)
    { id: 24, name: 'AI/ML Security Controls', passed: 8, total: 9, percentage: 88.9, status: 'compliant',
      key_issues: ['AI red team testing performed annually vs quarterly'] }
  ]
};

// Note: The full detailed mock data with requirements, risks, and structuredData
// for Batch 3-5 will be generated in the integration step to keep this file manageable.
// This summary provides the compliance scores needed for the dashboard.

export { acmeBatch2, dataflowBatch2, cloudstoreBatch2, batch3to5Summary };
