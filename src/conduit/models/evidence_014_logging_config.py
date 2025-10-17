"""ASSURE Control #14: Logging Configuration Evidence"""

from enum import Enum
from typing import List

from pydantic import Field

from .base import BaseEvidence


class LogRetentionPeriod(Enum):
    """Log retention periods"""

    THIRTY_DAYS = "30_days"
    NINETY_DAYS = "90_days"
    ONE_YEAR = "1_year"
    TWO_YEARS = "2_years"
    SEVEN_YEARS = "7_years"
    INDEFINITE = "indefinite"


class LogType(Enum):
    """Types of logs that should be collected"""

    SECURITY = "security"  # Security events (auth failures, privilege escalation)
    ACCESS = "access"  # User access logs (login/logout, resource access)
    AUDIT = "audit"  # Audit trail (data changes, config changes)
    APPLICATION = "application"  # Application-level logs
    SYSTEM = "system"  # System-level logs (OS, infrastructure)
    DATABASE = "database"  # Database query and access logs


class MonitoringTool(Enum):
    """SIEM/monitoring tools"""

    SPLUNK = "splunk"
    DATADOG = "datadog"
    ELK = "elk"  # Elasticsearch, Logstash, Kibana
    CLOUDWATCH = "cloudwatch"  # AWS CloudWatch
    SENTINEL = "sentinel"  # Microsoft Sentinel
    SUMO_LOGIC = "sumo_logic"
    OTHER = "other"


class LoggingConfigEvidence(BaseEvidence):
    """
    ASSURE Control #14: Logging Configuration Evidence.

    This evidence type validates that vendors have comprehensive logging
    with adequate retention and monitoring/alerting capabilities.

    ASSURE Requirements:
    - Log retention must be >= 1 year (365 days)
    - Security and audit logs must be collected (critical requirement!)
    - SIEM/monitoring tool must be in place
    - Logs should be immutable/tamper-proof
    - Centralized logging should be implemented

    SOC 2 Overlap:
    - CC7.2: System Monitoring (logging and monitoring controls)

    NIST CSF:
    - PR.PS-04: Log records are generated and made available for continuous monitoring

    CIS Controls:
    - Control 8: Audit Log Management

    Example:
        evidence = LoggingConfigEvidence(
            vendor_name="Acme Corp",
            evidence_date="2025-10-17",
            retention_period=LogRetentionPeriod.ONE_YEAR,
            log_types_collected=[
                LogType.SECURITY,
                LogType.ACCESS,
                LogType.AUDIT,
                LogType.APPLICATION
            ],
            monitoring_tool=MonitoringTool.SPLUNK,
            logs_immutable=True,
            centralized_logging=True,
            extraction_confidence=0.95
        )

        if evidence.is_compliant():
            print("Vendor meets ASSURE logging requirements")
    """

    evidence_type: str = Field(default="assure_014_logging_config")

    # Log retention (required - must be >= 1 year)
    retention_period: LogRetentionPeriod = Field(
        description="Log retention period (ASSURE requires >= 1 year)"
    )

    # Log types (required - security and audit are critical)
    log_types_collected: List[LogType] = Field(
        min_length=1,
        description="Types of logs collected (security and audit are required by ASSURE)",
    )

    # Monitoring/SIEM (required)
    monitoring_tool: MonitoringTool = Field(
        description="SIEM or monitoring tool in use for log analysis and alerting"
    )

    # Additional security controls
    logs_immutable: bool = Field(
        description="Are logs immutable/tamper-proof? (write-once, integrity verification)"
    )
    centralized_logging: bool = Field(
        description="Is logging centralized across all systems/services?"
    )

    # SOC 2 overlap (override defaults from BaseEvidence)
    soc2_section_4_criteria: List[str] = Field(
        default=["CC7.2"],
        description="SOC 2 System Monitoring criteria (logging controls)",
    )
    soc2_coverage_percentage: int = Field(
        default=80,
        ge=0,
        le=100,
        description="Logging is substantially covered in SOC 2 CC7.2 (retention requirements may vary)",
    )

    def is_compliant(self) -> bool:
        """
        Check if this evidence meets ASSURE compliance requirements.

        Compliance criteria:
        1. Log retention must be >= 1 year
        2. Security logs must be collected
        3. Audit logs must be collected
        4. Monitoring tool must be present
        5. Logs should be immutable

        Returns:
            bool: True if evidence meets ASSURE requirements, False otherwise
        """
        # Requirement 1: Retention >= 1 year
        sufficient_retention = self.retention_period in [
            LogRetentionPeriod.ONE_YEAR,
            LogRetentionPeriod.TWO_YEARS,
            LogRetentionPeriod.SEVEN_YEARS,
            LogRetentionPeriod.INDEFINITE,
        ]
        if not sufficient_retention:
            return False

        # Requirement 2: Security logs must be collected
        if LogType.SECURITY not in self.log_types_collected:
            return False

        # Requirement 3: Audit logs must be collected
        if LogType.AUDIT not in self.log_types_collected:
            return False

        # Requirement 4: Monitoring tool must be present (already enforced by required field)
        # Requirement 5: Logs should be immutable
        if not self.logs_immutable:
            return False

        return True

    def get_non_compliance_reasons(self) -> List[str]:
        """
        Get specific reasons why this evidence is non-compliant.

        Useful for reporting and remediation guidance.

        Returns:
            List[str]: List of non-compliance reasons (empty if compliant)
        """
        reasons = []

        # Check retention period
        sufficient_retention = self.retention_period in [
            LogRetentionPeriod.ONE_YEAR,
            LogRetentionPeriod.TWO_YEARS,
            LogRetentionPeriod.SEVEN_YEARS,
            LogRetentionPeriod.INDEFINITE,
        ]
        if not sufficient_retention:
            reasons.append(
                f"Log retention period is {self.retention_period.value} "
                "(ASSURE requires >= 1 year for security/audit logs)"
            )

        # Check for security logs
        if LogType.SECURITY not in self.log_types_collected:
            reasons.append("Security logs are not being collected (ASSURE requirement)")

        # Check for audit logs
        if LogType.AUDIT not in self.log_types_collected:
            reasons.append("Audit logs are not being collected (ASSURE requirement)")

        # Check immutability
        if not self.logs_immutable:
            reasons.append(
                "Logs are not immutable/tamper-proof (ASSURE recommends "
                "write-once storage or integrity verification)"
            )

        return reasons

    def get_total_requirements(self) -> int:
        """
        Logging Configuration has 5 core requirements that ASSURE checks.

        Requirements:
        1. Log retention >= 1 year
        2. Security logs collected
        3. Audit logs collected
        4. Monitoring tool present
        5. Logs immutable/tamper-proof

        Returns:
            int: Total of 5 requirements
        """
        return 5

    def get_passed_requirements(self) -> int:
        """
        Count how many of the 5 logging requirements pass validation.

        Returns:
            int: Number of passed requirements (0-5)
        """
        passed = 0

        # Requirement 1: Retention >= 1 year
        sufficient_retention = self.retention_period in [
            LogRetentionPeriod.ONE_YEAR,
            LogRetentionPeriod.TWO_YEARS,
            LogRetentionPeriod.SEVEN_YEARS,
            LogRetentionPeriod.INDEFINITE,
        ]
        if sufficient_retention:
            passed += 1

        # Requirement 2: Security logs collected
        if LogType.SECURITY in self.log_types_collected:
            passed += 1

        # Requirement 3: Audit logs collected
        if LogType.AUDIT in self.log_types_collected:
            passed += 1

        # Requirement 4: Monitoring tool present (always true if field is set)
        if self.monitoring_tool:
            passed += 1

        # Requirement 5: Logs immutable
        if self.logs_immutable:
            passed += 1

        return passed

    def get_retention_days(self) -> int:
        """
        Convert retention period enum to approximate number of days.

        Useful for comparing against specific day requirements.

        Returns:
            int: Approximate retention period in days (or -1 for indefinite)

        Examples:
            >>> evidence.retention_period = LogRetentionPeriod.ONE_YEAR
            >>> evidence.get_retention_days()
            365
        """
        retention_map = {
            LogRetentionPeriod.THIRTY_DAYS: 30,
            LogRetentionPeriod.NINETY_DAYS: 90,
            LogRetentionPeriod.ONE_YEAR: 365,
            LogRetentionPeriod.TWO_YEARS: 730,
            LogRetentionPeriod.SEVEN_YEARS: 2555,
            LogRetentionPeriod.INDEFINITE: -1,  # Special value
        }
        return retention_map.get(self.retention_period, 0)
