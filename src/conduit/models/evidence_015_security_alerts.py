"""
Evidence Type #15: Security Alerts Configuration

ASSURE Requirement:
Vendors must implement automated security alerting for critical security events
including failed authentication attempts, privilege escalation, data access anomalies,
and system configuration changes. Alerts must be monitored 24/7 with defined response SLAs.

This evidence type captures:
- Alert types configured (failed auth, privilege escalation, etc.)
- Alert thresholds and triggering conditions
- Notification channels and recipients
- Response time SLAs for different severity levels
- 24/7 monitoring coverage
"""

from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class AlertType(str, Enum):
    """Types of security alerts that should be configured"""
    FAILED_AUTHENTICATION = "failed_authentication"  # Multiple failed login attempts
    PRIVILEGE_ESCALATION = "privilege_escalation"  # User gaining elevated permissions
    UNAUTHORIZED_ACCESS = "unauthorized_access"  # Access to restricted resources
    DATA_EXFILTRATION = "data_exfiltration"  # Unusual data transfer patterns
    CONFIGURATION_CHANGE = "configuration_change"  # Security config modifications
    MALWARE_DETECTION = "malware_detection"  # Malware/virus detected
    INTRUSION_ATTEMPT = "intrusion_attempt"  # Network intrusion detected
    ACCOUNT_LOCKOUT = "account_lockout"  # Account locked due to policy
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"  # Access to PII/sensitive data
    SYSTEM_RESOURCE_ANOMALY = "system_resource_anomaly"  # CPU/memory/disk anomalies


class AlertSeverity(str, Enum):
    """Severity levels for security alerts"""
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Action required within hours
    MEDIUM = "medium"  # Action required within 1 day
    LOW = "low"  # Action required within 1 week
    INFORMATIONAL = "informational"  # No action required, logged for audit


class NotificationChannel(str, Enum):
    """How alerts are delivered"""
    EMAIL = "email"
    SMS = "sms"
    PAGERDUTY = "pagerduty"
    SLACK = "slack"
    TEAMS = "teams"
    SIEM = "siem"  # Security Information and Event Management system
    WEBHOOK = "webhook"
    PHONE_CALL = "phone_call"


class MonitoringCoverage(str, Enum):
    """When alerts are monitored"""
    TWENTY_FOUR_SEVEN = "24/7"  # Around the clock
    BUSINESS_HOURS = "business_hours"  # 9 AM - 5 PM weekdays
    EXTENDED_HOURS = "extended_hours"  # 7 AM - 10 PM weekdays
    WEEKDAYS_ONLY = "weekdays_only"  # Mon-Fri, any hours
    AUTOMATED_ONLY = "automated_only"  # No human monitoring, automated response


class SecurityAlertConfiguration(BaseEvidence):
    """Configuration for a specific type of security alert"""

    alert_type: AlertType = Field(
        description="Type of security event that triggers this alert"
    )

    is_enabled: bool = Field(
        description="Whether this alert type is currently enabled"
    )

    severity: AlertSeverity = Field(
        description="Severity level assigned to this alert type"
    )

    threshold_description: Optional[str] = Field(
        default=None,
        description="Conditions that trigger the alert (e.g., '5 failed logins in 10 minutes')",
        max_length=500
    )

    notification_channels: List[NotificationChannel] = Field(
        description="How alerts are delivered to security team",
        min_length=1
    )

    response_sla_hours: Optional[int] = Field(
        default=None,
        description="Required response time for this alert type (in hours)",
        ge=0,
        le=168  # Max 1 week
    )


class SecurityAlertsEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Security Alerts Configuration

    ASSURE requires:
    1. Automated alerts for critical security events (failed auth, privilege escalation, etc.)
    2. 24/7 monitoring of security alerts
    3. Defined response SLAs based on severity
    4. Multiple notification channels for redundancy
    5. Alert thresholds configured to minimize false positives
    """

    evidence_type: str = Field(
        default="assure_015_security_alerts",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Alert configurations
    alert_configurations: List[SecurityAlertConfiguration] = Field(
        description="List of configured security alert types",
        min_length=1
    )

    # Monitoring coverage
    monitoring_coverage: MonitoringCoverage = Field(
        description="When security alerts are actively monitored"
    )

    monitoring_team_size: Optional[int] = Field(
        default=None,
        description="Number of people on security monitoring team",
        ge=1
    )

    # Response process
    incident_response_plan_exists: bool = Field(
        description="Whether a documented incident response plan exists"
    )

    escalation_process_defined: bool = Field(
        description="Whether there's a defined escalation process for critical alerts"
    )

    # Alert management
    false_positive_rate_acceptable: bool = Field(
        default=True,
        description="Whether false positive rate is considered acceptable (<10%)"
    )

    alert_tuning_frequency: Optional[str] = Field(
        default=None,
        description="How often alert thresholds are reviewed and tuned",
        max_length=200
    )

    # Integration with SIEM/SOAR
    integrated_with_siem: bool = Field(
        default=False,
        description="Whether alerts are integrated with a SIEM system"
    )

    siem_platform: Optional[str] = Field(
        default=None,
        description="Name of SIEM platform (e.g., 'Splunk', 'Datadog', 'AWS SecurityHub')",
        max_length=100
    )

    @field_validator("alert_configurations")
    @classmethod
    def validate_critical_alerts_configured(cls, v: List[SecurityAlertConfiguration]) -> List[SecurityAlertConfiguration]:
        """ASSURE requires specific critical alert types to be configured"""
        alert_types = {config.alert_type for config in v}

        # Critical alert types required by ASSURE
        required_alerts = {
            AlertType.FAILED_AUTHENTICATION,
            AlertType.PRIVILEGE_ESCALATION,
            AlertType.UNAUTHORIZED_ACCESS,
            AlertType.CONFIGURATION_CHANGE
        }

        missing_alerts = required_alerts - alert_types

        if missing_alerts:
            missing_names = [alert.value for alert in missing_alerts]
            raise ValueError(
                f"Missing critical alert types: {', '.join(missing_names)}. "
                f"ASSURE requires alerts for: failed authentication, privilege escalation, "
                f"unauthorized access, and configuration changes."
            )

        # Check that critical alerts are actually enabled
        disabled_critical = [
            config for config in v
            if config.alert_type in required_alerts and not config.is_enabled
        ]

        if disabled_critical:
            disabled_names = [config.alert_type.value for config in disabled_critical]
            raise ValueError(
                f"The following critical alerts are disabled: {', '.join(disabled_names)}. "
                f"ASSURE requires these alerts to be enabled."
            )

        return v

    @field_validator("monitoring_coverage")
    @classmethod
    def validate_monitoring_coverage(cls, v: MonitoringCoverage) -> MonitoringCoverage:
        """ASSURE requires 24/7 monitoring for critical security alerts"""
        insufficient_coverage = [
            MonitoringCoverage.BUSINESS_HOURS,
            MonitoringCoverage.WEEKDAYS_ONLY,
            MonitoringCoverage.AUTOMATED_ONLY
        ]

        if v in insufficient_coverage:
            raise ValueError(
                f"Monitoring coverage is {v.value}. "
                f"ASSURE requires 24/7 monitoring of critical security alerts."
            )

        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for security alerts.

        ASSURE requirements:
        1. Failed authentication alerts configured and enabled
        2. Privilege escalation alerts configured and enabled
        3. Unauthorized access alerts configured and enabled
        4. Configuration change alerts configured and enabled
        5. 24/7 monitoring coverage
        6. Incident response plan exists
        7. Escalation process defined
        8. Response SLAs defined for critical alerts
        9. Multiple notification channels (redundancy)
        10. Integration with SIEM (recommended)

        Total: 10 requirements (9 mandatory, 1 recommended)
        """
        return 10

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        alert_types = {config.alert_type for config in self.alert_configurations}
        enabled_alerts = {config.alert_type for config in self.alert_configurations if config.is_enabled}

        # Requirements 1-4: Critical alert types configured and enabled
        critical_alerts = {
            AlertType.FAILED_AUTHENTICATION,
            AlertType.PRIVILEGE_ESCALATION,
            AlertType.UNAUTHORIZED_ACCESS,
            AlertType.CONFIGURATION_CHANGE
        }

        for alert_type in critical_alerts:
            if alert_type in enabled_alerts:
                passed += 1

        # Requirement 5: 24/7 monitoring coverage
        if self.monitoring_coverage in [
            MonitoringCoverage.TWENTY_FOUR_SEVEN,
            MonitoringCoverage.EXTENDED_HOURS
        ]:
            passed += 1

        # Requirement 6: Incident response plan exists
        if self.incident_response_plan_exists:
            passed += 1

        # Requirement 7: Escalation process defined
        if self.escalation_process_defined:
            passed += 1

        # Requirement 8: Response SLAs defined for critical alerts
        critical_configs = [c for c in self.alert_configurations if c.alert_type in critical_alerts]
        if all(c.response_sla_hours is not None for c in critical_configs):
            passed += 1

        # Requirement 9: Multiple notification channels (redundancy)
        # Check if any alert has multiple channels
        has_redundancy = any(len(c.notification_channels) >= 2 for c in self.alert_configurations)
        if has_redundancy:
            passed += 1

        # Requirement 10: Integration with SIEM (recommended)
        if self.integrated_with_siem:
            passed += 1

        return passed
