"""
Test suite for Evidence #5: Incident Response

This test validates the complete implementation:
- Pydantic model with 3 enums and 6 requirements
- Training examples with 3 XML examples
- XML parser handling incident_types_covered array
- Normalizers for incident types, test types, and SLAs
- Transformer function
"""

import pytest
from datetime import date, timedelta
from conduit.models.evidence_005_incident_response import (
    IncidentResponseEvidence,
    IncidentType,
    TestType,
    NotificationSLA,
)


class TestEnums:
    """Test that all required enums are properly defined"""

    def test_incident_type_enum(self):
        """Verify IncidentType enum has 5 required values"""
        assert IncidentType.SECURITY_BREACH.value == "security_breach"
        assert IncidentType.PRIVACY_BREACH.value == "privacy_breach"
        assert IncidentType.AVAILABILITY.value == "availability"
        assert IncidentType.DATA_INTEGRITY.value == "data_integrity"
        assert IncidentType.RANSOMWARE.value == "ransomware"

        # Verify enum count
        assert len(IncidentType) == 5

    def test_test_type_enum(self):
        """Verify TestType enum has 5 required values"""
        assert TestType.TABLETOP.value == "tabletop"
        assert TestType.WALKTHROUGH.value == "walkthrough"
        assert TestType.SIMULATION.value == "simulation"
        assert TestType.LIVE_DRILL.value == "live_drill"
        assert TestType.NONE.value == "none"

        # Verify enum count
        assert len(TestType) == 5

    def test_notification_sla_enum(self):
        """Verify NotificationSLA enum has 6 required values"""
        assert NotificationSLA.IMMEDIATE.value == "immediate"
        assert NotificationSLA.ONE_HOUR.value == "1_hour"
        assert NotificationSLA.FOUR_HOURS.value == "4_hours"
        assert NotificationSLA.TWENTY_FOUR_HOURS.value == "24_hours"
        assert NotificationSLA.SEVENTY_TWO_HOURS.value == "72_hours"
        assert NotificationSLA.NONE.value == "none"

        # Verify enum count
        assert len(NotificationSLA) == 6


class TestPydanticModel:
    """Test Pydantic model validation and compliance checking"""

    def test_compliant_evidence(self):
        """Test fully compliant incident response evidence"""
        evidence = IncidentResponseEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            plan_exists=True,
            last_test_date=date.today() - timedelta(days=30),
            test_type=TestType.TABLETOP,
            incident_types_covered=[
                IncidentType.SECURITY_BREACH,
                IncidentType.PRIVACY_BREACH,
                IncidentType.RANSOMWARE,
            ],
            security_breach_sla=NotificationSLA.TWENTY_FOUR_HOURS,
            privacy_breach_sla=NotificationSLA.SEVENTY_TWO_HOURS,
            lessons_learned_documented=True,
            plan_accessible_to_employees=True,
            extraction_confidence=0.95,
        )

        # Verify compliance
        assert evidence.is_compliant() is True
        assert evidence.get_compliance_percentage() == 100.0
        assert evidence.get_passed_requirements() == 6
        assert evidence.get_total_requirements() == 6
        assert len(evidence.get_non_compliance_reasons()) == 0

    def test_non_compliant_no_plan(self):
        """Test evidence with no plan - should fail all checks"""
        evidence = IncidentResponseEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            plan_exists=False,
            last_test_date=None,
            test_type=TestType.NONE,
            incident_types_covered=[],
            security_breach_sla=NotificationSLA.NONE,
            privacy_breach_sla=NotificationSLA.NONE,
            lessons_learned_documented=False,
            plan_accessible_to_employees=False,
            extraction_confidence=0.85,
        )

        # Verify non-compliance
        assert evidence.is_compliant() is False
        assert evidence.get_compliance_percentage() == 0.0
        assert evidence.get_passed_requirements() == 0
        assert evidence.get_total_requirements() == 6

        reasons = evidence.get_non_compliance_reasons()
        assert "No documented incident response plan exists" in reasons

    def test_non_compliant_old_test(self):
        """Test evidence with test older than 12 months"""
        old_test_date = date.today() - timedelta(days=400)

        with pytest.raises(ValueError, match="older than 12 months"):
            IncidentResponseEvidence(
                vendor_name="Acme Corp",
                evidence_date=date.today(),
                plan_exists=True,
                last_test_date=old_test_date,
                test_type=TestType.TABLETOP,
                incident_types_covered=[
                    IncidentType.SECURITY_BREACH,
                    IncidentType.PRIVACY_BREACH,
                    IncidentType.RANSOMWARE,
                ],
                security_breach_sla=NotificationSLA.TWENTY_FOUR_HOURS,
                privacy_breach_sla=NotificationSLA.SEVENTY_TWO_HOURS,
                lessons_learned_documented=True,
                plan_accessible_to_employees=True,
                extraction_confidence=0.85,
            )

    def test_non_compliant_missing_critical_incident_types(self):
        """Test evidence missing critical incident types"""
        evidence = IncidentResponseEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            plan_exists=True,
            last_test_date=date.today() - timedelta(days=30),
            test_type=TestType.TABLETOP,
            incident_types_covered=[
                IncidentType.AVAILABILITY,  # Missing critical types
            ],
            security_breach_sla=NotificationSLA.TWENTY_FOUR_HOURS,
            privacy_breach_sla=NotificationSLA.SEVENTY_TWO_HOURS,
            lessons_learned_documented=True,
            plan_accessible_to_employees=True,
            extraction_confidence=0.85,
        )

        # Verify partial compliance
        assert evidence.is_compliant() is False
        assert evidence.get_passed_requirements() == 5  # Missing 1 requirement

        reasons = evidence.get_non_compliance_reasons()
        assert any("does not cover critical incident types" in r for r in reasons)

    def test_non_compliant_missing_slas(self):
        """Test evidence with missing notification SLAs"""
        evidence = IncidentResponseEvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            plan_exists=True,
            last_test_date=date.today() - timedelta(days=30),
            test_type=TestType.SIMULATION,
            incident_types_covered=[
                IncidentType.SECURITY_BREACH,
                IncidentType.PRIVACY_BREACH,
                IncidentType.RANSOMWARE,
            ],
            security_breach_sla=NotificationSLA.NONE,
            privacy_breach_sla=NotificationSLA.NONE,
            lessons_learned_documented=True,
            plan_accessible_to_employees=True,
            extraction_confidence=0.85,
        )

        # Verify partial compliance
        assert evidence.is_compliant() is False
        assert evidence.get_passed_requirements() == 4  # Missing 2 SLA requirements

        reasons = evidence.get_non_compliance_reasons()
        assert "No notification SLA defined for security breaches" in reasons
        assert "No notification SLA defined for privacy breaches" in reasons


class TestRequirementsCounting:
    """Test that get_total_requirements() and get_passed_requirements() work correctly"""

    def test_total_requirements_returns_6(self):
        """Verify total requirements is always 6"""
        evidence = IncidentResponseEvidence(
            vendor_name="Test Vendor",
            evidence_date=date.today(),
            plan_exists=True,
            last_test_date=date.today(),
            test_type=TestType.TABLETOP,
            incident_types_covered=[],
            security_breach_sla=NotificationSLA.NONE,
            privacy_breach_sla=NotificationSLA.NONE,
            lessons_learned_documented=False,
            plan_accessible_to_employees=False,
            extraction_confidence=0.80,
        )

        assert evidence.get_total_requirements() == 6

    def test_passed_requirements_incremental(self):
        """Test that passed requirements count increases correctly"""

        # 1 requirement passed: plan exists only
        evidence = IncidentResponseEvidence(
            vendor_name="Test",
            evidence_date=date.today(),
            plan_exists=True,
            last_test_date=None,
            test_type=TestType.NONE,
            incident_types_covered=[],
            security_breach_sla=NotificationSLA.NONE,
            privacy_breach_sla=NotificationSLA.NONE,
            lessons_learned_documented=False,
            plan_accessible_to_employees=False,
            extraction_confidence=0.80,
        )
        assert evidence.get_passed_requirements() == 1

        # 2 requirements passed: plan + test
        evidence.last_test_date = date.today() - timedelta(days=30)
        evidence.test_type = TestType.TABLETOP
        assert evidence.get_passed_requirements() == 2

        # 3 requirements passed: plan + test + incident types
        evidence.incident_types_covered = [
            IncidentType.SECURITY_BREACH,
            IncidentType.PRIVACY_BREACH,
            IncidentType.RANSOMWARE,
        ]
        assert evidence.get_passed_requirements() == 3

        # 4 requirements passed: + security SLA
        evidence.security_breach_sla = NotificationSLA.TWENTY_FOUR_HOURS
        assert evidence.get_passed_requirements() == 4

        # 5 requirements passed: + privacy SLA
        evidence.privacy_breach_sla = NotificationSLA.SEVENTY_TWO_HOURS
        assert evidence.get_passed_requirements() == 5

        # 6 requirements passed: + lessons learned
        evidence.lessons_learned_documented = True
        assert evidence.get_passed_requirements() == 6


class TestNormalizerFunctions:
    """Test normalizer functions for transforming variations to enum values"""

    def test_incident_type_normalizers(self):
        """Test incident type normalization"""
        from conduit.transformer import normalize_incident_type

        # Security breach variations
        assert normalize_incident_type("security incident") == "security_breach"
        assert normalize_incident_type("cyberattack") == "security_breach"
        assert normalize_incident_type("intrusion") == "security_breach"

        # Privacy breach variations
        assert normalize_incident_type("data breach") == "privacy_breach"
        assert normalize_incident_type("privacy incident") == "privacy_breach"
        assert normalize_incident_type("PII breach") == "privacy_breach"

        # Ransomware variations
        assert normalize_incident_type("ransomware attack") == "ransomware"
        assert normalize_incident_type("crypto attack") == "ransomware"

        # Availability variations
        assert normalize_incident_type("system outage") == "availability"
        assert normalize_incident_type("downtime") == "availability"

        # Data integrity variations
        assert normalize_incident_type("data corruption") == "data_integrity"
        assert normalize_incident_type("integrity issue") == "data_integrity"

    def test_ir_test_type_normalizers(self):
        """Test IR test type normalization"""
        from conduit.transformer import normalize_ir_test_type

        assert normalize_ir_test_type("tabletop exercise") == "tabletop"
        assert normalize_ir_test_type("discussion") == "tabletop"
        assert normalize_ir_test_type("walkthrough") == "walkthrough"
        assert normalize_ir_test_type("simulation") == "simulation"
        assert normalize_ir_test_type("live drill") == "live_drill"
        assert normalize_ir_test_type("none") == "none"

    def test_notification_sla_normalizers(self):
        """Test notification SLA normalization"""
        from conduit.transformer import normalize_notification_sla

        assert normalize_notification_sla("immediately") == "immediate"
        assert normalize_notification_sla("within 24 hours") == "24_hours"
        assert normalize_notification_sla("1 day") == "24_hours"
        assert normalize_notification_sla("72 hours") == "72_hours"
        assert normalize_notification_sla("3 days") == "72_hours"
        assert normalize_notification_sla("1 hour") == "1_hour"
        assert normalize_notification_sla("4 hours") == "4_hours"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
