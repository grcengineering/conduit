"""Tests for ASSURE Control #7: BCP/DR Testing Evidence"""

from datetime import date, timedelta

import pytest
from pydantic import ValidationError

from conduit.models.evidence_007_bcpdr import (
    BCPDREvidence,
    BCPDRFinding,
    TestResult,
    TestType,
)


class TestBCPDREvidence:
    """Test suite for BCP/DR Testing evidence model"""

    def test_valid_evidence_passes(self):
        """Test that valid BCP/DR evidence passes validation"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=30),  # Recent test
            test_result=TestResult.PASS,
            test_type=TestType.FULL_FAILOVER,
            scope="Production database and application servers",
            extraction_confidence=0.95,
        )

        assert evidence.vendor_name == "Acme Corp"
        assert evidence.test_result == TestResult.PASS
        assert evidence.is_compliant() is True

    def test_old_test_date_rejected(self):
        """Test that test date older than 12 months raises ValidationError"""
        with pytest.raises(ValidationError) as exc_info:
            BCPDREvidence(
                vendor_name="Acme Corp",
                evidence_date=date.today(),
                test_date=date.today() - timedelta(days=400),  # Too old!
                test_result=TestResult.PASS,
                test_type=TestType.FULL_FAILOVER,
                scope="Production systems",
                extraction_confidence=0.95,
            )

        # Check that error message mentions "older than 12 months"
        error_message = str(exc_info.value)
        assert "older than 12 months" in error_message.lower()

    def test_pass_with_findings_is_compliant(self):
        """Test that PASS_WITH_FINDINGS is considered compliant"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=60),
            test_result=TestResult.PASS_WITH_FINDINGS,
            test_type=TestType.PARTIAL_FAILOVER,
            scope="Database failover only",
            findings=[
                BCPDRFinding(
                    finding="DNS propagation took 15 minutes instead of 5",
                    severity="medium",
                    remediation_status="in_progress",
                )
            ],
            extraction_confidence=0.90,
        )

        assert evidence.is_compliant() is True
        assert len(evidence.findings) == 1

    def test_failed_test_is_non_compliant(self):
        """Test that FAIL result makes evidence non-compliant"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=30),
            test_result=TestResult.FAIL,
            test_type=TestType.FULL_FAILOVER,
            scope="Production systems",
            extraction_confidence=0.95,
        )

        assert evidence.is_compliant() is False

    def test_get_non_compliance_reasons_for_old_test(self):
        """Test non-compliance reasons for old test date"""
        old_date = date.today() - timedelta(days=400)

        # Create evidence (bypass validation for testing)
        evidence = BCPDREvidence.model_construct(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=old_date,
            test_result=TestResult.PASS,
            test_type=TestType.TABLETOP,
            scope="Tabletop exercise",
            extraction_confidence=0.85,
        )

        reasons = evidence.get_non_compliance_reasons()
        assert len(reasons) > 0
        assert any("older than 12 months" in reason for reason in reasons)

    def test_get_non_compliance_reasons_for_failed_test(self):
        """Test non-compliance reasons for failed test"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=30),
            test_result=TestResult.FAIL,
            test_type=TestType.FULL_FAILOVER,
            scope="Production systems",
            extraction_confidence=0.95,
        )

        reasons = evidence.get_non_compliance_reasons()
        assert len(reasons) > 0
        assert any("failed" in reason.lower() for reason in reasons)

    def test_optional_fields_work(self):
        """Test that optional fields (RTO/RPO met) work correctly"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=45),
            test_result=TestResult.PASS,
            test_type=TestType.FULL_FAILOVER,
            scope="All production systems",
            recovery_time_objective_met=True,
            recovery_point_objective_met=True,
            extraction_confidence=0.98,
        )

        assert evidence.recovery_time_objective_met is True
        assert evidence.recovery_point_objective_met is True
        assert evidence.is_compliant() is True

    def test_soc2_overlap_defaults(self):
        """Test that SOC 2 overlap fields have correct defaults"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=30),
            test_result=TestResult.PASS,
            test_type=TestType.FULL_FAILOVER,
            scope="Production systems",
            extraction_confidence=0.95,
        )

        assert "A1.3" in evidence.soc2_section_4_criteria
        assert evidence.soc2_coverage_percentage == 90

    def test_json_schema_generation(self):
        """Test that Pydantic can generate JSON schema"""
        schema = BCPDREvidence.model_json_schema()

        assert schema["type"] == "object"
        assert "properties" in schema
        assert "test_date" in schema["properties"]
        assert "test_result" in schema["properties"]
        assert "required" in schema

    def test_evidence_type_default(self):
        """Test that evidence_type has correct default value"""
        evidence = BCPDREvidence(
            vendor_name="Acme Corp",
            evidence_date=date.today(),
            test_date=date.today() - timedelta(days=30),
            test_result=TestResult.PASS,
            test_type=TestType.FULL_FAILOVER,
            scope="Production systems",
            extraction_confidence=0.95,
        )

        assert evidence.evidence_type == "assure_007_bcpdr_testing"


class TestBCPDRFinding:
    """Test suite for BCP/DR Finding model"""

    def test_valid_finding(self):
        """Test that valid finding passes validation"""
        finding = BCPDRFinding(
            finding="Recovery took longer than expected",
            severity="high",
            remediation_status="open",
        )

        assert finding.finding == "Recovery took longer than expected"
        assert finding.severity == "high"

    def test_invalid_severity_rejected(self):
        """Test that invalid severity value raises ValidationError"""
        with pytest.raises(ValidationError):
            BCPDRFinding(
                finding="Some issue",
                severity="super_critical",  # Invalid!
                remediation_status="open",
            )

    def test_invalid_remediation_status_rejected(self):
        """Test that invalid remediation status raises ValidationError"""
        with pytest.raises(ValidationError):
            BCPDRFinding(
                finding="Some issue",
                severity="medium",
                remediation_status="maybe_fixed",  # Invalid!
            )


class TestEnums:
    """Test suite for BCP/DR enums"""

    def test_test_result_enum(self):
        """Test TestResult enum values"""
        assert TestResult.PASS.value == "pass"
        assert TestResult.PASS_WITH_FINDINGS.value == "pass_with_findings"
        assert TestResult.FAIL.value == "fail"

    def test_test_type_enum(self):
        """Test TestType enum values"""
        assert TestType.TABLETOP.value == "tabletop"
        assert TestType.PARTIAL_FAILOVER.value == "partial_failover"
        assert TestType.FULL_FAILOVER.value == "full_failover"
