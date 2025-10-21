"""Evidence Type #24: AI/ML Security Controls"""
from enum import Enum
from typing import Optional, List
from pydantic import Field, field_validator
from .base import BaseEvidence


class AIRiskLevel(str, Enum):
    """Risk levels for AI systems"""
    CRITICAL = "critical"  # High-risk AI (e.g., credit decisions, medical)
    HIGH = "high"  # Significant risk
    MEDIUM = "medium"  # Moderate risk
    LOW = "low"  # Low risk
    MINIMAL = "minimal"  # Minimal risk


class AIUseCase(str, Enum):
    """Common AI/ML use cases"""
    CONTENT_GENERATION = "content_generation"  # Text, image, code generation
    DECISION_MAKING = "decision_making"  # Automated decisions
    RECOMMENDATION = "recommendation"  # Recommendations/suggestions
    FRAUD_DETECTION = "fraud_detection"  # Fraud/anomaly detection
    PERSONALIZATION = "personalization"  # Content personalization
    PREDICTION = "prediction"  # Predictive analytics
    CLASSIFICATION = "classification"  # Data classification
    CONVERSATIONAL_AI = "conversational_ai"  # Chatbots, assistants
    AUTOMATION = "automation"  # Process automation
    OTHER = "other"  # Other use case


class AIGovernanceEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: AI/ML Security Controls

    ASSURE requires (emerging standard based on NIST AI RMF):
    1. Inventory of AI systems and use cases
    2. Risk assessment for AI systems (NIST AI RMF)
    3. Training data governance (provenance, quality, bias)
    4. Model validation and testing (accuracy, bias, fairness)
    5. Explainability/interpretability for high-risk AI
    6. Human oversight for critical AI decisions
    7. Adversarial testing and robustness validation
    8. AI incident response procedures
    9. Third-party AI model risk management
    """

    evidence_type: str = Field(
        default="assure_024_ai_governance",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # AI systems inventory
    ai_systems_used: bool = Field(
        description="Whether vendor uses AI/ML systems in their product/service"
    )

    ai_inventory_maintained: bool = Field(
        default=False,
        description="Whether vendor maintains inventory of AI systems"
    )

    ai_use_cases: List[AIUseCase] = Field(
        default_factory=list,
        description="List of AI/ML use cases"
    )

    ai_use_case_descriptions: Optional[str] = Field(
        default=None,
        description="Detailed descriptions of AI use cases",
        max_length=2000
    )

    # Risk assessment
    ai_risk_assessment_performed: bool = Field(
        default=False,
        description="Whether AI risk assessments are performed (e.g., NIST AI RMF)"
    )

    highest_ai_risk_level: Optional[AIRiskLevel] = Field(
        default=None,
        description="Highest risk level of AI systems in use"
    )

    ai_risk_framework_used: Optional[str] = Field(
        default=None,
        description="AI risk framework used (e.g., 'NIST AI RMF', 'EU AI Act')",
        max_length=200
    )

    # Training data governance
    training_data_governance_exists: bool = Field(
        default=False,
        description="Whether training data governance processes exist"
    )

    training_data_provenance_tracked: bool = Field(
        default=False,
        description="Whether training data source/provenance is tracked"
    )

    training_data_quality_validated: bool = Field(
        default=False,
        description="Whether training data quality is validated"
    )

    customer_data_used_for_training: bool = Field(
        default=False,
        description="Whether customer data is used for model training"
    )

    customer_data_training_opt_out: bool = Field(
        default=False,
        description="Whether customers can opt out of data being used for training"
    )

    # Model validation and testing
    model_validation_performed: bool = Field(
        default=False,
        description="Whether AI models undergo validation testing"
    )

    bias_testing_performed: bool = Field(
        default=False,
        description="Whether bias/fairness testing is performed on AI models"
    )

    bias_testing_frequency: Optional[str] = Field(
        default=None,
        description="Frequency of bias testing (e.g., 'quarterly', 'before each release')",
        max_length=100
    )

    accuracy_metrics_tracked: bool = Field(
        default=False,
        description="Whether model accuracy metrics are tracked over time"
    )

    # Explainability and transparency
    explainability_provided: bool = Field(
        default=False,
        description="Whether AI decisions are explainable/interpretable"
    )

    model_cards_published: bool = Field(
        default=False,
        description="Whether model cards or similar documentation are published"
    )

    ai_transparency_report: bool = Field(
        default=False,
        description="Whether vendor publishes AI transparency reports"
    )

    # Human oversight
    human_oversight_exists: bool = Field(
        default=False,
        description="Whether human oversight exists for AI decisions"
    )

    human_review_for_critical_decisions: bool = Field(
        default=False,
        description="Whether critical AI decisions require human review"
    )

    ai_decision_appeal_process: bool = Field(
        default=False,
        description="Whether users can appeal AI decisions"
    )

    # Adversarial testing
    adversarial_testing_performed: bool = Field(
        default=False,
        description="Whether adversarial/robustness testing is performed"
    )

    red_team_testing_performed: bool = Field(
        default=False,
        description="Whether red team testing is performed on AI systems"
    )

    # Incident response
    ai_incident_response_plan: bool = Field(
        default=False,
        description="Whether specific incident response plan exists for AI failures"
    )

    ai_incident_monitoring: bool = Field(
        default=False,
        description="Whether AI system behavior is monitored for anomalies/drift"
    )

    # Third-party AI
    third_party_ai_models_used: bool = Field(
        default=False,
        description="Whether third-party AI models are used (e.g., OpenAI, Anthropic)"
    )

    third_party_ai_risk_assessed: bool = Field(
        default=False,
        description="Whether third-party AI model risks are assessed"
    )

    third_party_ai_vendors: List[str] = Field(
        default_factory=list,
        description="List of third-party AI vendors (e.g., 'OpenAI', 'Anthropic', 'Google')"
    )

    @field_validator("ai_systems_used")
    @classmethod
    def validate_ai_disclosure(cls, v: bool) -> bool:
        """Note: This is informational - no validation failure if no AI used"""
        return v

    @field_validator("bias_testing_performed")
    @classmethod
    def validate_bias_testing_for_high_risk(cls, v: bool, info) -> bool:
        """ASSURE recommends bias testing for high-risk AI"""
        highest_risk = info.data.get('highest_ai_risk_level')
        if highest_risk in [AIRiskLevel.CRITICAL, AIRiskLevel.HIGH] and not v:
            raise ValueError(
                f"AI system is {highest_risk} risk but no bias testing performed. "
                f"ASSURE requires bias/fairness testing for high-risk AI systems."
            )
        return v

    @field_validator("human_review_for_critical_decisions")
    @classmethod
    def validate_human_oversight_for_critical(cls, v: bool, info) -> bool:
        """ASSURE requires human oversight for critical AI decisions"""
        highest_risk = info.data.get('highest_ai_risk_level')
        if highest_risk == AIRiskLevel.CRITICAL and not v:
            raise ValueError(
                "AI system is critical risk but no human review for decisions. "
                "ASSURE requires human oversight for critical AI decisions."
            )
        return v

    def get_total_requirements(self) -> int:
        """Total number of ASSURE requirements for AI governance evidence"""
        # If no AI used, requirement count is 1 (disclosure)
        if not self.ai_systems_used:
            return 1
        # If AI used, full requirements apply
        return 9

    def get_passed_requirements(self) -> int:
        """Count how many requirements are met"""
        # If no AI systems used, single requirement is met (disclosure)
        if not self.ai_systems_used:
            return 1

        passed = 0

        # 1. AI inventory maintained
        if self.ai_inventory_maintained:
            passed += 1

        # 2. Risk assessment performed
        if self.ai_risk_assessment_performed:
            passed += 1

        # 3. Training data governance
        if self.training_data_governance_exists and self.training_data_provenance_tracked:
            passed += 1

        # 4. Model validation and bias testing
        if self.model_validation_performed and self.bias_testing_performed:
            passed += 1

        # 5. Explainability for high-risk AI
        if self.highest_ai_risk_level in [AIRiskLevel.CRITICAL, AIRiskLevel.HIGH]:
            if self.explainability_provided:
                passed += 1
        else:
            passed += 1  # Not high-risk, so automatically passes

        # 6. Human oversight for critical decisions
        if self.highest_ai_risk_level == AIRiskLevel.CRITICAL:
            if self.human_review_for_critical_decisions:
                passed += 1
        else:
            passed += 1  # Not critical, so automatically passes

        # 7. Adversarial testing
        if self.adversarial_testing_performed or self.red_team_testing_performed:
            passed += 1

        # 8. AI incident response
        if self.ai_incident_response_plan and self.ai_incident_monitoring:
            passed += 1

        # 9. Third-party AI risk management
        if not self.third_party_ai_models_used:
            passed += 1  # Not using third-party AI, requirement N/A
        elif self.third_party_ai_risk_assessed:
            passed += 1

        return passed
