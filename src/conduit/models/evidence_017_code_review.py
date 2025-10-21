"""
Evidence Type #17: Code Review Requirements

ASSURE Requirement:
Vendors must enforce mandatory code review processes for all production code changes.
Reviews must include security considerations and be performed by qualified reviewers.

This evidence type captures:
- Whether peer code review is mandatory
- Review tool/platform used
- Security checks included in reviews
- Reviewer qualifications
- Enforcement mechanism
"""

from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class CodeReviewTool(str, Enum):
    """Tools/platforms used for code review"""
    GITHUB = "github"  # GitHub Pull Requests
    GITLAB = "gitlab"  # GitLab Merge Requests
    BITBUCKET = "bitbucket"  # Bitbucket Pull Requests
    AZURE_DEVOPS = "azure_devops"  # Azure DevOps
    GERRIT = "gerrit"  # Gerrit Code Review
    PHABRICATOR = "phabricator"  # Phabricator/Differential
    CRUCIBLE = "crucible"  # Atlassian Crucible
    REVIEW_BOARD = "review_board"  # Review Board
    CUSTOM = "custom"  # Custom review system


class SecurityCheckType(str, Enum):
    """Types of security checks in code reviews"""
    INPUT_VALIDATION = "input_validation"  # Check for input validation
    AUTHENTICATION = "authentication"  # Check auth/authorization logic
    SENSITIVE_DATA = "sensitive_data"  # Check for hardcoded secrets/credentials
    SQL_INJECTION = "sql_injection"  # Check for SQL injection risks
    XSS = "xss"  # Check for XSS vulnerabilities
    DEPENDENCY_SECURITY = "dependency_security"  # Check dependency versions
    ACCESS_CONTROL = "access_control"  # Check access control logic
    CRYPTOGRAPHY = "cryptography"  # Check crypto usage
    ERROR_HANDLING = "error_handling"  # Check error handling/logging
    SECURITY_BEST_PRACTICES = "security_best_practices"  # General security practices


class ReviewerQualification(str, Enum):
    """Qualifications for code reviewers"""
    SENIOR_DEVELOPER = "senior_developer"  # Senior developer on team
    SECURITY_ENGINEER = "security_engineer"  # Dedicated security engineer
    TEAM_LEAD = "team_lead"  # Team lead or tech lead
    ARCHITECT = "architect"  # Software architect
    ANY_TEAM_MEMBER = "any_team_member"  # Any team member can review
    SECURITY_TRAINED = "security_trained"  # Security training required


class CodeReviewEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Code Review Requirements

    ASSURE requires:
    1. Peer code review mandatory for all production code changes
    2. Reviews enforced through technical controls (branch protection)
    3. Security considerations included in review process
    4. Qualified reviewers (senior developers or security trained)
    5. Review tool/platform in use
    6. No bypassing of review process
    """

    evidence_type: str = Field(
        default="assure_017_code_review",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Code review enforcement
    peer_review_required: bool = Field(
        description="Whether peer code review is required for all production code changes"
    )

    review_tool: CodeReviewTool = Field(
        description="Tool/platform used for code reviews"
    )

    review_tool_name: Optional[str] = Field(
        default=None,
        description="Specific name of review tool (if custom or specific product)",
        max_length=200
    )

    # Technical enforcement
    technically_enforced: bool = Field(
        description="Whether code review is technically enforced (e.g., branch protection rules)"
    )

    branch_protection_enabled: bool = Field(
        description="Whether branch protection prevents direct commits to main/production branches"
    )

    minimum_reviewers_required: Optional[int] = Field(
        default=None,
        description="Minimum number of reviewers required before merge",
        ge=0,
        le=10
    )

    # Security checks
    security_checks_included: bool = Field(
        description="Whether security considerations are explicitly included in code review process"
    )

    security_check_types: List[SecurityCheckType] = Field(
        default_factory=list,
        description="Types of security checks performed during code review"
    )

    security_checklist_used: bool = Field(
        default=False,
        description="Whether a security review checklist is used"
    )

    # Reviewer qualifications
    reviewer_qualifications: List[ReviewerQualification] = Field(
        description="Qualifications required for code reviewers",
        min_length=1
    )

    security_engineer_review_required: bool = Field(
        default=False,
        description="Whether security-sensitive changes require security engineer review"
    )

    # Review process
    automated_checks_in_review: bool = Field(
        default=False,
        description="Whether automated checks (linting, SAST, tests) run before review"
    )

    review_comments_required: bool = Field(
        default=False,
        description="Whether reviewers must leave comments/feedback"
    )

    # Bypass controls
    review_bypass_allowed: bool = Field(
        description="Whether bypassing code review is allowed (emergency/hotfix)"
    )

    bypass_documented: bool = Field(
        default=False,
        description="Whether review bypasses are logged and require justification"
    )

    bypass_requires_approval: bool = Field(
        default=False,
        description="Whether bypassing review requires senior approval"
    )

    @field_validator("peer_review_required")
    @classmethod
    def validate_review_required(cls, v: bool) -> bool:
        """ASSURE requires peer code review for all production changes"""
        if not v:
            raise ValueError(
                "Peer code review is not required. "
                "ASSURE requires mandatory code review for all production code changes."
            )
        return v

    @field_validator("technically_enforced")
    @classmethod
    def validate_technical_enforcement(cls, v: bool) -> bool:
        """ASSURE requires technical enforcement, not just policy"""
        if not v:
            raise ValueError(
                "Code review is not technically enforced. "
                "ASSURE requires technical controls (e.g., branch protection) to enforce code review."
            )
        return v

    @field_validator("minimum_reviewers_required")
    @classmethod
    def validate_reviewer_count(cls, v: Optional[int]) -> Optional[int]:
        """ASSURE recommends at least 1 reviewer"""
        if v is not None and v < 1:
            raise ValueError(
                "Minimum reviewers required is less than 1. "
                "ASSURE requires at least one peer reviewer for all code changes."
            )
        return v

    @field_validator("reviewer_qualifications")
    @classmethod
    def validate_qualifications(cls, v: List[ReviewerQualification]) -> List[ReviewerQualification]:
        """Validate reviewer qualifications are appropriate"""
        if ReviewerQualification.ANY_TEAM_MEMBER in v and len(v) == 1:
            import logging
            logging.warning(
                "Any team member can review code without specific qualifications. "
                "ASSURE recommends requiring senior developers or security-trained reviewers."
            )
        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for code review.

        ASSURE requirements:
        1. Peer review required for all production changes
        2. Review tool/platform in use
        3. Technical enforcement (branch protection)
        4. At least 1 reviewer required before merge
        5. Security checks included in review process
        6. Qualified reviewers (not just any team member)
        7. Automated checks run before review
        8. If bypass allowed, it must be documented and require approval

        Total: 8 requirements
        """
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Requirement 1: Peer review required
        if self.peer_review_required:
            passed += 1

        # Requirement 2: Review tool in use
        if self.review_tool:
            passed += 1

        # Requirement 3: Technical enforcement (branch protection)
        if self.technically_enforced and self.branch_protection_enabled:
            passed += 1

        # Requirement 4: At least 1 reviewer required
        if self.minimum_reviewers_required and self.minimum_reviewers_required >= 1:
            passed += 1

        # Requirement 5: Security checks included
        if self.security_checks_included:
            passed += 1

        # Requirement 6: Qualified reviewers
        # Pass if NOT just "any team member"
        qualified = [q for q in self.reviewer_qualifications if q != ReviewerQualification.ANY_TEAM_MEMBER]
        if qualified:
            passed += 1

        # Requirement 7: Automated checks run before review
        if self.automated_checks_in_review:
            passed += 1

        # Requirement 8: If bypass allowed, proper controls exist
        if not self.review_bypass_allowed:
            passed += 1  # No bypass = pass
        elif self.bypass_documented and self.bypass_requires_approval:
            passed += 1  # Bypass with controls = pass

        return passed
