"""Evidence Type #16: Change Management Process"""
from enum import Enum
from typing import Optional
from pydantic import Field
from .base import BaseEvidence

class ChangeApprovalLevel(str, Enum):
    AUTOMATED = "automated"  # Low-risk changes
    PEER_APPROVAL = "peer_approval"
    MANAGER_APPROVAL = "manager_approval"
    CAB_APPROVAL = "cab_approval"  # Change Advisory Board

class ChangeManagementEvidence(BaseEvidence):
    evidence_type: str = Field(default="assure_016_change_management", frozen=True)

    # Change process
    change_management_process_documented: bool
    change_approval_required: bool
    approval_level: ChangeApprovalLevel

    # Testing
    testing_required_before_production: bool
    rollback_plan_required: bool

    # Tracking
    change_tracking_tool: Optional[str] = Field(default=None, max_length=200)
    changes_logged: bool

    # Emergency changes
    emergency_change_process: bool = False
    emergency_changes_reviewed_post_implementation: bool = False

    # Communication
    change_communication_process: bool = False
    stakeholder_notification: bool = False

    def get_total_requirements(self) -> int:
        return 9

    def get_passed_requirements(self) -> int:
        passed = 0
        if self.change_management_process_documented: passed += 1
        if self.change_approval_required: passed += 1
        if self.approval_level in [ChangeApprovalLevel.CAB_APPROVAL, ChangeApprovalLevel.MANAGER_APPROVAL]: passed += 1
        if self.testing_required_before_production: passed += 1
        if self.rollback_plan_required: passed += 1
        if self.changes_logged: passed += 1
        if self.emergency_change_process: passed += 1
        if self.change_communication_process: passed += 1
        if self.stakeholder_notification: passed += 1
        return passed
