"""
Evidence Type #1: Architecture & Segmentation

ASSURE Requirement:
Vendors must provide comprehensive system architecture documentation showing network
segmentation, security boundaries, data flow between components, and isolation between
customer environments. This demonstrates defense-in-depth and least privilege at the
infrastructure level.

This evidence type captures:
- Architecture diagram reference
- Network segmentation strategy
- Security zones and boundaries
- Multi-tenancy isolation approach
- Infrastructure components and their roles
"""

from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator, HttpUrl

from .base import BaseEvidence


class SegmentationStrategy(str, Enum):
    """How network segmentation is implemented"""
    FULL_ISOLATION = "full_isolation"  # Complete physical/logical separation
    VLAN_BASED = "vlan_based"  # Virtual LANs
    VPC_BASED = "vpc_based"  # Cloud VPCs/VNets
    SUBNET_BASED = "subnet_based"  # Subnet segregation
    MICRO_SEGMENTATION = "micro_segmentation"  # Per-workload segmentation
    ZERO_TRUST = "zero_trust"  # Zero trust architecture
    FLAT_NETWORK = "flat_network"  # No segmentation (not recommended)


class SecurityZone(str, Enum):
    """Types of security zones in architecture"""
    PUBLIC_DMZ = "public_dmz"  # Internet-facing zone
    APPLICATION_TIER = "application_tier"  # Application servers
    DATABASE_TIER = "database_tier"  # Database servers
    MANAGEMENT_ZONE = "management_zone"  # Admin/management systems
    CUSTOMER_ZONE = "customer_zone"  # Customer-specific environments
    MONITORING_ZONE = "monitoring_zone"  # Security monitoring systems
    BACKUP_ZONE = "backup_zone"  # Backup infrastructure


class MultiTenancyModel(str, Enum):
    """How multiple customers are isolated"""
    DEDICATED_INFRASTRUCTURE = "dedicated_infrastructure"  # Each customer gets own infrastructure
    SHARED_INFRASTRUCTURE_LOGICAL_ISOLATION = "shared_logical_isolation"  # Shared infra, logical separation
    CONTAINERIZED = "containerized"  # Container-based isolation
    DATABASE_SCHEMAS = "database_schemas"  # Same DB, different schemas
    HYBRID = "hybrid"  # Mix of approaches
    SINGLE_TENANT = "single_tenant"  # Only one customer


class CloudProvider(str, Enum):
    """Cloud infrastructure provider"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA_CLOUD = "alibaba_cloud"
    ORACLE_CLOUD = "oracle_cloud"
    ON_PREMISES = "on_premises"
    HYBRID_CLOUD = "hybrid_cloud"
    MULTI_CLOUD = "multi_cloud"


class InfrastructureComponent(BaseEvidence):
    """A component in the system architecture"""

    component_name: str = Field(
        description="Name/identifier of this component (e.g., 'API Gateway', 'PostgreSQL Database')",
        min_length=2,
        max_length=200
    )

    component_type: str = Field(
        description="Type of component (e.g., 'load_balancer', 'database', 'api_server')",
        min_length=2,
        max_length=100
    )

    security_zone: SecurityZone = Field(
        description="Which security zone this component resides in"
    )

    publicly_accessible: bool = Field(
        description="Whether this component is accessible from the internet"
    )

    data_classification: str = Field(
        description="Highest sensitivity of data handled (e.g., 'highly_sensitive', 'internal', 'public')",
        max_length=50
    )

    has_customer_data: bool = Field(
        description="Whether this component stores or processes customer data"
    )


class NetworkSegment(BaseEvidence):
    """A network segment with defined security boundaries"""

    segment_name: str = Field(
        description="Name of this network segment (e.g., 'Production VPC', 'DMZ Subnet')",
        min_length=2,
        max_length=200
    )

    security_zone: SecurityZone = Field(
        description="Security zone classification for this segment"
    )

    allowed_inbound_sources: List[str] = Field(
        description="What sources can connect to this segment (e.g., ['public_internet'], ['management_zone'])",
        min_length=1
    )

    allowed_outbound_destinations: List[str] = Field(
        description="What destinations this segment can connect to",
        min_length=1
    )

    firewall_rules_enforced: bool = Field(
        description="Whether firewall/security group rules restrict traffic"
    )

    default_deny_policy: bool = Field(
        description="Whether default policy is deny-all (requires explicit allows)"
    )


class ArchitectureEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Architecture & Segmentation

    ASSURE requires:
    1. Comprehensive architecture diagram available
    2. Clear network segmentation implemented
    3. Multi-tenancy isolation documented
    4. Security zones defined with boundaries
    5. Default-deny firewall policies
    6. Separation between production and non-production environments
    """

    evidence_type: str = Field(
        default="assure_001_architecture",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Architecture documentation
    architecture_diagram_available: bool = Field(
        description="Whether a comprehensive architecture diagram exists"
    )

    architecture_diagram_url: Optional[HttpUrl] = Field(
        default=None,
        description="URL or reference to architecture diagram"
    )

    architecture_last_updated: Optional[str] = Field(
        default=None,
        description="When architecture documentation was last updated (e.g., '2024-Q1', 'January 2024')",
        max_length=50
    )

    # Segmentation strategy
    segmentation_strategy: SegmentationStrategy = Field(
        description="Primary network segmentation approach"
    )

    segmentation_description: str = Field(
        description="Detailed description of how network segmentation is implemented",
        min_length=20,
        max_length=2000
    )

    # Multi-tenancy
    multi_tenancy_model: MultiTenancyModel = Field(
        description="How multiple customers are isolated from each other"
    )

    tenant_isolation_tested: bool = Field(
        default=False,
        description="Whether tenant isolation has been penetration tested"
    )

    # Cloud infrastructure
    primary_cloud_provider: CloudProvider = Field(
        description="Primary cloud infrastructure provider"
    )

    high_availability_configured: bool = Field(
        description="Whether architecture includes HA/redundancy"
    )

    disaster_recovery_region: Optional[str] = Field(
        default=None,
        description="Geographic region for disaster recovery (if configured)",
        max_length=100
    )

    # Network segments
    network_segments: List[NetworkSegment] = Field(
        description="Defined network segments with security boundaries",
        min_length=1
    )

    # Infrastructure components
    infrastructure_components: List[InfrastructureComponent] = Field(
        description="Key infrastructure components in the architecture",
        min_length=1
    )

    # Security controls
    production_non_production_separated: bool = Field(
        description="Whether production and non-production environments are separated"
    )

    jump_box_required_for_admin_access: bool = Field(
        default=False,
        description="Whether bastion/jump box is required for administrative access"
    )

    network_ids_ips_deployed: bool = Field(
        default=False,
        description="Whether network-based IDS/IPS is deployed"
    )

    @field_validator("segmentation_strategy")
    @classmethod
    def validate_segmentation_sufficient(cls, v: SegmentationStrategy) -> SegmentationStrategy:
        """ASSURE requires proper network segmentation"""
        if v == SegmentationStrategy.FLAT_NETWORK:
            raise ValueError(
                "Flat network architecture detected. "
                "ASSURE requires network segmentation to isolate security zones and limit blast radius."
            )
        return v

    @field_validator("network_segments")
    @classmethod
    def validate_critical_zones_present(cls, v: List[NetworkSegment]) -> List[NetworkSegment]:
        """Validate that critical security zones are defined"""
        zones = {segment.security_zone for segment in v}

        # Critical zones that should exist
        recommended_zones = {
            SecurityZone.APPLICATION_TIER,
            SecurityZone.DATABASE_TIER
        }

        missing_zones = recommended_zones - zones

        if missing_zones:
            import logging
            missing_names = [zone.value for zone in missing_zones]
            logging.warning(
                f"Architecture is missing recommended security zones: {', '.join(missing_names)}. "
                f"ASSURE recommends separate zones for application and database tiers."
            )

        return v

    @field_validator("network_segments")
    @classmethod
    def validate_default_deny_policies(cls, v: List[NetworkSegment]) -> List[NetworkSegment]:
        """ASSURE requires default-deny firewall policies"""
        segments_without_default_deny = [
            seg for seg in v
            if not seg.default_deny_policy
        ]

        if segments_without_default_deny:
            segment_names = [seg.segment_name for seg in segments_without_default_deny]
            raise ValueError(
                f"The following network segments do not have default-deny policies: {', '.join(segment_names)}. "
                f"ASSURE requires default-deny firewall rules (explicit allow required)."
            )

        return v

    @field_validator("infrastructure_components")
    @classmethod
    def validate_customer_data_components(cls, v: List[InfrastructureComponent]) -> List[InfrastructureComponent]:
        """Components with customer data should not be publicly accessible"""
        exposed_data_components = [
            comp for comp in v
            if comp.has_customer_data and comp.publicly_accessible
        ]

        if exposed_data_components:
            comp_names = [comp.component_name for comp in exposed_data_components]
            raise ValueError(
                f"The following components contain customer data but are publicly accessible: {', '.join(comp_names)}. "
                f"ASSURE requires customer data components to be in private subnets behind application tier."
            )

        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for architecture & segmentation.

        ASSURE requirements:
        1. Architecture diagram available
        2. Network segmentation implemented (not flat network)
        3. Multi-tenancy isolation documented
        4. Production/non-production environments separated
        5. Default-deny firewall policies on all segments
        6. Database tier isolated from public internet
        7. Application and database tiers in separate zones
        8. Jump box/bastion required for admin access
        9. High availability configured
        10. Tenant isolation penetration tested

        Total: 10 requirements (8 mandatory, 2 recommended)
        """
        return 10

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Requirement 1: Architecture diagram available
        if self.architecture_diagram_available:
            passed += 1

        # Requirement 2: Network segmentation implemented
        if self.segmentation_strategy != SegmentationStrategy.FLAT_NETWORK:
            passed += 1

        # Requirement 3: Multi-tenancy isolation documented
        if self.multi_tenancy_model != MultiTenancyModel.DATABASE_SCHEMAS:
            # Database schemas alone are insufficient for strong isolation
            passed += 1

        # Requirement 4: Production/non-production separated
        if self.production_non_production_separated:
            passed += 1

        # Requirement 5: Default-deny policies on all segments
        if all(seg.default_deny_policy for seg in self.network_segments):
            passed += 1

        # Requirement 6: Database tier isolated from public internet
        db_components = [
            comp for comp in self.infrastructure_components
            if comp.security_zone == SecurityZone.DATABASE_TIER
        ]
        if db_components and not any(comp.publicly_accessible for comp in db_components):
            passed += 1

        # Requirement 7: Application and database tiers in separate zones
        zones = {segment.security_zone for segment in self.network_segments}
        if SecurityZone.APPLICATION_TIER in zones and SecurityZone.DATABASE_TIER in zones:
            passed += 1

        # Requirement 8: Jump box required for admin access (recommended)
        if self.jump_box_required_for_admin_access:
            passed += 1

        # Requirement 9: High availability configured
        if self.high_availability_configured:
            passed += 1

        # Requirement 10: Tenant isolation penetration tested (recommended)
        if self.tenant_isolation_tested:
            passed += 1

        return passed
