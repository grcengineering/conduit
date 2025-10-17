"""
Evidence Type #12: Encryption at Rest

ASSURE Requirement:
Vendors must encrypt all customer data at rest using industry-standard encryption
algorithms (AES-256 or equivalent). Key management must follow security best practices.

This evidence type captures:
- Encryption status for databases, file storage, and backups
- Encryption algorithm and key strength
- Key management approach (HSM, KMS, etc.)
- Certificate/compliance for encryption practices
"""

from datetime import date
from enum import Enum
from typing import List, Optional

from pydantic import Field, field_validator

from .base import BaseEvidence


class EncryptionAlgorithm(str, Enum):
    """Industry-standard encryption algorithms"""
    AES_256 = "aes_256"
    AES_128 = "aes_128"
    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"


class KeyManagementType(str, Enum):
    """Key management approaches"""
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_KMS = "gcp_kms"
    HSM = "hsm"  # Hardware Security Module
    INTERNAL_KMS = "internal_kms"
    THIRD_PARTY_KMS = "third_party_kms"


class DataStoreType(str, Enum):
    """Types of data stores that should be encrypted"""
    DATABASE = "database"
    FILE_STORAGE = "file_storage"
    BACKUPS = "backups"
    OBJECT_STORAGE = "object_storage"


class EncryptedDataStore(BaseEvidence):
    """A specific data store with encryption details"""

    store_type: DataStoreType = Field(
        description="Type of data store (database, file storage, backups, etc.)"
    )

    store_name: Optional[str] = Field(
        default=None,
        description="Name/identifier of the data store (e.g., 'PostgreSQL production DB', 'S3 customer-data bucket')"
    )

    is_encrypted: bool = Field(
        description="Whether this data store has encryption at rest enabled"
    )

    encryption_algorithm: Optional[EncryptionAlgorithm] = Field(
        default=None,
        description="Encryption algorithm used (required if is_encrypted=True)"
    )

    key_management: Optional[KeyManagementType] = Field(
        default=None,
        description="Key management system used (required if is_encrypted=True)"
    )


class EncryptionAtRestEvidence(BaseEvidence):
    """
    Evidence for ASSURE requirement: Encryption at Rest

    ASSURE requires:
    1. All customer data encrypted at rest with AES-256 or equivalent
    2. Databases encrypted
    3. File storage encrypted
    4. Backups encrypted
    5. Key management using HSM or cloud KMS
    """

    evidence_type: str = Field(
        default="assure_012_encryption_at_rest",
        frozen=True,
        description="ASSURE evidence type identifier"
    )

    # Encrypted data stores
    encrypted_stores: List[EncryptedDataStore] = Field(
        description="List of data stores with encryption details"
    )

    # Key management compliance
    key_rotation_enabled: bool = Field(
        description="Whether automatic key rotation is enabled"
    )

    key_rotation_frequency_days: Optional[int] = Field(
        default=None,
        description="Frequency of key rotation in days (if enabled)"
    )

    # Compliance certifications
    fips_140_2_compliant: bool = Field(
        default=False,
        description="Whether encryption is FIPS 140-2 compliant"
    )

    @field_validator("encrypted_stores")
    @classmethod
    def validate_critical_stores_encrypted(cls, v: List[EncryptedDataStore]) -> List[EncryptedDataStore]:
        """Validate that all critical data stores (database, file storage, backups) are encrypted."""
        if not v:
            raise ValueError("At least one encrypted data store must be documented")

        # Check for critical store types
        store_types = {store.store_type for store in v}
        critical_types = {DataStoreType.DATABASE, DataStoreType.FILE_STORAGE, DataStoreType.BACKUPS}
        missing_types = critical_types - store_types

        if missing_types:
            missing_names = [t.value for t in missing_types]
            raise ValueError(
                f"Missing encryption details for critical data stores: {', '.join(missing_names)}. "
                f"ASSURE requires encryption for databases, file storage, and backups."
            )

        # Check that all stores are actually encrypted
        unencrypted = [store for store in v if not store.is_encrypted]
        if unencrypted:
            store_names = [f"{s.store_type.value} ({s.store_name})" if s.store_name else s.store_type.value
                          for s in unencrypted]
            raise ValueError(
                f"The following data stores are NOT encrypted: {', '.join(store_names)}. "
                f"ASSURE requires all customer data to be encrypted at rest."
            )

        return v

    @field_validator("encrypted_stores")
    @classmethod
    def validate_encryption_strength(cls, v: List[EncryptedDataStore]) -> List[EncryptedDataStore]:
        """Validate that encryption algorithms meet minimum strength requirements."""
        weak_encryption = []

        for store in v:
            if store.is_encrypted and store.encryption_algorithm:
                # AES-128 is acceptable but not preferred; flag for awareness
                if store.encryption_algorithm == EncryptionAlgorithm.AES_128:
                    weak_encryption.append(store)

        if weak_encryption:
            store_names = [f"{s.store_type.value}" for s in weak_encryption]
            # This is a warning, not a hard failure - AES-128 is still acceptable
            import logging
            logging.warning(
                f"Warning: The following stores use AES-128 instead of AES-256: {', '.join(store_names)}. "
                f"Consider upgrading to AES-256 for stronger security."
            )

        return v

    def get_total_requirements(self) -> int:
        """
        Count of sub-requirements for encryption at rest.

        ASSURE requirements:
        1. Database encrypted
        2. File storage encrypted
        3. Backups encrypted
        4. Encryption algorithm is AES-256 or equivalent (checked for all 3 stores = 3 checks)
        5. Key management using HSM or cloud KMS
        6. Key rotation enabled

        Total: 8 requirements
        """
        return 8

    def get_passed_requirements(self) -> int:
        """Count how many sub-requirements passed"""
        passed = 0

        # Check each critical store type
        database_stores = [s for s in self.encrypted_stores if s.store_type == DataStoreType.DATABASE]
        file_stores = [s for s in self.encrypted_stores if s.store_type == DataStoreType.FILE_STORAGE]
        backup_stores = [s for s in self.encrypted_stores if s.store_type == DataStoreType.BACKUPS]

        # Requirement 1: Database encrypted
        if database_stores and all(s.is_encrypted for s in database_stores):
            passed += 1

        # Requirement 2: File storage encrypted
        if file_stores and all(s.is_encrypted for s in file_stores):
            passed += 1

        # Requirement 3: Backups encrypted
        if backup_stores and all(s.is_encrypted for s in backup_stores):
            passed += 1

        # Requirement 4a-c: Encryption algorithm strength (check each store type)
        for store_list in [database_stores, file_stores, backup_stores]:
            if store_list and all(
                s.encryption_algorithm in [EncryptionAlgorithm.AES_256, EncryptionAlgorithm.RSA_4096]
                for s in store_list if s.encryption_algorithm
            ):
                passed += 1

        # Requirement 5: Key management using HSM or cloud KMS
        if all(
            s.key_management in [
                KeyManagementType.AWS_KMS,
                KeyManagementType.AZURE_KEY_VAULT,
                KeyManagementType.GCP_KMS,
                KeyManagementType.HSM,
            ]
            for s in self.encrypted_stores if s.key_management
        ):
            passed += 1

        # Requirement 6: Key rotation enabled
        if self.key_rotation_enabled:
            passed += 1

        return passed
