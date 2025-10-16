# CONDUIT - Claude AI Instructions

**Last Updated:** October 16, 2025
**Repository:** grcengineering/conduit
**Status:** Phase 1 - Building 3 starter evidence schemas

## Project Overview

CONDUIT is an evidence exchange protocol for ASSURE TPRM (Third-Party Risk Management). It solves the problem of vendors answering the same security questions 50+ times by creating standardized, machine-readable evidence packages.

## Core Concepts

- **24 Evidence Types**: Based on ASSURE Core Due Diligence framework
- **LLM-Powered**: Uses Claude to transform vendor docs into structured format
- **SOC 2 Aware**: Identifies overlap with existing SOC 2 reports (gap analysis)
- **Trust Centre Ready**: Vendors publish once, customers consume automatically
- **Evidence-First**: Map from evidence types back to controls (reverse mapping)
- **Pydantic v2**: Data validation and automatic JSON schema generation

## ASSURE Framework (24 Controls)

### Control #1: Architecture & Segmentation
**Evidence Required:**
- Architectural diagram showing network segmentation
- Subprocessor list
- SBOM (Software Bill of Materials)

### Control #2: Data Mapping
**Evidence Required:**
- Attestation of data mapping exercise
- Subprocessor list
- Documented list of data types collected and purposes

### Control #3: Risk Assessment
**Evidence Required:**
- Risk assessment report (redaction acceptable)

### Control #4: Vulnerability Management ⭐ Phase 1
**Evidence Required:**
- Vulnerability scans for last 3 months (monthly minimum)
- Most recent penetration test (within 12 months)
- Bug bounty program details (if available)
- SLA compliance records (Critical: 7d, High: 30d, Medium: 90d)

### Control #5: Incident Response
**Evidence Required:**
- Evidence of incident response plan implementation
- Tooling configurations for IR
- Interview/evidence of plan activation

### Control #6: Backup Configuration
**Evidence Required:**
- Detailed backup configuration

### Control #7: BCP/DR Testing ⭐ Phase 1
**Evidence Required:**
- Evidence of most recent BCP/DR test
- Test results (pass/fail/pass with findings)
- Scope of test

### Control #8: Access Reviews
**Evidence Required:**
- Evidence of last access review
- Systems in scope

### Control #9: Production Access Controls
**Evidence Required:**
- Evidence of controls preventing persistent production access
- Just-in-time (JIT) or ephemeral access configurations

### Control #10: Network ACLs
**Evidence Required:**
- Network ACL configuration (default deny)
- Access review evidence

### Control #11: 2FA Validation
**Evidence Required:**
- Validation of 2FA mechanisms in place
- Coverage percentage

### Control #12: Encryption at Rest
**Evidence Required:**
- Company attestation of all customer data storage locations
- Evidence of encryption enabled on all locations (AES-256+)

### Control #13: Encryption in Transit
**Evidence Required:**
- TLS configuration (1.2+ required)
- Evidence that deprecated protocols are explicitly blocked (TLS 1.1, SSL, etc.)
- Qualys SSL scan or equivalent

### Control #14: Logging Configuration
**Evidence Required:**
- Logging configuration details

### Control #15: Security Alerts
**Evidence Required:**
- Evidence of security alerts being delivered

### Control #16: Branch Protections
**Evidence Required:**
- Branch protection configuration (change testing + review for release)

### Control #17: Change Control Attestation
**Evidence Required:**
- Attestation of who can overwrite controls
- Whether changes can be pushed to production in any other way

### Control #18: Checksums/FIM
**Evidence Required:**
- File Integrity Monitoring configuration
- Checksum configuration

### Control #19: CIS Scan
**Evidence Required:**
- CIS benchmark scan results

### Control #20: Hosting Verification
**Evidence Required:**
- Verification of cloud hosting provider (AWS, GCP, Azure)
- OR: Data center compliance with industry standards

### Control #21: Confidentiality Contract Terms
**Evidence Required:**
- Contract confidentiality terms applicable to risk

### Control #22: Compliance Contract Terms
**Evidence Required:**
- Contract attestation of compliance
- Agreement to maintain compliance with legal/regulatory obligations

### Control #23: SSO/MFA Requirements ⭐ Phase 1
**Evidence Required:**
- SAML or SSO support (NO PAYWALL - this is critical)
- 2FA enforcement (phishing-resistant preferred: app, hardware, device trust)
- MFA types available

### Control #24: AI Controls
**Evidence Required:**
- TBD

## Architecture Decision: Option 2 (Separate Files per Model)

### **Structure:**
```
src/conduit/models/
├── __init__.py                          # Re-exports all models
├── base.py                              # BaseEvidence shared class
├── evidence_001_architecture.py         # One file per control
├── evidence_002_data_mapping.py
├── ... (24 files total)
└── evidence_024_ai_controls.py
```

### **Why This Structure:**
- ✅ Clear organization (filename = control number)
- ✅ Small files (~100-150 lines each, easy to navigate)
- ✅ Git-friendly (no merge conflicts)
- ✅ Testing mirrors structure
- ✅ Scalable (easy to add new evidence types)
- ✅ Matches ASSURE 1-to-1 mapping

### **Import Pattern:**
```python
# Simple imports (via __init__.py re-exports):
from conduit.models import BCPDREvidence, VulnerabilityEvidence

# Or from specific file:
from conduit.models.evidence_007_bcpdr import BCPDREvidence
```

## User Context

**User**: GRC professional, NOT a developer
**Learning Mode**: Provide detailed explanations, break down complex topics
**Incremental Changes**: Small, focused changes with clear explanations
**Warnings**: Use 🔥/⚠️/🔴 for large or risky changes

## Technical Stack

- **Python 3.12+**: Modern Python with type hints
- **PDM**: Package management (NOT pip/poetry)
- **Pydantic v2**: Data validation and models (automatic JSON schema generation)
- **Anthropic Claude**: LLM for document analysis
- **Typer**: CLI framework
- **Rich**: Terminal output formatting
- **Ruff**: Linting and formatting
- **React + Vite**: UI dashboard (Phase 5)
- **Plotly**: Visualization (Phase 5)

## Development Workflow

1. **TODO.md tracking**: Update TODO.md (gitignored) for progress
2. **Small commits**: Incremental, explained changes
3. **Type hints**: Always use type hints for all functions
4. **Documentation**: Update docs when adding features
5. **Testing**: Add tests for new functionality
6. **One file per evidence type**: Keep models organized

## Phase 1 Priority (Week 1)

### **Starter Evidence Schemas (3 types):**
1. **Evidence #7 (BCP/DR Testing)** - Simple, proves the pattern works
2. **Evidence #23 (SSO/MFA)** - Medium complexity, vendor pain point
3. **Evidence #4 (Vulnerability Management)** - Complex, multi-doc, demonstrates power

### **Deliverables:**
- ✅ `base.py` with BaseEvidence class (shared fields/methods)
- ✅ `evidence_007_bcpdr.py` with full validation
- ✅ `evidence_023_sso_mfa.py` with SSO paywall detection
- ✅ `evidence_004_vulnerability.py` with nested models
- ✅ Unit tests for all 3
- ✅ Documentation (ARCHITECTURE.md, EVIDENCE_SPECS.md)

## File Naming Convention

- Evidence models: `evidence_XXX_short_name.py` (e.g., `evidence_007_bcpdr.py`)
- Test files: `test_evidence_XXX_short_name.py` (mirrors model filename)
- Control number is zero-padded (001, 002, ..., 024)

## Pydantic Best Practices

1. **Inherit from BaseEvidence**: All evidence types inherit common fields
2. **Use Enums**: For fixed choices (e.g., TestResult, MFAType)
3. **Field validators**: Use `@field_validator` for business rules (e.g., 12-month recency)
4. **Type hints**: Always use proper types (date, int, float, List, Optional)
5. **Default values**: Use Field(default=...) for optional fields
6. **Docstrings**: Clear docstrings for all classes and complex validators
7. **is_compliant() method**: Every evidence type implements ASSURE compliance check

## Commands

- `pdm install`: Install dependencies
- `pdm run conduit --help`: CLI help (Phase 3)
- `pdm run lint`: Check code quality
- `pdm run format`: Format code
- `pdm run test`: Run tests

## Key Principles

1. **Evidence-First**: Start with evidence types, map to controls
2. **LLM-Native**: Claude validates and transforms docs
3. **SOC 2 Aware**: Show overlap, identify net-new requirements
4. **Quality Levels**: Minimal/Standard/Comprehensive for each evidence type
5. **Vendor-Friendly**: Publish once, consumed by all customers

## Important Notes

- This is NOT based on STIX/TAXII (we're creating a new framework)
- Focus on 24 ASSURE evidence types
- SOC 2 gap analysis is core feature
- Trust centres should adopt CONDUIT format
- LLM extracts evidence from unstructured docs

## When Making Changes

1. Update TODO.md with progress
2. Explain WHY (not just WHAT) in commits
3. Add inline comments for complex logic
4. Update documentation
5. Consider backward compatibility
6. Keep files small and focused (one evidence type per file)

## Success Metrics

- 24 evidence schemas defined (Phase 1: 3, Phase 4: remaining 21)
- 80%+ extraction accuracy from vendor docs
- SOC 2 gap analysis working
- 3 example vendor packages (AWS, Stripe, Okta)
- Working dashboard with visualization
