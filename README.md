# CONDUIT

**Evidence exchange protocol for ASSURE TPRM**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PDM](https://img.shields.io/badge/pdm-managed-blueviolet)](https://pdm.fming.dev)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2-orange)](https://docs.pydantic.dev/)

---

## The Problem

Vendors answer the same security questions **50+ times** for different customers:
- ❌ Repetitive work
- ❌ Inconsistent answers
- ❌ No standardization
- ❌ Hard to validate

## The CONDUIT Solution

**Vendors publish ONCE** in standardized CONDUIT format (24 evidence types).
**All customers consume automatically** - no more repetitive questionnaires.

```
Vendor publishes 24 evidence types (CONDUIT format)
           │
           ├──→ Customer A consumes automatically
           ├──→ Customer B consumes automatically
           └──→ Customer C consumes automatically
```

**Benefits:**
- ✅ Vendor publishes once
- ✅ Standardized format (24 ASSURE evidence types)
- ✅ Machine-readable & LLM-validated
- ✅ SOC 2 gap analysis built-in

---

## 🎨 Live Demo

**[View Interactive Dashboard →](https://grcengineering.github.io/conduit/)**

Explore CONDUIT's percentage-based compliance visualization with mock vendor data. Click nodes to see detailed requirements, risks, and raw JSON output.

---

## Status

✅ **Phase 1 - Complete**
- 3 evidence schemas implemented with percentage-based compliance
- 39 unit tests passing
- Dashboard integration documentation

🚧 **Phase 5 (Accelerated) - In Development**
- Interactive Plotly dashboard
- 3 view modes: Vendor-Control, Supply-Chain, Risk-Control
- Clickable nodes with detailed drill-down

---

## ASSURE Framework (24 Evidence Types)

CONDUIT implements the ASSURE Core Due Diligence framework:

| # | Evidence Type | Complexity | Status |
|---|---------------|------------|--------|
| 1 | Architecture & Segmentation | Medium | 📋 Planned |
| 2 | Data Mapping | Low | 📋 Planned |
| 3 | Risk Assessment | Medium | 📋 Planned |
| 4 | Vulnerability Management | **High** | 🚧 **Phase 1** |
| 5 | Incident Response | Medium | 📋 Planned |
| 6 | Backup Configuration | Low | 📋 Planned |
| 7 | BCP/DR Testing | **Low** | 🚧 **Phase 1** |
| 8 | Access Reviews | Low | 📋 Planned |
| 9 | Production Access Controls | Medium | 📋 Planned |
| 10 | Network ACLs | Medium | 📋 Planned |
| 11 | 2FA Validation | Low | 📋 Planned |
| 12 | Encryption at Rest | Medium | 📋 Planned |
| 13 | Encryption in Transit | Low | 📋 Planned |
| 14 | Logging Configuration | Low | 📋 Planned |
| 15 | Security Alerts | Low | 📋 Planned |
| 16 | Branch Protections | Low | 📋 Planned |
| 17 | Change Control | Low | 📋 Planned |
| 18 | Checksums/FIM | Low | 📋 Planned |
| 19 | CIS Scan | Medium | 📋 Planned |
| 20 | Hosting Verification | Low | 📋 Planned |
| 21 | Confidentiality Contract | Medium | 📋 Planned |
| 22 | Compliance Contract | Medium | 📋 Planned |
| 23 | SSO/MFA Requirements | **Medium** | 🚧 **Phase 1** |
| 24 | AI Controls | Unknown | 📋 TBD |

---

## Architecture

CONDUIT uses **separate files per evidence type** for clear organization:

```
src/conduit/models/
├── base.py                              # Shared BaseEvidence class
├── evidence_001_architecture.py         # Control #1
├── evidence_004_vulnerability.py        # Control #4 (Phase 1)
├── evidence_007_bcpdr.py                # Control #7 (Phase 1)
├── evidence_023_sso_mfa.py              # Control #23 (Phase 1)
└── ... (24 files total)
```

**Why separate files?**
- ✅ Easy to find (filename = control number)
- ✅ Small files (~100-150 lines each)
- ✅ Git-friendly (no merge conflicts)
- ✅ Testing mirrors structure
- ✅ Scalable

---

## Quick Start (Coming Soon)

```bash
# Install
pdm install

# Transform vendor document to CONDUIT format
conduit transform vendor_soc2.pdf

# Validate CONDUIT evidence package
conduit validate evidence_package/

# Analyze SOC 2 overlap
conduit gaps evidence_package/ --soc2 vendor_soc2.pdf
```

---

## Technology Stack

- **Python 3.12+** - Modern Python with type hints
- **Pydantic v2** - Data validation & JSON schema generation
- **Anthropic Claude** - LLM for document analysis
- **PDM** - Package management
- **Typer** - CLI framework
- **Rich** - Terminal output
- **React + Vite** - Dashboard (Phase 5)
- **Plotly** - Visualization (Phase 5)

---

## Development

```bash
# Install dependencies
pdm install

# Run tests
pdm run test

# Lint code
pdm run lint

# Format code
pdm run format
```

---

## Roadmap

- **Phase 1** (Week 1): 3 starter evidence schemas + validation
- **Phase 2** (Week 2): LLM transformer with Claude API
- **Phase 3** (Week 3): CLI tool (transform, validate, gaps)
- **Phase 4** (Week 4-5): Remaining 21 evidence schemas
- **Phase 5** (Week 6-7): React dashboard with visualization
- **Phase 6** (Week 8): Examples (AWS, Stripe, Okta) + docs

---

## License

MIT

---

## Questions?

Open an issue or contact the GRC Engineering team.
