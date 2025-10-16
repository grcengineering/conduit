# CONDUIT

**Evidence exchange protocol for ASSURE TPRM**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![PDM](https://img.shields.io/badge/pdm-managed-blueviolet)](https://pdm.fming.dev)
[![Pydantic v2](https://img.shields.io/badge/pydantic-v2-orange)](https://docs.pydantic.dev/)

---

## The Problem with Traditional TPRM

### Today's Broken Workflow

```
Customer A sends 200-question security questionnaire
                    ↓
        Vendor fills it out (8-12 hours)
                    ↓
    Customer A manually reviews answers (4-6 hours)
                    ↓
        Customer A asks follow-up questions
                    ↓
            Vendor responds again
                    ↓
Customer A creates risk assessment in their GRC tool
```

**Then the cycle repeats for Customer B, C, D... 50+ times per year!**

### Key Problems with Traditional TPRM:

| Problem | Impact | Annual Cost (per vendor) |
|---------|--------|--------------------------|
| **Vendor Fatigue** | Same questions answered 50+ times | 400-600 hours ($40K-60K) |
| **Inconsistency** | Different answers to same question across customers | High risk exposure |
| **No Standardization** | Every customer has unique questionnaire format | Can't automate |
| **Manual Processing** | Humans read 150-page SOC 2 reports | 13 hours per review |
| **Stale Data** | Annual reviews mean 11 months of outdated info | False sense of security |
| **No Validation** | "We encrypt data" - but how? Is it current? | Trust but don't verify |
| **Evidence Hunting** | Evidence scattered across multiple documents | Hard to audit |
| **SOC 2 Gaps** | SOC 2 doesn't cover critical TPRM requirements | Missing risk areas |

### Real-World Example: Acme SaaS

```
Acme SaaS has 50 enterprise customers.

Traditional TPRM (per year):
├─ 50 security questionnaires to complete
├─ Each takes 8-12 hours (includes: research, write, review, submit)
├─ Follow-up questions: +2 hours per customer
├─ Total: 500-700 hours/year
├─ Cost: $50,000-70,000 in security team time
└─ Result: Still get inconsistent answers, customer complaints

Customer Side (each):
├─ Review 200 vendor responses manually (4-6 hours)
├─ Read SOC 2 report for gaps (3-4 hours)
├─ Create risk assessment in GRC tool (2 hours)
├─ Follow-up questions (2 hours)
├─ Total: 11-16 hours per vendor review
└─ Result: Outdated by the time assessment is done
```

## The CONDUIT Solution

**Vendors publish ONCE** in standardized CONDUIT format (24 evidence types).
**All customers consume automatically** - no more repetitive questionnaires.

### How It Works: AI-Powered Document Transformation

```
┌─────────────────────────────────────────────────────────────┐
│  📄 INPUT: Vendor Documents (Unstructured)                  │
│  ├─ SOC 2 Type II Report (150 pages)                        │
│  ├─ ISO 27001 Certificate                                   │
│  ├─ Policies & Test Results                                 │
│  └─ Security Questionnaires                                 │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  🤖 AI LAYER 1: Extraction (Claude API)                     │
│  • Multi-document synthesis                                 │
│  • Extracts 24 standardized evidence types                  │
│  • Confidence scoring (0.0-1.0)                             │
│  • Source attribution (doc + page refs)                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  🛡️ AI LAYER 2: Validation (Pydantic Schemas)               │
│  • Schema validation (required fields, types)               │
│  • Business logic checks (date recency, SLAs)               │
│  • Percentage-based compliance scoring                      │
│  • Pass/fail per requirement                                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  📊 AI LAYER 3: Gap Analysis (Claude + Domain Knowledge)    │
│  • SOC 2 overlap detection                                  │
│  • Missing evidence identification                          │
│  • Risk prioritization                                      │
│  • Remediation guidance                                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  📦 OUTPUT: CONDUIT Evidence Package (Structured)           │
│  ├─ 24 JSON evidence files (standardized)                   │
│  ├─ Compliance scores (percentage-based)                    │
│  ├─ Gap analysis report                                     │
│  ├─ Risk register with remediation steps                    │
│  └─ Interactive dashboard visualization                     │
└─────────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
  Customer A        Customer B        Customer C

  All consume the SAME validated evidence package
  No questionnaires, no vendor fatigue, no inconsistencies
```

### Example: BCP/DR Testing Evidence

```
AI extracts from vendor docs:
├─ Test Date: 2025-08-15
├─ Test Result: Partial Pass (RTO exceeded by 2h)
├─ Test Type: Partial Failover
└─ Scope: Production DB & app servers

Compliance Scoring (3 requirements):
├─ ✓ Test within 12 months: PASS (1/3)
├─ ✗ Test result successful: FAIL (1/3)  ← RTO not met
└─ ✓ Scope documented: PASS (2/3)

Compliance: 66.7% → PARTIALLY_COMPLIANT ⚠️

Risk Analysis:
• Service disruption if DR fails
• Customer availability SLA at risk (RTO: 4h target, 6h actual)

Remediation:
1. Re-test BCP/DR within 30 days
2. Investigate why RTO exceeded by 2 hours
3. Update DR runbook to meet 4-hour RTO
```

**Benefits:**
- ✅ Vendor publishes once (saves 650 hours/year)
- ✅ Standardized format (24 ASSURE evidence types)
- ✅ AI-validated with confidence scores
- ✅ SOC 2 gap analysis built-in
- ✅ Percentage-based compliance (transparent metrics)

---

## CONDUIT vs Traditional TPRM: Side-by-Side

### For Vendors (Publishers)

| Traditional TPRM | CONDUIT |
|------------------|---------|
| Fill out 50+ unique security questionnaires | Publish **1 standardized evidence package** |
| 8-12 hours per questionnaire | **1 hour** to upload docs + review AI extraction |
| Inconsistent answers across customers | **100% consistent** - same evidence for all |
| Manual copy/paste from SOC 2 report | AI **automatically extracts** from your docs |
| No validation until customer reviews | **Instant validation** via Pydantic schemas |
| Customer asks "Is this still current?" | **Timestamp + confidence score** on every field |
| Evidence scattered across email threads | **All evidence in one package** with source attribution |
| 500-700 hours/year total | **50 hours/year** (92% time savings) |
| **$50K-70K annual cost** | **~$6K annual cost** (91% cost savings) |

### For Customers (Consumers)

| Traditional TPRM | CONDUIT |
|------------------|---------|
| Send 200-question security questionnaire | **Download vendor's CONDUIT package** |
| Wait 2-4 weeks for vendor response | **Instant access** to latest evidence |
| Manually review 200 text answers | **Interactive dashboard** with pass/fail status |
| Read 150-page SOC 2 report manually | AI **pre-digested** evidence with page refs |
| Guess which SOC 2 sections apply | **Automatic SOC 2 gap analysis** |
| "They say they encrypt data" (trust?) | **Exact evidence**: "AES-256, soc2_report.pdf p.34" |
| Create risk assessment from scratch | **Auto-generated risk register** with remediation steps |
| Compliance status: ❓ Unknown | **Compliance score: 66.7%** (2/3 requirements passed) |
| Annual review (stale data 11 months/year) | **Continuous monitoring** with expiry alerts |
| 11-16 hours per vendor review | **30 minutes** per vendor (97% time savings) |
| No comparison across vendors | **Standardized metrics** enable vendor comparison |

### Key Differentiators: What CONDUIT Solves

#### 1. **Standardization** (The SBOM Moment for TPRM)
```
Traditional TPRM:
└─ Every customer invents their own questionnaire format
   └─ Result: Impossible to automate, compare, or validate

CONDUIT:
└─ 24 standardized evidence types (ASSURE framework)
   └─ Result: Machine-readable, automatable, comparable across vendors
```

#### 2. **Evidence-Based (Not Survey-Based)**
```
Traditional TPRM:
└─ Customer: "Do you test BCP/DR annually?"
   └─ Vendor: "Yes" (no evidence required)
      └─ Result: Trust but don't verify

CONDUIT:
└─ CONDUIT Package requires:
   ├─ test_date: "2025-08-15"
   ├─ test_result: "partial_pass"
   ├─ source_document: "soc2_report.pdf, page 45-47"
   ├─ extraction_confidence: 0.92
   └─ Result: Verifiable, auditable evidence with source attribution
```

#### 3. **SOC 2 Gap Analysis (Built-In)**
```
Traditional TPRM:
└─ Vendor: "Here's our SOC 2 report"
   └─ Customer: Reads 150 pages, manually identifies gaps
      └─ Result: Probably misses critical ASSURE requirements

CONDUIT:
└─ CONDUIT Package includes:
   ├─ Evidence #23 (SSO/MFA): 75% compliant
   │  ├─ SOC 2 Coverage: 50%
   │  └─ Gap: "SOC 2 NEVER checks SSO paywall requirement!"
   └─ Result: Automatic gap detection with remediation guidance
```

#### 4. **Continuous Validation (Not Annual)**
```
Traditional TPRM:
└─ Annual vendor review
   └─ Data is stale 11 months of the year
      └─ Result: False sense of security

CONDUIT:
└─ Continuous monitoring:
   ├─ Vendor publishes updated package quarterly
   ├─ Automated alerts: "Pentest expires in 30 days"
   ├─ Change detection: "MFA compliance dropped from 75% → 50%"
   └─ Result: Always current, proactive risk management
```

#### 5. **AI-Powered Intelligence (Not Manual Review)**
```
Traditional TPRM:
└─ Human analyst reads SOC 2 report for 4-6 hours
   └─ Extracts key findings manually
      └─ Result: Slow, expensive, inconsistent

CONDUIT:
└─ Claude AI reads ALL vendor documents in seconds:
   ├─ Extracts 24 evidence types automatically
   ├─ Synthesizes conflicting information
   ├─ Scores confidence (0.0-1.0) on every extraction
   ├─ Identifies risks with business impact context
   └─ Result: Instant, accurate, scalable intelligence
```

#### 6. **Percentage-Based Compliance (Not Binary)**
```
Traditional TPRM:
└─ Vendor risk rating: "Low / Medium / High"
   └─ No transparency into how rating was calculated
      └─ Result: Hard to justify to auditors, can't track improvement

CONDUIT:
└─ Percentage-based compliance per control:
   ├─ BCP/DR: 66.7% (2/3 requirements passed)
   ├─ Vulnerability Mgmt: 50.0% (2/4 requirements passed)
   ├─ SSO/MFA: 75.0% (3/4 requirements passed)
   └─ Result: Transparent, auditable, tracks improvement over time
```

### Industry Impact

**CONDUIT aims to be the "SBOM for TPRM"**

Just like Software Bill of Materials (SBOM) standardized dependency tracking:
- Before SBOM: Every company tracked dependencies differently
- After SBOM: Standard format, automated tools, industry-wide adoption

CONDUIT does the same for Third-Party Risk Management:
- Before CONDUIT: Every customer has unique questionnaire
- After CONDUIT: Standard evidence format, automated processing, vendor ecosystems

**The Vision**: Every SaaS vendor publishes CONDUIT package in their trust center. Every GRC tool auto-imports CONDUIT packages. No more questionnaires.

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
