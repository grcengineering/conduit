# Dashboard Integration Guide

**Last Updated:** October 16, 2025
**Status:** Phase 2 - Simplified Percentage-Based Approach

## Overview

This guide explains how CONDUIT Pydantic evidence models integrate with React dashboards using a **simplified percentage-based compliance calculation** instead of complex 0.0-1.0 "strength" scoring.

**Key Principle:** Transparent pass/fail counting replaces opaque strength scores.

---

## Core Concept: Percentage-Based Compliance

### The Formula

```python
compliance_percentage = (passed_requirements / total_requirements) * 100
```

**Example:**
- Control has 8 sub-requirements
- 6 pass validation
- Compliance = 6/8 = 75%

### Two Levels of Aggregation

#### 1. **Main Control Level (Vendor Overview)**

**For a single vendor across all 24 ASSURE controls:**

```python
# How many controls passed out of 24?
vendor_compliance = (passed_controls / 24) * 100

# Example: Vendor passes 18 out of 24 controls
# vendor_compliance = 18/24 = 75%
```

#### 2. **Sub-Control Level (Per-Control Granularity)**

**For a specific control's sub-requirements:**

```python
# How many sub-requirements passed?
control_compliance = (passed_requirements / total_requirements) * 100

# Example: Control #4 (Vulnerability) has 4 requirements, 3 pass
# control_compliance = 3/4 = 75%
```

---

## Pydantic Models: New Methods

All evidence types now implement three key methods (inherited from `BaseEvidence`):

### 1. `get_total_requirements() -> int`

Returns the total number of sub-requirements for this control.

**Example (BCP/DR):**
```python
def get_total_requirements(self) -> int:
    """BCP/DR has 3 requirements"""
    return 3  # test recency, test result, scope documented
```

### 2. `get_passed_requirements() -> int`

Counts how many sub-requirements pass validation.

**Example (BCP/DR):**
```python
def get_passed_requirements(self) -> int:
    passed = 0

    # Requirement 1: Test within 12 months
    if self.test_date >= (date.today() - timedelta(days=365)):
        passed += 1

    # Requirement 2: Test passed
    if self.test_result in [TestResult.PASS, TestResult.PASS_WITH_FINDINGS]:
        passed += 1

    # Requirement 3: Scope documented
    if self.scope and len(self.scope.strip()) > 0:
        passed += 1

    return passed  # Returns 0-3
```

### 3. `get_compliance_percentage() -> float`

Auto-calculated percentage (already implemented in `BaseEvidence`).

**Example:**
```python
def get_compliance_percentage(self) -> float:
    """Returns (passed/total) * 100"""
    total = self.get_total_requirements()
    if total == 0:
        return 0.0
    passed = self.get_passed_requirements()
    return (passed / total) * 100.0
```

### 4. `get_compliance_status() -> str`

Auto-calculated status based on percentage thresholds.

**Thresholds:**
- `compliant`: ≥85%
- `partially_compliant`: 50-84%
- `non_compliant`: <50%

```python
def get_compliance_status(self) -> str:
    percentage = self.get_compliance_percentage()
    if percentage >= 85:
        return "compliant"
    elif percentage >= 50:
        return "partially_compliant"
    else:
        return "non_compliant"
```

---

## Evidence Type Requirement Counts

| Control | Evidence Type | Total Requirements | Description |
|---------|---------------|-------------------|-------------|
| #4 | Vulnerability Management | 4 | Monthly scans, pentest, SLA, remediation |
| #7 | BCP/DR Testing | 3 | Test recency, test result, scope |
| #23 | SSO/MFA | 4 | SSO support, no paywall, MFA, phishing-resistant |

---

## JSON Export Format

### Old Format (Complex Strength)

```json
{
  "vendor_name": "Acme Corp",
  "controls": [
    {
      "id": 7,
      "strength": 0.85,  // ❌ What is 0.85?
      "status": "compliant"
    }
  ]
}
```

### New Format (Percentage-Based)

```json
{
  "vendor_name": "Acme Corp",
  "controls": [
    {
      "id": 7,
      "passed": 2,              // ✅ 2 requirements passed
      "total": 3,               // ✅ Out of 3 total
      "percentage": 66.7,       // ✅ 2/3 = 66.7%
      "status": "partially_compliant"  // ✅ Auto-calculated
    }
  ]
}
```

### Exporting from Pydantic Models

```python
from conduit.models import BCPDREvidence

# Create evidence
evidence = BCPDREvidence(
    vendor_name="Acme Corp",
    evidence_date="2025-10-16",
    test_date="2025-01-15",
    test_result="pass",
    test_type="full_failover",
    scope="Production database",
    extraction_confidence=0.95
)

# Export for dashboard
dashboard_data = {
    "id": 7,
    "passed": evidence.get_passed_requirements(),
    "total": evidence.get_total_requirements(),
    "percentage": evidence.get_compliance_percentage(),
    "status": evidence.get_compliance_status()
}

# Result: {"id": 7, "passed": 3, "total": 3, "percentage": 100.0, "status": "compliant"}
```

---

## Dashboard 1: Single-Vendor Control View

**Purpose:** Show detailed compliance for one vendor across 24 controls.

### Data Structure (TypeScript)

```typescript
interface ControlCompliance {
  id: number;                    // Control ID (1-24)
  name: string;                  // "BCP/DR Testing"
  passed: number;                // Sub-requirements passed
  total: number;                 // Total sub-requirements
  percentage: number;            // passed/total * 100
  status: "compliant" | "partially_compliant" | "non_compliant";
  machineReadable: boolean;      // Toggle for JSON view
  structuredData?: object;       // Full Pydantic JSON export
}

interface VendorCompliance {
  vendor_name: string;
  controls: ControlCompliance[];
  overall_passed: number;        // How many of 24 controls passed
  overall_percentage: number;    // overall_passed / 24 * 100
}
```

### Example

```typescript
const vendor: VendorCompliance = {
  vendor_name: "Acme Corp",
  overall_passed: 18,
  overall_percentage: 75.0,  // 18/24 = 75%
  controls: [
    {
      id: 7,
      name: "BCP/DR Testing",
      passed: 3,
      total: 3,
      percentage: 100.0,
      status: "compliant"
    },
    {
      id: 23,
      name: "SSO/MFA",
      passed: 3,
      total: 4,
      percentage: 75.0,
      status: "partially_compliant"
    }
    // ... 22 more controls
  ]
};
```

### Visual Representation

**Control Card:**
```
┌─────────────────────────────────────────┐
│ Control #7: BCP/DR Testing              │
│ ✓ 3/3 requirements passed (100%)       │
│ Status: COMPLIANT                       │
│ [View Details ▼]                        │
└─────────────────────────────────────────┘
```

**Expanded Details:**
```
Requirements:
  ✓ Test within 12 months
  ✓ Test passed or passed with findings
  ✓ Scope documented

SOC 2 Overlap: 90% (A1.3)
```

---

## Dashboard 2: Multi-Vendor Network Graph (Plotly)

**Purpose:** Visualize vendor-control relationships with compliance strength.

### Node Types

#### Vendor Nodes (Left Side)

```typescript
interface VendorNode {
  id: string;                    // "v1", "v2", etc.
  name: string;                  // "Acme Corp"
  x: number;                     // 0 (left column)
  y: number;                     // Vertical spacing
  size: number;                  // Based on overall_percentage
  color: string;                 // Based on overall_percentage
  hovertext: string;             // Vendor details
  controls_passed: number;       // How many of 24 controls passed
  controls_total: number;        // 24
  overall_percentage: number;    // controls_passed / 24 * 100
}
```

**Size Calculation:**
```typescript
const baseSize = 20;
const sizeMultiplier = 0.5;
vendorNode.size = baseSize + (overall_percentage * sizeMultiplier);
// 100% → size 70, 50% → size 45, 0% → size 20
```

**Color Mapping:**
```typescript
function getVendorColor(percentage: number): string {
  if (percentage >= 85) return "#10b981"; // Green (compliant)
  if (percentage >= 50) return "#f59e0b"; // Orange (partial)
  return "#ef4444";                        // Red (non-compliant)
}
```

#### Control Nodes (Right Side)

```typescript
interface ControlNode {
  id: string;                    // "c1", "c7", etc.
  name: string;                  // "Control #7"
  x: number;                     // 400 (right column)
  y: number;                     // Vertical spacing
  size: number;                  // Based on avg_percentage
  color: string;                 // Based on avg_percentage
  hovertext: string;             // Control details
  avg_percentage: number;        // Average across all vendors
}
```

### Edges (Vendor → Control Connections)

**Old Format (Complex):**
```typescript
{
  from: "v1",
  to: "c7",
  strength: 0.85,  // ❌ Where does 0.85 come from?
  color: "green"
}
```

**New Format (Percentage-Based):**
```typescript
interface Edge {
  from: string;                  // Vendor ID
  to: string;                    // Control ID
  passed: number;                // Sub-requirements passed
  total: number;                 // Total sub-requirements
  percentage: number;            // passed/total * 100
  color: string;                 // Based on percentage
  style: "solid" | "dashed";     // Based on percentage
}
```

**Edge Styling:**
```typescript
function getEdgeStyle(percentage: number): { color: string; style: string } {
  if (percentage >= 85) {
    return { color: "#10b981", style: "solid" };      // Green solid
  } else if (percentage >= 70) {
    return { color: "#f59e0b", style: "solid" };      // Orange solid
  } else {
    return { color: "#ef4444", style: "dashed" };     // Red dashed
  }
}
```

**Example Edge:**
```typescript
const edge: Edge = {
  from: "v1",
  to: "c7",
  passed: 2,
  total: 3,
  percentage: 66.7,
  color: "#ef4444",    // Red (< 70%)
  style: "dashed"
};
```

### Hover Text Examples

**Vendor Hover:**
```
Acme Corp
Criticality: High
Controls: 18/24 compliant (75%)
Risk Score: 15%
```

**Control Hover:**
```
BCP/DR Testing
Control #7
Criticality: High
Vendors: 5
Avg Compliance: 83%
```

**Edge Hover:**
```
Acme Corp → Control #7
2/3 requirements passed (66.7%)
Status: Partially Compliant
```

---

## Graph View Modes

### 1. Vendor-Control View

**Layout:**
```
[Vendors]          [Controls]
   v1 ──────────── c1
    │ \            │
    │  \           │
   v2 ──\─────────c7
    │    \         │
   v3 ────\───────c23
```

**Purpose:** Show which vendors meet which controls.

### 2. Supply-Chain View

**Layout:**
```
       v1 (Primary)
      / │ \
    v3  v4  v5 (Subprocessors)
```

**Purpose:** Show vendor dependencies (subprocessors).

### 3. Risk-Control View

**Layout:** Group vendors by risk score, connect to shared controls.

**Purpose:** Identify high-risk vendors and common control gaps.

---

## Status Thresholds

### Why These Numbers?

| Threshold | Status | Rationale |
|-----------|--------|-----------|
| ≥85% | Compliant | Most sub-requirements met (e.g., 3/4 or 5/6) |
| 50-84% | Partially Compliant | Half or more met, but gaps exist |
| <50% | Non-Compliant | Majority of requirements failing |

**Edge Coloring Alignment:**
- Green solid: ≥85% (compliant)
- Orange solid: 70-84% (borderline partial)
- Red dashed: <70% (non-compliant/weak partial)

---

## Example: Complete Vendor Export

```python
from conduit.models import BCPDREvidence, SSOMMFAEvidence, VulnerabilityEvidence

# Create evidence for 3 controls
bcpdr = BCPDREvidence(...)
sso = SSOMMFAEvidence(...)
vuln = VulnerabilityEvidence(...)

# Export for dashboard
vendor_data = {
    "vendor_name": "Acme Corp",
    "controls": [
        {
            "id": 4,
            "name": "Vulnerability Management",
            "passed": vuln.get_passed_requirements(),
            "total": vuln.get_total_requirements(),
            "percentage": vuln.get_compliance_percentage(),
            "status": vuln.get_compliance_status(),
            "machineReadable": True,
            "structuredData": vuln.model_dump()
        },
        {
            "id": 7,
            "name": "BCP/DR Testing",
            "passed": bcpdr.get_passed_requirements(),
            "total": bcpdr.get_total_requirements(),
            "percentage": bcpdr.get_compliance_percentage(),
            "status": bcpdr.get_compliance_status(),
            "machineReadable": True,
            "structuredData": bcpdr.model_dump()
        },
        {
            "id": 23,
            "name": "SSO/MFA",
            "passed": sso.get_passed_requirements(),
            "total": sso.get_total_requirements(),
            "percentage": sso.get_compliance_percentage(),
            "status": sso.get_compliance_status(),
            "machineReadable": True,
            "structuredData": sso.model_dump()
        }
    ],
    "overall_passed": sum(1 for c in [vuln, bcpdr, sso] if c.is_compliant()),
    "overall_percentage": (sum(1 for c in [vuln, bcpdr, sso] if c.is_compliant()) / 24) * 100
}
```

**Result:**
```json
{
  "vendor_name": "Acme Corp",
  "overall_passed": 2,
  "overall_percentage": 8.33,
  "controls": [
    {
      "id": 4,
      "name": "Vulnerability Management",
      "passed": 3,
      "total": 4,
      "percentage": 75.0,
      "status": "partially_compliant"
    },
    {
      "id": 7,
      "name": "BCP/DR Testing",
      "passed": 3,
      "total": 3,
      "percentage": 100.0,
      "status": "compliant"
    },
    {
      "id": 23,
      "name": "SSO/MFA",
      "passed": 3,
      "total": 4,
      "percentage": 75.0,
      "status": "partially_compliant"
    }
  ]
}
```

---

## Benefits of Percentage-Based Approach

✅ **Transparent:** "6 out of 8 passed" is immediately clear
✅ **Auditable:** Can drill down to see which requirements failed
✅ **Simple:** No mysterious 0.0-1.0 calculations
✅ **Vendor-Friendly:** Clear gap analysis
✅ **SOC 2 Aware:** Can show "12/18 covered by SOC 2, 6/18 net-new"
✅ **Dashboard-Ready:** Percentage maps directly to colors/sizes

---

## STIX Visualization Learnings

**What We Learned:**
- STIX uses uniform edge weights (no complex scoring)
- vis.js for browser-based graph rendering
- 100% client-side processing for security
- Focus on interactivity over complex calculations

**What We're Keeping:**
- Plotly + React tech stack (already chosen)
- Percentage-based simplicity (inspired by STIX's uniform approach)
- Edge coloring based on clear thresholds
- Hover details for transparency

**What We're Not Doing:**
- Complex 0.0-1.0 strength calculations
- Weighted scoring algorithms
- Opaque aggregation formulas

---

## Next Steps (Phase 5)

1. ✅ **Phase 2 Complete:** Pydantic models export percentage data
2. **Phase 5a:** Update Dashboard 1 TSX to use percentage format
3. **Phase 5b:** Update Dashboard 2 TSX to use percentage-based edge coloring
4. **Phase 5c:** Add hover text with "X/Y requirements passed (Z%)"
5. **Phase 5d:** Test with real CONDUIT data from Phase 3 CLI

---

## Quick Reference

### Pydantic Export Snippet

```python
control_data = {
    "id": evidence.evidence_type,
    "passed": evidence.get_passed_requirements(),
    "total": evidence.get_total_requirements(),
    "percentage": evidence.get_compliance_percentage(),
    "status": evidence.get_compliance_status()
}
```

### TypeScript Edge Styling

```typescript
const getEdgeColor = (percentage: number): string => {
  return percentage >= 85 ? "#10b981" :
         percentage >= 70 ? "#f59e0b" : "#ef4444";
};

const getEdgeStyle = (percentage: number): string => {
  return percentage >= 70 ? "solid" : "dashed";
};
```

### Status Badge Colors

```css
.compliant { background: #10b981; }         /* Green */
.partially_compliant { background: #f59e0b; } /* Orange */
.non_compliant { background: #ef4444; }     /* Red */
```

---

**End of Dashboard Integration Guide**
