# CONDUIT Dashboard - Claude Instructions

**Last Updated:** October 19, 2025
**Status:** Production-ready demo with 8 implemented ASSURE controls

---

## Essential Context

### Project Purpose
Interactive React dashboard for visualizing vendor compliance across ASSURE controls. This is a **static demo deployment** that showcases the CONDUIT evidence extraction framework using mock data.

### Key Distinction: Demo vs Production

**This Dashboard (Demo):**
- Static mock data for 3 vendors
- Client-side only, deployed to GitHub Pages
- Pre-computed examples in chatbot
- No real API calls or database

**Actual CONDUIT Backend:**
- Real document processing with Claude Haiku 4.5
- XML-based extraction with Pydantic validation
- 8 evidence types fully implemented
- Pattern-based normalization (26+ patterns)

---

## Architecture Overview

### Technology Stack
- **React 18** with Vite (fast HMR)
- **Plotly.js** for network graph visualizations
- **Tailwind CSS** for styling
- **Framer Motion** for animations
- **shadcn/ui** for UI components

### Key Files and Their Purpose

#### Core Application
- **src/App.jsx** - Main application with demo banner and 3 view modes
- **src/main.jsx** - React entry point
- **src/App.css** - Global styles

#### Data Layer
- **src/data/mockData.js** - Mock evidence for 3 vendors × 8 controls (~1,500 lines)
- **src/data/demoExamples.js** - Pre-computed chatbot examples with XML documentation

#### Components
- **src/components/VendorDialog.jsx** - Vendor details modal, displays XML extraction
- **src/components/ActionCard.jsx** - Evidence action buttons (XML/JSON download)
- **src/components/DemoChatbot.jsx** - Interactive 5-step workflow demo
- **src/components/ComplianceGraph.jsx** - Plotly network visualization
- **src/components/VendorCard.jsx** - Vendor summary cards
- **src/components/StatsCard.jsx** - Dashboard statistics
- **src/components/ControlDialog.jsx** - Control details modal
- **src/components/RiskDialog.jsx** - Risk details modal
- **src/components/ChatMessage.jsx** - Chatbot message component
- **src/components/ExampleButtons.jsx** - Demo example selector
- **src/components/StepProgress.jsx** - Workflow progress indicator
- **src/components/EdgeLegend.jsx** - Graph legend component

#### UI Components (shadcn/ui)
- **src/components/ui/** - Reusable UI primitives (button, card, dialog, tabs, badge)

---

## Mock Data Structure

### Vendor Structure
Each vendor in [mockData.js](src/data/mockData.js) has:
```javascript
{
  id: 'vendor_1',
  name: 'Acme SaaS',
  criticality: 'high',
  riskScore: 0.35,
  subprocessors: ['AWS', 'SendGrid', 'Stripe'],
  controls: [ /* 8 control objects */ ]
}
```

### Control Structure
Each control has:
```javascript
{
  id: 9,
  name: 'Production Access Controls',
  passed: 4,
  total: 6,
  percentage: 66.7,
  status: 'partially_compliant',
  requirements: [ /* pass/fail details */ ],
  risks: [ /* identified risks */ ],
  source_document: 'acme_security_policy.pdf',
  extraction_confidence: 0.85,
  soc2_overlap: 90,
  structuredData: { /* Pydantic-compatible structure */ }
}
```

### Compliance Thresholds
- **Compliant:** ≥85% requirements passed
- **Partially Compliant:** 50-84% passed
- **Non-Compliant:** <50% passed

---

## Implemented ASSURE Controls

| Control # | Name | File Reference |
|-----------|------|----------------|
| #4 | Vulnerability Management | mockData.js lines 85-145 |
| #5 | Incident Response | mockData.js lines 408-480 |
| #7 | BCP/DR Testing | mockData.js lines 42-84 |
| #9 | Production Access | mockData.js lines 180-240 |
| #12 | Encryption at Rest | mockData.js lines 241-341 |
| #13 | Encryption in Transit | mockData.js lines 342-407 |
| #14 | Logging Configuration | mockData.js lines 481-541 |
| #23 | SSO/MFA Requirements | mockData.js lines 146-179 |

**Total:** 8 of 24 ASSURE controls implemented (16 remaining)

---

## XML Extraction Format

### Display in VendorDialog
The dashboard displays extracted evidence in XML format matching the actual backend:

**Component:** [VendorDialog.jsx:29-71](src/components/VendorDialog.jsx#L29-L71)

The `convertToXML()` function transforms Pydantic structures to XML:
```javascript
convertToXML(control.structuredData)
// Returns formatted XML with proper indentation
```

**Example Output:**
```xml
<assure_009_production_access>
  <access_method>bastion</access_method>
  <default_access>none</default_access>
  <mfa_required_for_privileged>true</mfa_required_for_privileged>
  <max_session_duration>4_hours</max_session_duration>
  <persistent_access_allowed>false</persistent_access_allowed>
  <privileged_accounts_segregated>true</privileged_accounts_segregated>
</assure_009_production_access>
```

### Download in ActionCard
**Component:** [ActionCard.jsx:60-88](src/components/ActionCard.jsx#L60-L88)

The `handleDownloadXML()` function creates a complete vendor evidence package with:
- XML declaration
- Vendor metadata (name, ID)
- All controls' structured data in XML format
- Proper indentation and formatting

Users can download:
1. **XML** (primary) - Complete evidence package
2. **JSON** (secondary) - Legacy fallback format

---

## Demo Mode Features

### Demo Banner (App.jsx)
**Location:** [App.jsx:188-221](src/App.jsx#L188-L221)

Prominent banner at top explaining:
- Static mock data (3 vendors, 8 controls)
- XML-based extraction with Claude Haiku 4.5
- Pattern-based validation
- Link to interactive chatbot demo

### Chatbot Info Banner (DemoChatbot.jsx)
**Location:** [DemoChatbot.jsx:128-141](src/components/DemoChatbot.jsx#L128-L141)

Info banner clarifying:
- Pre-computed examples (not real API calls)
- Actual backend uses Claude Haiku 4.5
- XML format extraction
- Pydantic schema validation

---

## Development Workflow

### Local Development
```bash
npm install       # Install dependencies
npm run dev       # Start dev server at localhost:5173
```

### Production Build
```bash
npm run build     # Build for production
npm run preview   # Preview production build
```

### GitHub Pages Deployment
```bash
npm run deploy    # Deploy to GitHub Pages
```

**Live Demo:** https://grcengineering.github.io/conduit/

---

## Integration with Backend (Future)

To connect this dashboard to the actual CONDUIT backend:

1. **API Endpoints** - Create REST API for:
   - `GET /api/vendors` - List vendors with compliance scores
   - `GET /api/vendors/:id` - Vendor details with all controls
   - `POST /api/extract` - Real-time evidence extraction
   - `GET /api/controls` - ASSURE controls metadata

2. **Replace Mock Data** - Swap [mockData.js](src/data/mockData.js) with API calls

3. **Authentication** - Add auth layer using GAS/Okta integration

4. **Real-time Updates** - WebSocket for live extraction progress

5. **File Upload** - Enable document upload in chatbot

See main CONDUIT repository for backend integration guide.

---

## Important Notes

### When Making Changes

**ALWAYS update these files together:**
1. [mockData.js](src/data/mockData.js) - If adding/modifying evidence
2. [README.md](README.md) - Document new features/capabilities
3. [CLAUDE.md](CLAUDE.md) - Update architecture context (this file)

### Compliance Profile Guidelines

When adding new evidence to mockData.js:
- **Acme SaaS:** Partial compliance (60-75%) - realistic startup
- **DataFlow Inc:** Good compliance (75-87%) - mid-market company
- **CloudStore Pro:** Perfect compliance (100%) - enterprise security leader

### XML Format Requirements

When displaying XML:
- Use `evidence_type` as root element (e.g., `<assure_009_production_access>`)
- Match actual Pydantic field names exactly
- Support nested objects and arrays
- Maintain consistent indentation (2 spaces)

### Demo Mode Banners

Always maintain clear distinction between:
- **Demo Mode** (this dashboard) - Static mock data
- **Production Backend** (CONDUIT framework) - Real extraction

---

## File Size Considerations

**Large Files (excluded from context):**
- [mockData.js](src/data/mockData.js) - ~1,500 lines of mock evidence
- [demoExamples.js](src/data/demoExamples.js) - ~650 lines of pre-computed examples

When modifying these files:
1. Use Read tool to view specific sections
2. Edit incrementally with unique context strings
3. Test thoroughly after large additions

---

## Questions?

Refer to:
- **Main README:** [README.md](README.md) - Quick start and overview
- **CONDUIT Backend:** Main repository for integration guide
- **Architecture Docs:** This file for technical context
