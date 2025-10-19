# CONDUIT Dashboard

**Interactive visualization dashboard for vendor risk management and compliance evidence**

Static demo deployment showcasing the CONDUIT evidence extraction framework for Third-Party Risk Management (TPRM).

🔗 **Live Demo:** [https://grcengineering.github.io/conduit/](https://grcengineering.github.io/conduit/) *(GitHub Pages)*

---

## Overview

This dashboard provides an interactive visualization of vendor compliance across multiple ASSURE controls. It demonstrates the complete CONDUIT workflow from evidence extraction to compliance scoring using mock data for 3 vendors.

### Key Features

- **3 View Modes:** Vendor-Control, Supply-Chain, and Risk-Control visualizations using Plotly
- **8 Implemented Controls:** BCP/DR, Vulnerability Management, SSO/MFA, Production Access, Incident Response, Encryption (at rest & in transit), Logging
- **XML-Based Extraction:** Displays extracted evidence in XML format (matches actual backend)
- **Interactive Chatbot:** Live demo showing the complete 5-step CONDUIT workflow
- **Compliance Scoring:** Percentage-based scoring with 85%/50% thresholds
- **Mock Data:** 3 vendors (Acme SaaS, DataFlow Inc, CloudStore Pro) with realistic compliance profiles

---

## Demo Mode vs Production Backend

### This Dashboard (Demo Mode)
- **Static mock data** for 3 vendors with pre-defined compliance scores
- **Client-side only** - no API calls, deployed to GitHub Pages
- **Pre-computed examples** in the chatbot simulate the workflow
- **XML display format** matches production backend output

### Actual CONDUIT Backend
- **Real document processing** using Claude Haiku 4.5 via Anthropic API
- **XML-based extraction** with Claude outputting structured XML
- **Pydantic validation** with 26+ validated pattern types
- **8 evidence types** fully implemented (#4, #5, #7, #9, #12, #13, #14, #23)
- **Pattern-based normalization** for machine-readable evidence

---

## Technology Stack

- **React 18** with Vite for fast development
- **Plotly.js** for interactive network graph visualizations
- **Tailwind CSS** for styling
- **Framer Motion** for smooth animations
- **shadcn/ui** components for consistent UI

---

## Quick Start

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

### Build for Production

```bash
npm run build
```

### Deploy to GitHub Pages

```bash
npm run deploy
```

---

## ASSURE Controls Coverage

| Control # | Name | Status | Notes |
|-----------|------|--------|-------|
| #4 | Vulnerability Management | ✅ Implemented | Scans + pentest validation |
| #5 | Incident Response | ✅ Implemented | IR plan testing + SLA validation |
| #7 | BCP/DR Testing | ✅ Implemented | Annual test requirement |
| #9 | Production Access | ✅ Implemented | JIT access + MFA validation |
| #12 | Encryption at Rest | ✅ Implemented | Database, file, object, backup encryption |
| #13 | Encryption in Transit | ✅ Implemented | TLS 1.2+, Qualys SSL Labs grade |
| #14 | Logging Configuration | ✅ Implemented | Retention, centralization, immutability |
| #23 | SSO/MFA Requirements | ✅ Implemented | Phishing-resistant MFA required |
| #1-3, #6, #8, #10-11, #15-22, #24 | Other controls | 🔄 Future work | 16 additional controls planned |

---

## Project Structure

```
dashboard/
├── src/
│   ├── components/          # React components
│   │   ├── ui/             # shadcn/ui base components
│   │   ├── VendorDialog.jsx      # Vendor details modal (shows XML)
│   │   ├── ActionCard.jsx        # Evidence action buttons (XML/JSON download)
│   │   ├── DemoChatbot.jsx       # Interactive demo workflow
│   │   ├── ComplianceGraph.jsx   # Plotly network visualization
│   │   └── ...
│   ├── data/
│   │   ├── mockData.js          # 3 vendors × 8 controls mock evidence
│   │   └── demoExamples.js      # Pre-computed chatbot examples
│   ├── App.jsx              # Main application with demo banner
│   └── main.jsx
├── public/                  # Static assets
└── package.json
```

---

## Mock Data Structure

Each vendor has:
- **8 implemented controls** with compliance scores
- **Requirements** with pass/fail details
- **Risks** identified during assessment
- **Source documents** and extraction confidence
- **SOC 2 overlap** percentage
- **Structured data** in Pydantic-compatible format

### Compliance Thresholds
- **Compliant:** ≥85% requirements passed
- **Partially Compliant:** 50-84% passed
- **Non-Compliant:** <50% passed

---

## XML Extraction Format

The dashboard displays evidence in XML format matching the actual CONDUIT backend:

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

Users can:
- **View Extracted XML** in VendorDialog for each control
- **Download XML** for complete vendor evidence package
- **Download JSON** as fallback format (legacy)

---

## Integration with Main CONDUIT Framework

To integrate this dashboard with the actual CONDUIT backend:

1. **Add API endpoints** to serve vendor evidence data
2. **Replace mockData.js** with API calls to `/api/vendors` and `/api/controls`
3. **Connect chatbot** to real extraction endpoint at `/api/extract`
4. **Add authentication** using existing GAS/Okta integration
5. **Enable real-time updates** via WebSocket for live extraction progress

See main CONDUIT repository for backend integration details.

---

## Development Notes

- Built with React 18 + Vite for fast HMR
- Uses Tailwind CSS for utility-first styling
- Plotly.js for interactive network graphs
- Framer Motion for smooth animations
- Static deployment optimized for GitHub Pages

---

## License

Part of the CONDUIT project. See main repository for license details.

---

**Questions?** Open an issue in the main CONDUIT repository.
