# CONDUIT Interactive Dashboard

**Live Demo:** [https://grcengineering.github.io/conduit/](https://grcengineering.github.io/conduit/) *(when deployed)*

## Overview

This dashboard demonstrates **CONDUIT's percentage-based compliance visualization** using Plotly.js and vanilla JavaScript. It showcases how vendors' ASSURE compliance can be visualized transparently using simple pass/fail counting instead of opaque 0.0-1.0 "strength" scores.

## Features

### Three View Modes

1. **Vendor-Control View** (Default)
   - Vendors on left, controls on right
   - Edge colors indicate compliance percentage
   - Click nodes for detailed requirements breakdown

2. **Supply-Chain View**
   - Circular vendor layout
   - Shows subprocessor relationships
   - Useful for understanding vendor dependencies

3. **Risk-Control View**
   - Risks on left, controls on right
   - Shows which controls mitigate which risks
   - Edge colors indicate risk severity

### Interactive Features

- **Click any node** to see detailed information
- **View requirements** for each control (passed/failed)
- **See risks** identified during assessment
- **Inspect raw JSON** from Pydantic models
- **Source document** references for audit trail

### Mock Data

The dashboard uses **realistic mock data**:
- **3 vendors:** Acme SaaS (66% compliant), DataFlow Inc (53% compliant), CloudStore Pro (100% compliant)
- **3 controls:** BCP/DR Testing, SSO/MFA, Vulnerability Management
- **Realistic failures:** Old pentests, SSO paywalls, missing DR tests

## Technology Stack

- **Plotly.js** (v2.27.0) - Graph visualization
- **Tailwind CSS** (v3.x) - Styling via CDN
- **Vanilla JavaScript** - No build step required
- **GitHub Pages** - Free static hosting

## Local Development

### Option 1: Python HTTP Server

```bash
# From the conduit root directory
cd dashboard
python3 -m http.server 8000

# Open http://localhost:8000
```

### Option 2: Live Server (VS Code)

1. Install "Live Server" VS Code extension
2. Right-click `index.html` → "Open with Live Server"

### Option 3: Direct File Open

Simply open `index.html` in your browser (may have CORS issues with some browsers).

## File Structure

```
dashboard/
├── index.html        # Main HTML page (~370 lines)
├── app.js            # Plotly visualization logic (~650 lines)
├── mock-data.js      # Mock CONDUIT evidence data (~550 lines)
├── styles.css        # Custom CSS (~150 lines)
└── README.md         # This file
```

**Total:** ~1720 lines of code

## Data Format

The mock data uses **CONDUIT's percentage-based format**:

```javascript
{
  id: 7,
  name: 'BCP/DR Testing',
  passed: 2,              // 2 requirements passed
  total: 3,               // Out of 3 total
  percentage: 66.7,       // 2/3 = 66.7%
  status: 'partially_compliant',
  requirements: [
    { name: 'Test within 12 months', passed: true },
    { name: 'Test passed', passed: false },
    { name: 'Scope documented', passed: true }
  ],
  risks: ['Service disruption if DR fails'],
  source_document: 'acme_soc2_report.pdf, page 45',
  structuredData: { /* Full Pydantic JSON */ }
}
```

## Edge Coloring Rules

| Percentage | Color | Style | Status |
|-----------|-------|-------|--------|
| ≥85% | Green | Solid | Compliant |
| 70-84% | Orange | Solid | Partially Compliant |
| <70% | Red | Dashed | Non-Compliant |

## Deployment to GitHub Pages

### Option 1: GitHub Settings

1. Go to repo Settings → Pages
2. Source: `main` branch, `/dashboard` folder
3. Save
4. Wait 1-2 minutes for deployment
5. Access at `https://grcengineering.github.io/conduit/`

### Option 2: Manual Deployment

```bash
# Create gh-pages branch
git checkout --orphan gh-pages
git reset --hard
git commit --allow-empty -m "Initial gh-pages"
git push origin gh-pages

# Copy dashboard files to gh-pages
git checkout main
git subtree push --prefix dashboard origin gh-pages
```

## Customization

### Adding New Vendors

Edit `mock-data.js`:

```javascript
mockEvidence.vendors.push({
  id: 'v4',
  name: 'NewVendor Corp',
  criticality: 'medium',
  riskScore: 0.25,
  subprocessors: [],
  controls: [ /* ... */ ]
});
```

### Adding New Controls

1. Add control to `mockEvidence.controls`
2. Add evidence to vendor's `controls` array
3. Update `controlIds` in `renderVendorControlView()` (app.js line ~225)

### Changing Colors

Edit color constants in `app.js`:
- `getEdgeColor()` - Edge colors
- `getVendorNodeColor()` - Vendor node colors
- `getControlNodeColor()` - Control node colors

## Browser Compatibility

- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+
- ⚠️ IE 11 (not supported)

## Performance

- **Initial load:** <1 second
- **Graph render:** <100ms
- **Click response:** Instant
- **No backend calls:** Everything runs client-side

## Known Limitations

1. Mock data only (not connected to real Pydantic backend yet)
2. Only 3 vendors × 3 controls (full ASSURE = 24 controls)
3. No real-time updates (static data)
4. No filtering/search yet (planned)

## Future Enhancements

- [ ] Connect to real CONDUIT API
- [ ] Add control search/filter
- [ ] Export graphs as PNG/SVG
- [ ] Timeline view (historical compliance)
- [ ] Comparison mode (vendor A vs vendor B)
- [ ] Risk heatmap overlay
- [ ] Dark mode toggle

## Credits

Built with:
- [Plotly.js](https://plotly.com/javascript/)
- [Tailwind CSS](https://tailwindcss.com/)
- [ASSURE TPRM Framework](https://github.com/grcengineering/conduit)

## License

MIT - See [../LICENSE](../LICENSE)

## Questions?

Open an issue at [github.com/grcengineering/conduit/issues](https://github.com/grcengineering/conduit/issues)
