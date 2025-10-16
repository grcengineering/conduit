/**
 * CONDUIT Dashboard - Interactive Plotly Visualization
 *
 * Implements 3 view modes:
 * 1. Vendor-Control: Vendors on left, controls on right
 * 2. Supply-Chain: Circular vendor dependencies
 * 3. Risk-Control: Risks on left, controls on right
 */

let currentViewMode = 'vendor-control';

/**
 * Initialize dashboard on page load
 */
document.addEventListener('DOMContentLoaded', () => {
  updateStats();
  renderGraph();
});

/**
 * Update statistics cards
 */
function updateStats() {
  // Calculate stats
  const totalVendors = mockEvidence.vendors.length;
  const totalControls = mockEvidence.vendors[0].controls.length;

  // Calculate average compliance across all vendors
  const allCompliance = mockEvidence.vendors.map(v => parseFloat(getVendorCompliance(v)));
  const avgCompliance = (allCompliance.reduce((a, b) => a + b, 0) / allCompliance.length).toFixed(1);

  // Count total unique risks
  const allRisks = new Set();
  mockEvidence.vendors.forEach(v => {
    v.controls.forEach(c => {
      c.risks.forEach(r => allRisks.add(r));
    });
  });

  // Count high-risk vendors (risk score > 40%)
  const highRiskVendors = mockEvidence.vendors.filter(v => v.riskScore > 0.4).length;

  // Update DOM
  document.getElementById('stat-vendors').textContent = totalVendors;
  document.getElementById('stat-controls').textContent = totalControls;
  document.getElementById('stat-compliance').textContent = `${avgCompliance}%`;
  document.getElementById('stat-risks').textContent = allRisks.size;
  document.getElementById('stat-high-risk').textContent = highRiskVendors;
}

/**
 * Set view mode and re-render graph
 */
function setViewMode(mode) {
  currentViewMode = mode;

  // Update button styles
  document.getElementById('btn-vendor-control').className =
    mode === 'vendor-control'
      ? 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-blue-600 text-white'
      : 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-slate-100 text-slate-700 hover:bg-slate-200';

  document.getElementById('btn-supply-chain').className =
    mode === 'supply-chain'
      ? 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-blue-600 text-white'
      : 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-slate-100 text-slate-700 hover:bg-slate-200';

  document.getElementById('btn-risk-control').className =
    mode === 'risk-control'
      ? 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-blue-600 text-white'
      : 'px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-slate-100 text-slate-700 hover:bg-slate-200';

  renderGraph();
}

/**
 * Main graph rendering function
 */
function renderGraph() {
  // Initialize Plotly traces
  let nodes = {
    x: [],
    y: [],
    text: [],
    customdata: [],  // Store IDs for click handling
    mode: 'markers+text',
    type: 'scatter',
    marker: {
      size: [],
      color: [],
      line: { width: 2, color: 'white' }
    },
    textposition: 'top center',
    textfont: { size: 10, color: '#1e293b' },
    hoverinfo: 'text',
    hovertext: []
  };

  // Edge traces (3 types: strong, medium, weak)
  let strongEdges = {
    x: [], y: [],
    mode: 'lines',
    type: 'scatter',
    line: { width: 3, color: '#10b981' },
    hoverinfo: 'skip',
    showlegend: false
  };

  let mediumEdges = {
    x: [], y: [],
    mode: 'lines',
    type: 'scatter',
    line: { width: 2, color: '#f59e0b' },
    hoverinfo: 'skip',
    showlegend: false
  };

  let weakEdges = {
    x: [], y: [],
    mode: 'lines',
    type: 'scatter',
    line: { width: 2, color: '#ef4444', dash: 'dash' },
    hoverinfo: 'skip',
    showlegend: false
  };

  const nodePositions = {};

  if (currentViewMode === 'vendor-control') {
    renderVendorControlView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions);
  } else if (currentViewMode === 'supply-chain') {
    renderSupplyChainView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions);
  } else if (currentViewMode === 'risk-control') {
    renderRiskControlView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions);
  }

  // Combine all traces (edges first so they're behind nodes)
  const data = [weakEdges, mediumEdges, strongEdges, nodes];

  const layout = {
    showlegend: false,
    hovermode: 'closest',
    margin: { l: 40, r: 40, t: 40, b: 40 },
    xaxis: {
      showgrid: false,
      zeroline: false,
      showticklabels: false,
      fixedrange: true
    },
    yaxis: {
      showgrid: false,
      zeroline: false,
      showticklabels: false,
      fixedrange: true
    },
    plot_bgcolor: '#f8fafc',
    paper_bgcolor: '#ffffff'
  };

  const config = {
    displayModeBar: true,
    displaylogo: false,
    modeBarButtonsToRemove: ['pan2d', 'lasso2d', 'select2d', 'zoom2d', 'zoomIn2d', 'zoomOut2d', 'autoScale2d', 'resetScale2d'],
    responsive: true
  };

  Plotly.newPlot('graph', data, layout, config);

  // Add click handler
  document.getElementById('graph').on('plotly_click', (data) => {
    const point = data.points[0];
    const nodeId = point.customdata;

    if (nodeId) {
      if (nodeId.startsWith('v')) {
        showVendorDetails(nodeId);
      } else if (nodeId.startsWith('c')) {
        showControlDetails(parseInt(nodeId.substring(1)));
      } else if (nodeId.startsWith('r')) {
        showRiskDetails(nodeId);
      }
    }
  });
}

/**
 * Render Vendor-Control View
 */
function renderVendorControlView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions) {
  const vendors = mockEvidence.vendors;
  const controls = mockEvidence.controls;

  // Position vendors on left (x=0)
  vendors.forEach((vendor, i) => {
    const y = i * 150;
    const x = 0;
    nodePositions[`vendor-${vendor.id}`] = { x, y };

    nodes.x.push(x);
    nodes.y.push(y);
    nodes.text.push(vendor.name);
    nodes.customdata.push(vendor.id);
    nodes.marker.size.push(getVendorNodeSize(vendor));
    nodes.marker.color.push(getVendorNodeColor(vendor));

    const compliance = getVendorCompliance(vendor);
    const compliantControls = vendor.controls.filter(c => c.status === 'compliant').length;

    nodes.hovertext.push(
      `<b>${vendor.name}</b><br>` +
      `Criticality: ${vendor.criticality}<br>` +
      `Overall Compliance: ${compliance}%<br>` +
      `Controls: ${compliantControls}/${vendor.controls.length} compliant<br>` +
      `Risk Score: ${(vendor.riskScore * 100).toFixed(0)}%<br>` +
      `<i>Click for details</i>`
    );
  });

  // Position controls on right (x=500)
  const controlIds = [4, 7, 23];  // We only have evidence for these 3
  controlIds.forEach((controlId, i) => {
    const control = controls.find(c => c.id === controlId);
    const y = i * 150;
    const x = 500;
    nodePositions[`control-${controlId}`] = { x, y };

    nodes.x.push(x);
    nodes.y.push(y);
    nodes.text.push(`C${controlId}`);
    nodes.customdata.push(`c${controlId}`);
    nodes.marker.size.push(getControlNodeSize(control));
    nodes.marker.color.push(getControlNodeColor(control));

    const vendorsWithControl = vendors.filter(v =>
      v.controls.some(c => c.id === controlId)
    );
    const avgCompliance = getControlAvgCompliance(controlId);

    nodes.hovertext.push(
      `<b>${control.name}</b><br>` +
      `Control #${controlId}<br>` +
      `Criticality: ${control.criticality}<br>` +
      `Vendors: ${vendorsWithControl.length}<br>` +
      `Avg Compliance: ${avgCompliance}%<br>` +
      `<i>Click for details</i>`
    );
  });

  // Draw edges (vendor → control)
  vendors.forEach(vendor => {
    const vendorPos = nodePositions[`vendor-${vendor.id}`];

    vendor.controls.forEach(control => {
      const controlPos = nodePositions[`control-${control.id}`];

      if (vendorPos && controlPos) {
        const percentage = control.percentage;
        let edgeSet = mediumEdges;

        if (percentage >= 85) {
          edgeSet = strongEdges;
        } else if (percentage < 70) {
          edgeSet = weakEdges;
        }

        edgeSet.x.push(vendorPos.x, controlPos.x, null);
        edgeSet.y.push(vendorPos.y, controlPos.y, null);
      }
    });
  });
}

/**
 * Render Supply-Chain View
 */
function renderSupplyChainView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions) {
  const vendors = mockEvidence.vendors;

  // Circular layout
  const radius = 200;
  const angleStep = (2 * Math.PI) / vendors.length;

  vendors.forEach((vendor, i) => {
    const angle = i * angleStep;
    const x = radius * Math.cos(angle);
    const y = radius * Math.sin(angle);
    nodePositions[`vendor-${vendor.id}`] = { x, y };

    nodes.x.push(x);
    nodes.y.push(y);
    nodes.text.push(vendor.name);
    nodes.customdata.push(vendor.id);
    nodes.marker.size.push(getVendorNodeSize(vendor));
    nodes.marker.color.push(getVendorNodeColor(vendor));

    const compliance = getVendorCompliance(vendor);

    nodes.hovertext.push(
      `<b>${vendor.name}</b><br>` +
      `Criticality: ${vendor.criticality}<br>` +
      `Compliance: ${compliance}%<br>` +
      `Subprocessors: ${vendor.subprocessors.length}<br>` +
      `<i>Click for details</i>`
    );
  });

  // Draw dependency edges (vendor → subprocessor)
  vendors.forEach(vendor => {
    const vendorPos = nodePositions[`vendor-${vendor.id}`];

    vendor.subprocessors.forEach(subId => {
      const subPos = nodePositions[`vendor-${subId}`];
      if (vendorPos && subPos) {
        mediumEdges.x.push(vendorPos.x, subPos.x, null);
        mediumEdges.y.push(vendorPos.y, subPos.y, null);
      }
    });
  });
}

/**
 * Render Risk-Control View
 */
function renderRiskControlView(nodes, strongEdges, mediumEdges, weakEdges, nodePositions) {
  const risks = mockEvidence.risks;
  const controls = mockEvidence.controls;

  // Position risks on left (x=0)
  risks.forEach((risk, i) => {
    const y = i * 120;
    const x = 0;
    nodePositions[`risk-${risk.id}`] = { x, y };

    nodes.x.push(x);
    nodes.y.push(y);
    nodes.text.push(risk.name);
    nodes.customdata.push(risk.id);
    nodes.marker.size.push(getRiskNodeSize(risk));
    nodes.marker.color.push(getRiskNodeColor(risk));

    nodes.hovertext.push(
      `<b>${risk.name}</b><br>` +
      `Severity: ${risk.severity}<br>` +
      `Affected Controls: ${risk.affectedControls.length}<br>` +
      `<i>${risk.description}</i><br>` +
      `<i>Click for details</i>`
    );
  });

  // Position controls on right (x=500)
  const allControlIds = new Set();
  risks.forEach(r => r.affectedControls.forEach(c => allControlIds.add(c)));
  const controlsList = Array.from(allControlIds).sort((a, b) => a - b);

  controlsList.forEach((controlId, i) => {
    const control = controls.find(c => c.id === controlId);
    const y = i * 80;
    const x = 500;
    nodePositions[`control-${controlId}`] = { x, y };

    nodes.x.push(x);
    nodes.y.push(y);
    nodes.text.push(`C${controlId}`);
    nodes.customdata.push(`c${controlId}`);
    nodes.marker.size.push(getControlNodeSize(control));
    nodes.marker.color.push(getControlNodeColor(control));

    const risksForControl = risks.filter(r => r.affectedControls.includes(controlId));

    nodes.hovertext.push(
      `<b>${control.name}</b><br>` +
      `Control #${controlId}<br>` +
      `Criticality: ${control.criticality}<br>` +
      `Mitigates: ${risksForControl.length} risks<br>` +
      `<i>Click for details</i>`
    );
  });

  // Draw edges (risk → control)
  risks.forEach(risk => {
    const riskPos = nodePositions[`risk-${risk.id}`];

    risk.affectedControls.forEach(controlId => {
      const controlPos = nodePositions[`control-${controlId}`];
      if (riskPos && controlPos) {
        // Color by risk severity
        let edgeSet = mediumEdges;
        if (risk.severity === 'critical') {
          edgeSet = weakEdges;
        } else if (risk.severity === 'high') {
          edgeSet = strongEdges;
        }

        edgeSet.x.push(riskPos.x, controlPos.x, null);
        edgeSet.y.push(riskPos.y, controlPos.y, null);
      }
    });
  });
}

/**
 * Node sizing functions
 */
function getVendorNodeSize(vendor) {
  const compliance = parseFloat(getVendorCompliance(vendor));
  if (compliance >= 85) return 30;
  if (compliance >= 70) return 25;
  return 20;
}

function getControlNodeSize(control) {
  if (control.criticality === 'critical') return 25;
  if (control.criticality === 'high') return 20;
  return 15;
}

function getRiskNodeSize(risk) {
  if (risk.severity === 'critical') return 25;
  if (risk.severity === 'high') return 22;
  return 18;
}

/**
 * Node coloring functions
 */
function getVendorNodeColor(vendor) {
  const riskScore = vendor.riskScore;
  if (riskScore > 0.4) return '#ef4444';  // Red (high risk)
  if (riskScore > 0.2) return '#f59e0b';  // Orange (medium risk)
  return '#10b981';  // Green (low risk)
}

function getControlNodeColor(control) {
  if (control.criticality === 'critical') return '#dc2626';
  if (control.criticality === 'high') return '#f59e0b';
  if (control.criticality === 'medium') return '#6366f1';
  return '#64748b';
}

function getRiskNodeColor(risk) {
  if (risk.severity === 'critical') return '#991b1b';
  if (risk.severity === 'high') return '#b91c1c';
  return '#dc2626';
}

/**
 * Show vendor details panel
 */
function showVendorDetails(vendorId) {
  const vendor = mockEvidence.vendors.find(v => v.id === vendorId);
  if (!vendor) return;

  const compliance = getVendorCompliance(vendor);
  const totalPassed = vendor.controls.reduce((sum, c) => sum + c.passed, 0);
  const totalRequirements = vendor.controls.reduce((sum, c) => sum + c.total, 0);

  let html = `
    <div class="space-y-4">
      <div class="bg-slate-50 rounded-lg p-4">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="text-lg font-semibold text-slate-900">${vendor.name}</h3>
            <p class="text-sm text-slate-600">Criticality: <span class="font-medium">${vendor.criticality}</span></p>
          </div>
          <div class="text-right">
            <div class="text-3xl font-bold text-slate-900">${compliance}%</div>
            <p class="text-xs text-slate-600">overall compliance</p>
          </div>
        </div>
        <div class="mt-3 text-sm text-slate-700">
          <p><strong>Requirements:</strong> ${totalPassed}/${totalRequirements} passed</p>
          <p><strong>Risk Score:</strong> ${(vendor.riskScore * 100).toFixed(0)}%</p>
        </div>
      </div>
  `;

  vendor.controls.forEach(control => {
    const statusColor = control.status === 'compliant' ? 'green' :
                       control.status === 'partially_compliant' ? 'amber' : 'red';
    const statusIcon = control.status === 'compliant' ? '✓' :
                      control.status === 'partially_compliant' ? '⚠' : '✗';

    html += `
      <div class="border border-slate-200 rounded-lg p-4">
        <div class="flex items-start justify-between mb-2">
          <h4 class="font-semibold text-slate-900">Control #${control.id}: ${control.name}</h4>
          <span class="px-2 py-1 rounded text-xs font-medium bg-${statusColor}-100 text-${statusColor}-700">
            ${statusIcon} ${control.status.replace('_', ' ')}
          </span>
        </div>
        <div class="mb-3">
          <p class="text-sm text-slate-600">
            <strong>${control.passed}/${control.total} requirements passed (${control.percentage.toFixed(1)}%)</strong>
          </p>
        </div>

        <div class="space-y-2">
          <p class="text-xs font-semibold text-slate-700 uppercase">Requirements:</p>
          ${control.requirements.map(req => `
            <div class="flex items-start gap-2 text-sm">
              <span class="${req.passed ? 'text-green-600' : 'text-red-600'}">${req.passed ? '✓' : '✗'}</span>
              <div>
                <p class="font-medium text-slate-900">${req.name}</p>
                <p class="text-xs text-slate-600">${req.detail}</p>
              </div>
            </div>
          `).join('')}
        </div>

        ${control.risks.length > 0 ? `
          <div class="mt-3 pt-3 border-t border-slate-200">
            <p class="text-xs font-semibold text-amber-700 uppercase mb-1">Risks:</p>
            ${control.risks.map(risk => `
              <p class="text-sm text-amber-800">• ${risk}</p>
            `).join('')}
          </div>
        ` : ''}

        <div class="mt-3 text-xs text-slate-500">
          <p><strong>Source:</strong> ${control.source_document}</p>
          <p><strong>Confidence:</strong> ${(control.extraction_confidence * 100).toFixed(0)}% |
             <strong>SOC 2 Overlap:</strong> ${control.soc2_overlap}%</p>
        </div>

        <details class="mt-3">
          <summary class="cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-700">
            View Raw JSON ▼
          </summary>
          <pre class="mt-2 bg-slate-900 text-green-400 p-3 rounded text-xs overflow-x-auto">${JSON.stringify(control.structuredData, null, 2)}</pre>
        </details>
      </div>
    `;
  });

  html += `</div>`;

  document.getElementById('details-title').textContent = `Vendor: ${vendor.name}`;
  document.getElementById('details-content').innerHTML = html;
  document.getElementById('details-panel').classList.remove('hidden');
}

/**
 * Show control details panel
 */
function showControlDetails(controlId) {
  const control = mockEvidence.controls.find(c => c.id === controlId);
  if (!control) return;

  const vendorsWithControl = mockEvidence.vendors.filter(v =>
    v.controls.some(c => c.id === controlId)
  );
  const avgCompliance = getControlAvgCompliance(controlId);

  let html = `
    <div class="space-y-4">
      <div class="bg-slate-50 rounded-lg p-4">
        <h3 class="text-lg font-semibold text-slate-900">Control #${control.id}: ${control.name}</h3>
        <p class="text-sm text-slate-600 mt-1">
          <strong>Category:</strong> ${control.category} | <strong>Criticality:</strong> ${control.criticality}
        </p>
        <p class="text-sm text-slate-700 mt-2">
          <strong>Average Compliance:</strong> ${avgCompliance}%
        </p>
        <p class="text-sm text-slate-700">
          <strong>Vendors Evaluated:</strong> ${vendorsWithControl.length}
        </p>
      </div>
  `;

  vendorsWithControl.forEach(vendor => {
    const ctrl = vendor.controls.find(c => c.id === controlId);
    const statusColor = ctrl.status === 'compliant' ? 'green' :
                       ctrl.status === 'partially_compliant' ? 'amber' : 'red';

    html += `
      <div class="border border-slate-200 rounded-lg p-4">
        <div class="flex items-start justify-between mb-2">
          <h4 class="font-semibold text-slate-900">${vendor.name}</h4>
          <div class="text-right">
            <div class="text-2xl font-bold text-${statusColor}-600">${ctrl.percentage.toFixed(1)}%</div>
            <p class="text-xs text-slate-600">${ctrl.passed}/${ctrl.total} passed</p>
          </div>
        </div>

        <div class="space-y-1">
          ${ctrl.requirements.map(req => `
            <div class="flex items-start gap-2 text-sm">
              <span class="${req.passed ? 'text-green-600' : 'text-red-600'}">${req.passed ? '✓' : '✗'}</span>
              <p class="text-slate-700">${req.name}</p>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  });

  html += `</div>`;

  document.getElementById('details-title').textContent = `Control #${control.id}: ${control.name}`;
  document.getElementById('details-content').innerHTML = html;
  document.getElementById('details-panel').classList.remove('hidden');
}

/**
 * Show risk details panel
 */
function showRiskDetails(riskId) {
  const risk = mockEvidence.risks.find(r => r.id === riskId);
  if (!risk) return;

  let html = `
    <div class="space-y-4">
      <div class="bg-slate-50 rounded-lg p-4">
        <h3 class="text-lg font-semibold text-slate-900">${risk.name}</h3>
        <p class="text-sm text-slate-600 mt-1">
          <strong>Severity:</strong> ${risk.severity}
        </p>
        <p class="text-sm text-slate-700 mt-2">${risk.description}</p>
      </div>

      <div class="border border-slate-200 rounded-lg p-4">
        <h4 class="font-semibold text-slate-900 mb-2">Affected Controls:</h4>
        <div class="space-y-1">
          ${risk.affectedControls.map(controlId => {
            const control = mockEvidence.controls.find(c => c.id === controlId);
            return `<p class="text-sm text-slate-700">• Control #${controlId}: ${control.name}</p>`;
          }).join('')}
        </div>
      </div>
    </div>
  `;

  document.getElementById('details-title').textContent = `Risk: ${risk.name}`;
  document.getElementById('details-content').innerHTML = html;
  document.getElementById('details-panel').classList.remove('hidden');
}

/**
 * Close details panel
 */
function closeDetailsPanel() {
  document.getElementById('details-panel').classList.add('hidden');
}
