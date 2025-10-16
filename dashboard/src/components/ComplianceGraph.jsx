/**
 * ComplianceGraph Component
 *
 * An interactive Plotly-based graph visualization for the CONDUIT dashboard.
 * This component displays vendor-control relationships, supply chain networks,
 * and risk-control mappings with color-coded compliance percentages.
 *
 * EDUCATIONAL NOTES:
 * - Plotly uses "traces" as the building blocks of a chart. Each trace represents
 *   a set of data points (like nodes or edges) that will be rendered together.
 * - We use "scatter" type traces because they allow us to plot points (nodes) and
 *   lines (edges) in a 2D space with custom styling.
 * - Plotly's layout system controls the appearance of the entire chart (axes, margins, etc.)
 */

import React, { useMemo } from 'react';
import Plot from 'react-plotly.js';
import { getEdgeColor, getEdgeStyle } from '../lib/utils';

/**
 * Main ComplianceGraph Component
 *
 * @param {Object} props - Component properties
 * @param {string} props.viewMode - Current view mode: 'vendor-control', 'supply-chain', or 'risk-control'
 * @param {Array} props.vendors - Array of vendor objects from mockData
 * @param {Array} props.controls - Array of control objects from mockData
 * @param {Array} props.risks - Array of risk objects from mockData
 * @param {Function} props.onNodeClick - Callback function when a node is clicked: (nodeId, nodeType) => void
 */
const ComplianceGraph = ({
  viewMode = 'vendor-control',
  vendors = [],
  controls = [],
  risks = [],
  onNodeClick = () => {}
}) => {

  /**
   * useMemo Hook Explanation:
   * This hook ensures that we only recalculate the graph data when the dependencies
   * (viewMode, vendors, controls, risks) actually change. This is important for
   * performance because generating graph data can be computationally expensive.
   *
   * Without useMemo, the graph would be regenerated on every render, even if
   * nothing changed, which could cause lag and unnecessary re-renders.
   */
  const graphData = useMemo(() => {
    switch (viewMode) {
      case 'vendor-control':
        return renderVendorControlView();
      case 'supply-chain':
        return renderSupplyChainView();
      case 'risk-control':
        return renderRiskControlView();
      default:
        return renderVendorControlView();
    }
  }, [viewMode, vendors, controls, risks]);

  /**
   * VENDOR-CONTROL VIEW
   *
   * This view shows:
   * - Vendors on the LEFT side (x=0)
   * - Controls on the RIGHT side (x=500)
   * - Edges connecting vendors to their controls, colored by compliance percentage
   *
   * Layout Strategy:
   * - Vendors are stacked vertically at x=0, evenly spaced based on their count
   * - Controls are stacked vertically at x=500, evenly spaced based on their count
   * - This creates a bipartite graph (two separate groups with connections between them)
   */
  function renderVendorControlView() {
    // Arrays to store edge coordinates - we separate by compliance level for different colors
    const strongEdges = { x: [], y: [], text: [], percentage: [] };  // >= 85% (Green)
    const mediumEdges = { x: [], y: [], text: [], percentage: [] };  // 70-84% (Orange)
    const weakEdges = { x: [], y: [], text: [], percentage: [] };    // < 70% (Red)

    // Vendor nodes (left side)
    const vendorNodes = {
      x: [],
      y: [],
      text: [],
      hovertext: [],
      customdata: []  // Store vendor IDs for click handling
    };

    // Control nodes (right side)
    const controlNodes = {
      x: [],
      y: [],
      text: [],
      hovertext: [],
      customdata: []  // Store control IDs for click handling
    };

    /**
     * Positioning Logic:
     * We calculate vertical positions by dividing the available height
     * evenly among nodes. The height range is 0-500.
     */
    const vendorSpacing = vendors.length > 1 ? 500 / (vendors.length - 1) : 0;
    const controlSpacing = controls.length > 1 ? 500 / (controls.length - 1) : 0;

    /**
     * Step 1: Create vendor nodes and their edges to controls
     *
     * For each vendor:
     * 1. Calculate its Y position based on its index
     * 2. Add it to the vendorNodes arrays
     * 3. Loop through its controls and create edges
     */
    vendors.forEach((vendor, vIndex) => {
      const vendorY = vIndex * vendorSpacing;

      // Add vendor node
      vendorNodes.x.push(0);  // All vendors at x=0 (left side)
      vendorNodes.y.push(vendorY);
      vendorNodes.text.push(vendor.name);
      vendorNodes.customdata.push(vendor.id);

      // Calculate vendor's overall compliance for hover text
      const totalReqs = vendor.controls.reduce((sum, c) => sum + c.total, 0);
      const passedReqs = vendor.controls.reduce((sum, c) => sum + c.passed, 0);
      const vendorCompliance = totalReqs > 0 ? ((passedReqs / totalReqs) * 100).toFixed(1) : 0;

      vendorNodes.hovertext.push(
        `${vendor.name}<br>` +
        `Overall Compliance: ${vendorCompliance}%<br>` +
        `Risk Score: ${(vendor.riskScore * 100).toFixed(0)}%<br>` +
        `Criticality: ${vendor.criticality}`
      );

      /**
       * Step 2: Create edges from this vendor to each of its controls
       *
       * Edge Drawing in Plotly:
       * To draw a line from point A (x1,y1) to point B (x2,y2), we need to:
       * 1. Add x1 to the x array
       * 2. Add x2 to the x array
       * 3. Add null to the x array (this tells Plotly to "lift the pen")
       * Same pattern for y coordinates.
       *
       * The "null" is crucial - without it, Plotly would connect ALL points
       * in the array with a continuous line.
       */
      vendor.controls.forEach((vendorControl) => {
        // Find the matching control in the controls array
        const controlIndex = controls.findIndex(c => c.id === vendorControl.id);
        if (controlIndex === -1) return;  // Skip if control not found

        const controlY = controlIndex * controlSpacing;
        const percentage = vendorControl.percentage;

        /**
         * Categorize edge by compliance percentage
         * This allows us to use different colors and styles for different
         * compliance levels. We use three separate traces for better control.
         */
        const edgeData = {
          x: [0, 500, null],  // From vendor (x=0) to control (x=500), then null
          y: [vendorY, controlY, null],  // From vendor Y to control Y, then null
          text: `${percentage.toFixed(1)}%`,
          percentage: percentage
        };

        // Add to appropriate category based on percentage thresholds
        if (percentage >= 85) {
          strongEdges.x.push(...edgeData.x);
          strongEdges.y.push(...edgeData.y);
          strongEdges.text.push(edgeData.text);
          strongEdges.percentage.push(edgeData.percentage);
        } else if (percentage >= 70) {
          mediumEdges.x.push(...edgeData.x);
          mediumEdges.y.push(...edgeData.y);
          mediumEdges.text.push(edgeData.text);
          mediumEdges.percentage.push(edgeData.percentage);
        } else {
          weakEdges.x.push(...edgeData.x);
          weakEdges.y.push(...edgeData.y);
          weakEdges.text.push(edgeData.text);
          weakEdges.percentage.push(edgeData.percentage);
        }
      });
    });

    /**
     * Step 3: Create control nodes (right side)
     *
     * We calculate average compliance for each control across all vendors
     * to show in the hover text.
     */
    controls.forEach((control, cIndex) => {
      const controlY = cIndex * controlSpacing;

      controlNodes.x.push(500);  // All controls at x=500 (right side)
      controlNodes.y.push(controlY);
      controlNodes.text.push(control.name);
      controlNodes.customdata.push(control.id);

      // Calculate average compliance for this control across all vendors
      const vendorsWithControl = vendors.filter(v =>
        v.controls.some(c => c.id === control.id)
      );

      let avgCompliance = 0;
      if (vendorsWithControl.length > 0) {
        const totalPassed = vendorsWithControl.reduce((sum, v) => {
          const ctrl = v.controls.find(c => c.id === control.id);
          return sum + (ctrl ? ctrl.passed : 0);
        }, 0);
        const totalReqs = vendorsWithControl.reduce((sum, v) => {
          const ctrl = v.controls.find(c => c.id === control.id);
          return sum + (ctrl ? ctrl.total : 0);
        }, 0);
        avgCompliance = totalReqs > 0 ? ((totalPassed / totalReqs) * 100).toFixed(1) : 0;
      }

      controlNodes.hovertext.push(
        `${control.name}<br>` +
        `Average Compliance: ${avgCompliance}%<br>` +
        `Category: ${control.category}<br>` +
        `Criticality: ${control.criticality}<br>` +
        `Vendors: ${vendorsWithControl.length}`
      );
    });

    /**
     * Step 4: Build Plotly traces
     *
     * Traces are the fundamental building blocks of a Plotly chart.
     * Each trace represents one "layer" of data that will be rendered.
     *
     * We create 5 traces:
     * 1. Strong edges (green, solid) - high compliance
     * 2. Medium edges (orange, solid) - moderate compliance
     * 3. Weak edges (red, dashed) - low compliance
     * 4. Vendor nodes (blue circles)
     * 5. Control nodes (purple circles)
     *
     * Order matters: traces are rendered in order, so edges go first
     * (drawn in the background) and nodes go last (drawn on top).
     */
    return [
      // TRACE 1: Strong edges (>= 85% compliance)
      {
        type: 'scatter',  // Scatter plot can show both points and lines
        mode: 'lines',    // Only show lines, not points
        x: strongEdges.x,
        y: strongEdges.y,
        line: {
          color: '#10b981',  // Green color
          width: 2,
          shape: 'linear'    // Straight lines
        },
        hoverinfo: 'text',   // Show custom hover text
        hovertext: strongEdges.text.filter((_, i) => (i + 1) % 3 !== 0),  // Remove nulls from hover
        name: 'Strong (≥85%)',  // Legend label
        showlegend: true
      },
      // TRACE 2: Medium edges (70-84% compliance)
      {
        type: 'scatter',
        mode: 'lines',
        x: mediumEdges.x,
        y: mediumEdges.y,
        line: {
          color: '#f59e0b',  // Orange color
          width: 2,
          shape: 'linear'
        },
        hoverinfo: 'text',
        hovertext: mediumEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Medium (70-84%)',
        showlegend: true
      },
      // TRACE 3: Weak edges (< 70% compliance)
      {
        type: 'scatter',
        mode: 'lines',
        x: weakEdges.x,
        y: weakEdges.y,
        line: {
          color: '#ef4444',  // Red color
          width: 2,
          dash: 'dash',      // Dashed line style
          shape: 'linear'
        },
        hoverinfo: 'text',
        hovertext: weakEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Weak (<70%)',
        showlegend: true
      },
      // TRACE 4: Vendor nodes
      {
        type: 'scatter',
        mode: 'markers+text',  // Show both the point and text label
        x: vendorNodes.x,
        y: vendorNodes.y,
        text: vendorNodes.text,
        customdata: vendorNodes.customdata,  // Store IDs for click handling
        textposition: 'middle left',   // Position text to the left of the point
        textfont: { size: 10, color: '#1e3a8a' },
        marker: {
          size: 12,
          color: '#3b82f6',  // Blue color for vendors
          line: { color: '#1e3a8a', width: 2 }
        },
        hoverinfo: 'text',
        hovertext: vendorNodes.hovertext,
        name: 'Vendors',
        showlegend: true
      },
      // TRACE 5: Control nodes
      {
        type: 'scatter',
        mode: 'markers+text',
        x: controlNodes.x,
        y: controlNodes.y,
        text: controlNodes.text,
        customdata: controlNodes.customdata,
        textposition: 'middle right',  // Position text to the right of the point
        textfont: { size: 10, color: '#6b21a8' },
        marker: {
          size: 12,
          color: '#a855f7',  // Purple color for controls
          line: { color: '#6b21a8', width: 2 }
        },
        hoverinfo: 'text',
        hovertext: controlNodes.hovertext,
        name: 'Controls',
        showlegend: true
      }
    ];
  }

  /**
   * SUPPLY-CHAIN VIEW
   *
   * This view shows the network of vendors and their subprocessors
   * in a circular layout. This is useful for understanding the
   * full supply chain and identifying single points of failure.
   *
   * Layout Strategy:
   * - Arrange all vendors in a circle
   * - Draw edges between vendors and their subprocessors
   * - Color edges based on the subprocessor's overall compliance
   */
  function renderSupplyChainView() {
    const strongEdges = { x: [], y: [], text: [] };
    const mediumEdges = { x: [], y: [], text: [] };
    const weakEdges = { x: [], y: [], text: [] };

    const vendorNodes = {
      x: [],
      y: [],
      text: [],
      hovertext: [],
      customdata: [],
      sizes: []  // Size nodes by criticality
    };

    /**
     * Circular Layout Math:
     * To place N items in a circle:
     * - Divide 360 degrees by N to get the angle between items
     * - For each item at index i, its angle is i * angleStep
     * - Convert angle to x,y coordinates using trigonometry:
     *   x = centerX + radius * cos(angle)
     *   y = centerY + radius * sin(angle)
     *
     * Note: JavaScript's Math.cos and Math.sin use radians, not degrees,
     * so we need to convert: radians = degrees * (Math.PI / 180)
     */
    const radius = 200;
    const centerX = 250;
    const centerY = 250;
    const angleStep = (2 * Math.PI) / vendors.length;

    /**
     * Step 1: Position vendors in a circle
     */
    vendors.forEach((vendor, index) => {
      const angle = index * angleStep;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      vendorNodes.x.push(x);
      vendorNodes.y.push(y);
      vendorNodes.text.push(vendor.name);
      vendorNodes.customdata.push(vendor.id);

      // Size nodes based on criticality
      const sizeMap = { critical: 20, high: 15, medium: 12, low: 10 };
      vendorNodes.sizes.push(sizeMap[vendor.criticality] || 12);

      // Calculate vendor compliance
      const totalReqs = vendor.controls.reduce((sum, c) => sum + c.total, 0);
      const passedReqs = vendor.controls.reduce((sum, c) => sum + c.passed, 0);
      const compliance = totalReqs > 0 ? ((passedReqs / totalReqs) * 100).toFixed(1) : 0;

      vendorNodes.hovertext.push(
        `${vendor.name}<br>` +
        `Compliance: ${compliance}%<br>` +
        `Risk Score: ${(vendor.riskScore * 100).toFixed(0)}%<br>` +
        `Criticality: ${vendor.criticality}<br>` +
        `Subprocessors: ${vendor.subprocessors.length}`
      );
    });

    /**
     * Step 2: Create edges between vendors and subprocessors
     *
     * We look up each subprocessor's position and draw a line to it.
     */
    vendors.forEach((vendor, vIndex) => {
      const vendorX = vendorNodes.x[vIndex];
      const vendorY = vendorNodes.y[vIndex];

      vendor.subprocessors.forEach((subprocessorId) => {
        // Find the subprocessor vendor
        const subprocessorIndex = vendors.findIndex(v => v.id === subprocessorId);
        if (subprocessorIndex === -1) return;

        const subprocessor = vendors[subprocessorIndex];
        const subprocessorX = vendorNodes.x[subprocessorIndex];
        const subprocessorY = vendorNodes.y[subprocessorIndex];

        // Calculate subprocessor's compliance
        const totalReqs = subprocessor.controls.reduce((sum, c) => sum + c.total, 0);
        const passedReqs = subprocessor.controls.reduce((sum, c) => sum + c.passed, 0);
        const compliance = totalReqs > 0 ? ((passedReqs / totalReqs) * 100).toFixed(1) : 0;

        const edgeData = {
          x: [vendorX, subprocessorX, null],
          y: [vendorY, subprocessorY, null],
          text: `${vendor.name} → ${subprocessor.name}<br>${compliance}% compliant`
        };

        // Categorize by compliance
        if (compliance >= 85) {
          strongEdges.x.push(...edgeData.x);
          strongEdges.y.push(...edgeData.y);
          strongEdges.text.push(edgeData.text);
        } else if (compliance >= 70) {
          mediumEdges.x.push(...edgeData.x);
          mediumEdges.y.push(...edgeData.y);
          mediumEdges.text.push(edgeData.text);
        } else {
          weakEdges.x.push(...edgeData.x);
          weakEdges.y.push(...edgeData.y);
          weakEdges.text.push(edgeData.text);
        }
      });
    });

    /**
     * Step 3: Build traces for supply chain view
     */
    return [
      // Strong edges
      {
        type: 'scatter',
        mode: 'lines',
        x: strongEdges.x,
        y: strongEdges.y,
        line: { color: '#10b981', width: 2 },
        hoverinfo: 'text',
        hovertext: strongEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Strong (≥85%)',
        showlegend: true
      },
      // Medium edges
      {
        type: 'scatter',
        mode: 'lines',
        x: mediumEdges.x,
        y: mediumEdges.y,
        line: { color: '#f59e0b', width: 2 },
        hoverinfo: 'text',
        hovertext: mediumEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Medium (70-84%)',
        showlegend: true
      },
      // Weak edges
      {
        type: 'scatter',
        mode: 'lines',
        x: weakEdges.x,
        y: weakEdges.y,
        line: { color: '#ef4444', width: 2, dash: 'dash' },
        hoverinfo: 'text',
        hovertext: weakEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Weak (<70%)',
        showlegend: true
      },
      // Vendor nodes
      {
        type: 'scatter',
        mode: 'markers+text',
        x: vendorNodes.x,
        y: vendorNodes.y,
        text: vendorNodes.text,
        customdata: vendorNodes.customdata,
        textposition: 'top center',
        textfont: { size: 10, color: '#1e3a8a' },
        marker: {
          size: vendorNodes.sizes,
          color: '#3b82f6',
          line: { color: '#1e3a8a', width: 2 }
        },
        hoverinfo: 'text',
        hovertext: vendorNodes.hovertext,
        name: 'Vendors',
        showlegend: true
      }
    ];
  }

  /**
   * RISK-CONTROL VIEW
   *
   * This view shows:
   * - Risks on the LEFT side (x=0)
   * - Controls on the RIGHT side (x=500)
   * - Edges connecting risks to the controls that mitigate them
   *
   * Layout Strategy:
   * Similar to vendor-control view, but showing risk-control relationships.
   * Edge color represents the average effectiveness of the control across
   * all vendors.
   */
  function renderRiskControlView() {
    const strongEdges = { x: [], y: [], text: [] };
    const mediumEdges = { x: [], y: [], text: [] };
    const weakEdges = { x: [], y: [], text: [] };

    const riskNodes = {
      x: [],
      y: [],
      text: [],
      hovertext: [],
      customdata: [],
      sizes: []
    };

    const controlNodes = {
      x: [],
      y: [],
      text: [],
      hovertext: [],
      customdata: []
    };

    // Calculate spacing
    const riskSpacing = risks.length > 1 ? 500 / (risks.length - 1) : 0;
    const controlSpacing = controls.length > 1 ? 500 / (controls.length - 1) : 0;

    /**
     * Step 1: Create risk nodes (left side)
     */
    risks.forEach((risk, rIndex) => {
      const riskY = rIndex * riskSpacing;

      riskNodes.x.push(0);
      riskNodes.y.push(riskY);
      riskNodes.text.push(risk.name);
      riskNodes.customdata.push(risk.id);

      // Size by severity
      const sizeMap = { critical: 20, high: 15, medium: 12, low: 10 };
      riskNodes.sizes.push(sizeMap[risk.severity] || 12);

      riskNodes.hovertext.push(
        `${risk.name}<br>` +
        `Severity: ${risk.severity}<br>` +
        `${risk.description}<br>` +
        `Mitigated by ${risk.affectedControls.length} controls`
      );
    });

    /**
     * Step 2: Create control nodes and edges
     */
    controls.forEach((control, cIndex) => {
      const controlY = cIndex * controlSpacing;

      controlNodes.x.push(500);
      controlNodes.y.push(controlY);
      controlNodes.text.push(control.name);
      controlNodes.customdata.push(control.id);

      // Calculate average compliance
      const vendorsWithControl = vendors.filter(v =>
        v.controls.some(c => c.id === control.id)
      );

      let avgCompliance = 0;
      if (vendorsWithControl.length > 0) {
        const totalPassed = vendorsWithControl.reduce((sum, v) => {
          const ctrl = v.controls.find(c => c.id === control.id);
          return sum + (ctrl ? ctrl.passed : 0);
        }, 0);
        const totalReqs = vendorsWithControl.reduce((sum, v) => {
          const ctrl = v.controls.find(c => c.id === control.id);
          return sum + (ctrl ? ctrl.total : 0);
        }, 0);
        avgCompliance = totalReqs > 0 ? ((totalPassed / totalReqs) * 100).toFixed(1) : 0;
      }

      controlNodes.hovertext.push(
        `${control.name}<br>` +
        `Average Compliance: ${avgCompliance}%<br>` +
        `Category: ${control.category}<br>` +
        `Criticality: ${control.criticality}`
      );

      /**
       * Step 3: Create edges from risks to this control
       *
       * We find all risks that list this control in their affectedControls array,
       * then draw edges from those risks to this control.
       */
      risks.forEach((risk, rIndex) => {
        if (risk.affectedControls.includes(control.id)) {
          const riskY = rIndex * riskSpacing;

          const edgeData = {
            x: [0, 500, null],
            y: [riskY, controlY, null],
            text: `${risk.name} → ${control.name}<br>Control effectiveness: ${avgCompliance}%`
          };

          // Categorize by control effectiveness
          if (avgCompliance >= 85) {
            strongEdges.x.push(...edgeData.x);
            strongEdges.y.push(...edgeData.y);
            strongEdges.text.push(edgeData.text);
          } else if (avgCompliance >= 70) {
            mediumEdges.x.push(...edgeData.x);
            mediumEdges.y.push(...edgeData.y);
            mediumEdges.text.push(edgeData.text);
          } else {
            weakEdges.x.push(...edgeData.x);
            weakEdges.y.push(...edgeData.y);
            weakEdges.text.push(edgeData.text);
          }
        }
      });
    });

    /**
     * Step 4: Build traces
     */
    return [
      // Strong edges
      {
        type: 'scatter',
        mode: 'lines',
        x: strongEdges.x,
        y: strongEdges.y,
        line: { color: '#10b981', width: 2 },
        hoverinfo: 'text',
        hovertext: strongEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Strong (≥85%)',
        showlegend: true
      },
      // Medium edges
      {
        type: 'scatter',
        mode: 'lines',
        x: mediumEdges.x,
        y: mediumEdges.y,
        line: { color: '#f59e0b', width: 2 },
        hoverinfo: 'text',
        hovertext: mediumEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Medium (70-84%)',
        showlegend: true
      },
      // Weak edges
      {
        type: 'scatter',
        mode: 'lines',
        x: weakEdges.x,
        y: weakEdges.y,
        line: { color: '#ef4444', width: 2, dash: 'dash' },
        hoverinfo: 'text',
        hovertext: weakEdges.text.filter((_, i) => (i + 1) % 3 !== 0),
        name: 'Weak (<70%)',
        showlegend: true
      },
      // Risk nodes
      {
        type: 'scatter',
        mode: 'markers+text',
        x: riskNodes.x,
        y: riskNodes.y,
        text: riskNodes.text,
        customdata: riskNodes.customdata,
        textposition: 'middle left',
        textfont: { size: 10, color: '#991b1b' },
        marker: {
          size: riskNodes.sizes,
          color: '#ef4444',
          line: { color: '#991b1b', width: 2 }
        },
        hoverinfo: 'text',
        hovertext: riskNodes.hovertext,
        name: 'Risks',
        showlegend: true
      },
      // Control nodes
      {
        type: 'scatter',
        mode: 'markers+text',
        x: controlNodes.x,
        y: controlNodes.y,
        text: controlNodes.text,
        customdata: controlNodes.customdata,
        textposition: 'middle right',
        textfont: { size: 10, color: '#6b21a8' },
        marker: {
          size: 12,
          color: '#a855f7',
          line: { color: '#6b21a8', width: 2 }
        },
        hoverinfo: 'text',
        hovertext: controlNodes.hovertext,
        name: 'Controls',
        showlegend: true
      }
    ];
  }

  /**
   * Handle click events on the graph
   *
   * Plotly's onClick event provides information about what was clicked.
   * We extract the customdata (which contains our IDs) and the trace name
   * to determine what type of node was clicked.
   */
  const handleClick = (event) => {
    if (!event.points || event.points.length === 0) return;

    const point = event.points[0];
    const nodeId = point.customdata;

    // Determine node type from trace name
    let nodeType = 'unknown';
    if (point.data.name === 'Vendors') nodeType = 'vendor';
    else if (point.data.name === 'Controls') nodeType = 'control';
    else if (point.data.name === 'Risks') nodeType = 'risk';

    // Only trigger callback for node clicks, not edge clicks
    if (nodeType !== 'unknown' && nodeId) {
      onNodeClick(nodeId, nodeType);
    }
  };

  /**
   * Plotly Layout Configuration
   *
   * The layout controls the overall appearance of the chart, including:
   * - Title and margins
   * - Axes configuration (range, visibility, etc.)
   * - Legend positioning
   * - Interactivity settings
   */
  const layout = {
    // Remove title for cleaner look (can add back if needed)
    title: '',

    // Hover mode - 'closest' means hover on the nearest point
    hovermode: 'closest',

    // Show legend (displays our edge categories and node types)
    showlegend: true,
    legend: {
      x: 1.05,       // Position legend to the right of the chart
      y: 1,          // Align to top
      xanchor: 'left',
      yanchor: 'top'
    },

    // X-axis configuration
    xaxis: {
      visible: false,        // Hide axis line and labels
      range: [-50, 550],     // Fixed range - prevents zooming
      fixedrange: true       // Disable zoom/pan on this axis
    },

    // Y-axis configuration
    yaxis: {
      visible: false,
      range: [-50, 550],
      fixedrange: true
    },

    // Margins around the plot
    margin: {
      l: 150,    // Left margin - space for vendor/risk labels
      r: 150,    // Right margin - space for control labels
      t: 50,     // Top margin
      b: 50      // Bottom margin
    },

    // Responsive sizing
    autosize: true,

    // Background colors
    plot_bgcolor: 'rgba(0,0,0,0)',   // Transparent plot background
    paper_bgcolor: 'rgba(0,0,0,0)'   // Transparent paper background
  };

  /**
   * Plotly Config Options
   *
   * These control the mode bar (toolbar) and other interactive features.
   */
  const config = {
    displayModeBar: true,              // Show the toolbar
    displaylogo: false,                // Hide Plotly logo (cleaner look)
    modeBarButtonsToRemove: [          // Remove buttons we don't need
      'zoom2d',
      'pan2d',
      'select2d',
      'lasso2d',
      'zoomIn2d',
      'zoomOut2d',
      'autoScale2d',
      'resetScale2d'
    ],
    responsive: true                   // Resize with container
  };

  /**
   * Render the Plot component
   *
   * The Plot component from react-plotly.js takes:
   * - data: array of traces (our graphData)
   * - layout: configuration object
   * - config: toolbar/interaction configuration
   * - onClick: click event handler
   * - style: CSS styling for the component
   */
  return (
    <div className="w-full h-full">
      <Plot
        data={graphData}
        layout={layout}
        config={config}
        onClick={handleClick}
        style={{ width: '100%', height: '100%' }}
        useResizeHandler={true}
      />
    </div>
  );
};

export default ComplianceGraph;
