/**
 * CONDUIT Dashboard - Main Application Component
 *
 * This is the main dashboard for the CONDUIT risk management system.
 * It displays vendor compliance data, controls, and risk information
 * with interactive visualizations.
 *
 * Features:
 * - Dashboard statistics (vendors, controls, compliance, risks)
 * - Multiple view modes (Vendor-Control, Supply-Chain, Risk-Control)
 * - Interactive Plotly graph visualizations with 3 view modes
 * - Interactive vendor cards with compliance details
 */
import { useState } from 'react'
import { motion } from 'framer-motion'
import { Users, Shield, TrendingUp, AlertTriangle, Github, Sparkles } from 'lucide-react'
import { mockEvidence } from '@/data/mockData.js'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import StatsCard from '@/components/StatsCard'
import VendorCard from '@/components/VendorCard'
import ComplianceGraph from '@/components/ComplianceGraph'
import VendorDialog from '@/components/VendorDialog'
import ControlDialog from '@/components/ControlDialog'
import RiskDialog from '@/components/RiskDialog'
import EdgeLegend from '@/components/EdgeLegend'
import DemoChatbot from '@/components/DemoChatbot'
import './App.css'

function App() {
  // State for the current view mode (tabs)
  const [viewMode, setViewMode] = useState('vendor-control')

  // State for demo vendors (added from chatbot)
  const [demoVendors, setDemoVendors] = useState([])

  // State for dialogs
  const [selectedVendor, setSelectedVendor] = useState(null)
  const [vendorDialogOpen, setVendorDialogOpen] = useState(false)
  const [selectedControl, setSelectedControl] = useState(null)
  const [controlDialogOpen, setControlDialogOpen] = useState(false)
  const [selectedRisk, setSelectedRisk] = useState(null)
  const [riskDialogOpen, setRiskDialogOpen] = useState(false)

  /**
   * Handle adding demo vendor from chatbot
   */
  const handleAddDemoVendor = (dashboardData) => {
    const newVendor = {
      id: `demo_${Date.now()}`,
      name: dashboardData.vendor_name,
      criticality: 'medium',
      riskScore: 0.15,
      subprocessors: [],
      controls: [{
        id: dashboardData.control_id,
        name: dashboardData.control_name,
        passed: dashboardData.passed || 3,
        total: dashboardData.total || 3,
        percentage: dashboardData.percentage || 100,
        status: dashboardData.status || 'compliant',
        requirements: [],
        risks: [],
        source_document: 'Demo extraction',
        extraction_confidence: dashboardData.extraction_confidence || 0.85,
        soc2_overlap: 85,
        structuredData: {
          evidence_type: dashboardData.evidence_type,
          vendor_name: dashboardData.vendor_name
        }
      }]
    }

    setDemoVendors(prev => [...prev, newVendor])
    setViewMode('vendor-control')
  }

  // Merge demo vendors with mock data
  const allVendors = [...mockEvidence.vendors, ...demoVendors]
  const evidenceData = {
    ...mockEvidence,
    vendors: allVendors
  }

  /**
   * Calculate Dashboard Statistics
   * These are computed from the mockEvidence data
   */

  // Total number of vendors (including demo vendors)
  const totalVendors = allVendors.length

  // Total number of unique controls evaluated across all vendors
  const totalControls = mockEvidence.controls.length

  // Average compliance percentage across all vendors
  const avgCompliance = (
    allVendors.reduce((sum, vendor) => {
      const totalReqs = vendor.controls.reduce((s, c) => s + c.total, 0)
      const passedReqs = vendor.controls.reduce((s, c) => s + c.passed, 0)
      return sum + (passedReqs / totalReqs) * 100
    }, 0) / allVendors.length
  ).toFixed(1)

  // Total number of unique risks identified
  const totalRisks = mockEvidence.risks.length

  // Count of high-risk vendors (risk score >= 40%)
  const highRiskVendors = allVendors.filter(v => v.riskScore >= 0.4).length

  /**
   * Handle vendor card click
   * Opens the vendor details dialog
   */
  const handleVendorClick = (vendor) => {
    setSelectedVendor(vendor)
    setVendorDialogOpen(true)
  }

  /**
   * Handle node click in the compliance graph
   * This is called when users click on vendors, controls, or risks in the graph
   */
  const handleNodeClick = (nodeId, nodeType) => {
    console.log(`${nodeType} node clicked:`, nodeId)

    if (nodeType === 'vendor') {
      const vendor = allVendors.find(v => v.id === nodeId)
      if (vendor) {
        setSelectedVendor(vendor)
        setVendorDialogOpen(true)
      }
    } else if (nodeType === 'control') {
      const control = mockEvidence.controls.find(c => c.id === nodeId)
      if (control) {
        setSelectedControl(control)
        setControlDialogOpen(true)
      }
    } else if (nodeType === 'risk') {
      const risk = mockEvidence.risks.find(r => r.id === nodeId)
      if (risk) {
        setSelectedRisk(risk)
        setRiskDialogOpen(true)
      }
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header Section */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Logo and Title */}
            <div className="flex items-center gap-3">
              <span className="text-3xl">🔗</span>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">CONDUIT</h1>
                <p className="text-sm text-gray-600">Risk Management Dashboard</p>
              </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-4">
              <button
                onClick={() => setViewMode('demo')}
                className="flex items-center gap-2 px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700 transition-colors font-medium shadow-sm"
              >
                <Sparkles className="h-5 w-5" />
                Live Demo
              </button>

              <a
                href="https://github.com/grcengineering/conduit"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-gray-600 hover:text-gray-900 transition-colors"
              >
                <Github className="h-5 w-5" />
                <span className="text-sm font-medium">GitHub</span>
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        {/* Demo Mode Banner */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="bg-gradient-to-r from-blue-50 to-teal-50 border-l-4 border-blue-500 rounded-lg p-4 mb-6 shadow-sm"
        >
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0">
              <Sparkles className="h-5 w-5 text-blue-600 mt-0.5" />
            </div>
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-blue-900 mb-1">
                Demo Mode - Static Mock Data
              </h3>
              <p className="text-xs text-blue-800 leading-relaxed">
                This dashboard displays mock evidence for 3 vendors with 8 implemented ASSURE controls.
                The actual CONDUIT backend uses <span className="font-semibold">XML-based extraction</span> with Claude Haiku 4.5
                to process real vendor documents. Click "Live Demo" to try the interactive evidence extraction chatbot.
              </p>
              <div className="mt-2 flex flex-wrap gap-2 text-xs">
                <span className="inline-flex items-center px-2 py-0.5 rounded bg-blue-100 text-blue-800 font-medium">
                  8 of 24 ASSURE controls implemented
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded bg-teal-100 text-teal-800 font-medium">
                  XML extraction format
                </span>
                <span className="inline-flex items-center px-2 py-0.5 rounded bg-purple-100 text-purple-800 font-medium">
                  Pattern-based validation
                </span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Statistics Cards Section */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8"
        >
          <StatsCard
            value={totalVendors}
            label="Total Vendors"
            icon={Users}
            variant="default"
          />
          <StatsCard
            value={totalControls}
            label="Controls"
            icon={Shield}
            variant="default"
          />
          <StatsCard
            value={parseFloat(avgCompliance)}
            label="Avg Compliance (%)"
            icon={TrendingUp}
            variant="success"
          />
          <StatsCard
            value={totalRisks}
            label="Total Risks"
            icon={AlertTriangle}
            variant="warning"
          />
          <StatsCard
            value={highRiskVendors}
            label="High Risk Vendors"
            icon={AlertTriangle}
            variant="destructive"
          />
        </motion.div>

        {/* Demo Chatbot OR Controls Panel */}
        {viewMode === 'demo' ? (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
            <DemoChatbot onAddVendor={handleAddDemoVendor} />
          </div>
        ) : (
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-8">
            <div className="flex items-center justify-between mb-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">View Mode</label>
                <Tabs value={viewMode} onValueChange={setViewMode}>
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="vendor-control">Vendor → Control</TabsTrigger>
                    <TabsTrigger value="supply-chain">Supply Chain</TabsTrigger>
                    <TabsTrigger value="risk-control">Risk → Control</TabsTrigger>
                  </TabsList>
                </Tabs>
              </div>
              <EdgeLegend />
            </div>

          <Tabs value={viewMode} onValueChange={setViewMode}>
          {/* Tab Content - Vendor-Control Graph */}
          <TabsContent value="vendor-control" className="mt-6">
            <div
              id="graph-container"
              className="bg-white rounded-lg border border-gray-200 shadow-sm p-8 min-h-[500px]"
            >
              <ComplianceGraph
                viewMode="vendor-control"
                vendors={evidenceData.vendors}
                controls={evidenceData.controls}
                risks={evidenceData.risks}
                onNodeClick={handleNodeClick}
              />
            </div>
          </TabsContent>

          {/* Tab Content - Supply-Chain Graph */}
          <TabsContent value="supply-chain" className="mt-6">
            <div
              id="graph-container"
              className="bg-white rounded-lg border border-gray-200 shadow-sm p-8 min-h-[500px]"
            >
              <ComplianceGraph
                viewMode="supply-chain"
                vendors={evidenceData.vendors}
                controls={evidenceData.controls}
                risks={evidenceData.risks}
                onNodeClick={handleNodeClick}
              />
            </div>
          </TabsContent>

          {/* Tab Content - Risk-Control Graph */}
          <TabsContent value="risk-control" className="mt-6">
            <div
              id="graph-container"
              className="bg-white rounded-lg border border-gray-200 shadow-sm p-8 min-h-[500px]"
            >
              <ComplianceGraph
                viewMode="risk-control"
                vendors={evidenceData.vendors}
                controls={evidenceData.controls}
                risks={evidenceData.risks}
                onNodeClick={handleNodeClick}
              />
            </div>
          </TabsContent>
        </Tabs>

        {/* Tip Box */}
        <div className="mt-4 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-800">
            <strong>💡 Tip:</strong> Click on vendor, control, or risk nodes to see detailed requirements, risks, and raw JSON data.
            Use scroll to zoom and drag to pan the graph.
          </p>
        </div>
      </div>
        )}

        {/* Vendor Cards Section */}
        <div className="mt-12">
          <h2 className="text-2xl font-bold text-gray-900 mb-6">
            Vendors
            {demoVendors.length > 0 && (
              <span className="ml-2 text-sm font-normal text-blue-600">
                ({demoVendors.length} from demo)
              </span>
            )}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {allVendors.map((vendor) => (
              <VendorCard
                key={vendor.id}
                vendor={vendor}
                onClick={handleVendorClick}
              />
            ))}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-16 py-6">
        <div className="container mx-auto px-6 text-center text-sm text-gray-600">
          <p>CONDUIT Risk Management Dashboard - Built with React, Vite, and Tailwind CSS</p>
        </div>
      </footer>

      {/* Dialogs */}
      <VendorDialog
        vendor={selectedVendor}
        open={vendorDialogOpen}
        onOpenChange={setVendorDialogOpen}
      />
      <ControlDialog
        control={selectedControl}
        vendors={mockEvidence.vendors}
        open={controlDialogOpen}
        onOpenChange={setControlDialogOpen}
      />
      <RiskDialog
        risk={selectedRisk}
        controls={mockEvidence.controls}
        vendors={allVendors}
        open={riskDialogOpen}
        onOpenChange={setRiskDialogOpen}
      />
    </div>
  )
}

export default App
