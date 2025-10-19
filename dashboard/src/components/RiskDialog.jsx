import { useState } from 'react'
import PropTypes from 'prop-types'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { AlertTriangle, ChevronDown, ChevronUp, CheckCircle, XCircle } from 'lucide-react'

/**
 * RiskDialog Component
 *
 * Shows risk details, severity, description, and affected controls with compliance data.
 */
function RiskDialog({ risk, controls, vendors, open, onOpenChange }) {
  const [expandedControls, setExpandedControls] = useState({})

  if (!risk) return null

  // Get severity variant
  const getSeverityVariant = (severity) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'warning'
      case 'low': return 'secondary'
      default: return 'default'
    }
  }

  // Get compliance status badge variant
  const getComplianceVariant = (percentage) => {
    if (percentage >= 85) return 'default' // green
    if (percentage >= 50) return 'warning' // yellow
    return 'destructive' // red
  }

  // Get compliance status text
  const getComplianceStatus = (percentage) => {
    if (percentage >= 85) return 'Compliant'
    if (percentage >= 50) return 'Partially Compliant'
    return 'Non-Compliant'
  }

  // Toggle failed requirements expansion for a control
  const toggleControl = (controlId) => {
    setExpandedControls(prev => ({ ...prev, [controlId]: !prev[controlId] }))
  }

  // Aggregate control data across all vendors
  const getControlAggregateData = (controlId) => {
    const vendorsWithControl = vendors.filter(v =>
      v.controls.some(c => c.id === controlId)
    )

    if (vendorsWithControl.length === 0) {
      return {
        avgCompliance: 0,
        totalPassed: 0,
        totalRequirements: 0,
        allFailedRequirements: [],
        vendorCount: 0
      }
    }

    let totalPassed = 0
    let totalRequirements = 0
    const allFailedRequirements = []

    vendorsWithControl.forEach(vendor => {
      const control = vendor.controls.find(c => c.id === controlId)
      if (control) {
        totalPassed += control.passed
        totalRequirements += control.total

        // Collect failed requirements
        const failedReqs = (control.requirements || [])
          .filter(req => !req.passed)
          .map(req => ({
            vendor: vendor.name,
            requirement: req.name,
            detail: req.detail
          }))
        allFailedRequirements.push(...failedReqs)
      }
    })

    const avgCompliance = totalRequirements > 0
      ? ((totalPassed / totalRequirements) * 100).toFixed(1)
      : 0

    return {
      avgCompliance: parseFloat(avgCompliance),
      totalPassed,
      totalRequirements,
      allFailedRequirements,
      vendorCount: vendorsWithControl.length
    }
  }

  // Calculate risk impact summary
  const calculateRiskImpact = () => {
    const controlData = risk.affectedControls.map(controlId => {
      const control = controls.find(c => c.id === controlId)
      const data = getControlAggregateData(controlId)
      return {
        controlId,
        controlName: control?.name || 'Unknown',
        compliance: data.avgCompliance,
        failedCount: data.allFailedRequirements.length
      }
    })

    const avgCompliance = controlData.length > 0
      ? (controlData.reduce((sum, c) => sum + c.compliance, 0) / controlData.length).toFixed(1)
      : 0

    const highestRiskControl = controlData.reduce((lowest, current) =>
      current.compliance < lowest.compliance ? current : lowest
    , controlData[0] || { compliance: 100 })

    return {
      avgCompliance: parseFloat(avgCompliance),
      highestRiskControl,
      totalFailures: controlData.reduce((sum, c) => sum + c.failedCount, 0)
    }
  }

  const riskImpact = calculateRiskImpact()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto bg-white text-gray-900">
        <DialogHeader>
          <DialogTitle className="text-2xl flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-red-600" />
            {risk.name}
          </DialogTitle>
          <DialogDescription>
            Risk details and mitigation controls
          </DialogDescription>
        </DialogHeader>

        {/* Risk Summary */}
        <div className="bg-red-50 rounded-lg p-4 mt-4 border border-red-200">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <strong className="text-sm text-gray-900">Severity:</strong>
              <Badge variant={getSeverityVariant(risk.severity)}>
                {risk.severity}
              </Badge>
            </div>
            <p className="text-sm text-gray-700 mt-2">
              {risk.description}
            </p>
          </div>
        </div>

        {/* Risk Impact Summary */}
        <div className="mt-6 p-4 bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg border border-blue-200">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Risk Impact Summary</h3>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-gray-600 text-xs">Avg Compliance</p>
              <p className="text-2xl font-bold text-gray-900">{riskImpact.avgCompliance}%</p>
            </div>
            <div>
              <p className="text-gray-600 text-xs">Total Failures</p>
              <p className="text-2xl font-bold text-red-600">{riskImpact.totalFailures}</p>
            </div>
            <div>
              <p className="text-gray-600 text-xs">Highest Risk</p>
              <p className="text-sm font-semibold text-gray-900">
                Control #{riskImpact.highestRiskControl?.controlId}
              </p>
              <p className="text-xs text-gray-600">{riskImpact.highestRiskControl?.compliance}% compliant</p>
            </div>
          </div>
        </div>

        {/* Control Compliance Cards */}
        <div className="mt-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Affected Controls ({risk.affectedControls.length})
          </h3>
          <div className="space-y-4">
            {risk.affectedControls.map((controlId) => {
              const control = controls.find(c => c.id === controlId)
              if (!control) return null

              const data = getControlAggregateData(controlId)
              const compliance = data.avgCompliance
              const hasFailures = data.allFailedRequirements.length > 0

              return (
                <div
                  key={controlId}
                  className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
                >
                  {/* Control Header */}
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex-1">
                      <h4 className="font-semibold text-gray-900">
                        Control #{controlId}: {control.name}
                      </h4>
                      <p className="text-xs text-gray-500 mt-1">
                        {data.vendorCount} vendor{data.vendorCount !== 1 ? 's' : ''} assessed
                      </p>
                    </div>
                    <Badge variant={getComplianceVariant(compliance)}>
                      {getComplianceStatus(compliance)}
                    </Badge>
                  </div>

                  {/* Progress Bar */}
                  <div className="mb-3">
                    <div className="flex items-center justify-between text-xs text-gray-600 mb-1">
                      <span>{data.totalPassed}/{data.totalRequirements} requirements passed</span>
                      <span className="font-semibold">{compliance}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${
                          compliance >= 85 ? 'bg-green-500' :
                          compliance >= 50 ? 'bg-yellow-500' :
                          'bg-red-500'
                        }`}
                        style={{ width: `${compliance}%` }}
                      />
                    </div>
                  </div>

                  {/* Failed Requirements Section */}
                  {hasFailures && (
                    <div className="mt-3 border-t border-gray-200 pt-3">
                      <button
                        onClick={() => toggleControl(controlId)}
                        className="flex items-center gap-1 text-sm font-medium text-red-600 hover:text-red-700 transition-colors"
                      >
                        {expandedControls[controlId] ? (
                          <>
                            <ChevronUp className="h-4 w-4" />
                            <span>Hide {data.allFailedRequirements.length} Failed Requirement{data.allFailedRequirements.length !== 1 ? 's' : ''}</span>
                          </>
                        ) : (
                          <>
                            <ChevronDown className="h-4 w-4" />
                            <span>View {data.allFailedRequirements.length} Failed Requirement{data.allFailedRequirements.length !== 1 ? 's' : ''}</span>
                          </>
                        )}
                      </button>

                      {expandedControls[controlId] && (
                        <div className="mt-3 space-y-3">
                          {data.allFailedRequirements.map((failedReq, idx) => (
                            <div
                              key={idx}
                              className="bg-red-50 border-l-4 border-red-400 p-3 rounded"
                            >
                              <div className="flex items-start gap-2">
                                <XCircle className="h-4 w-4 text-red-600 mt-0.5 flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <p className="text-sm font-medium text-red-900">
                                    {failedReq.requirement}
                                  </p>
                                  <p className="text-xs text-red-700 mt-1">
                                    {failedReq.detail}
                                  </p>
                                  <p className="text-xs text-gray-600 mt-1">
                                    <strong>Vendor:</strong> {failedReq.vendor}
                                  </p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* All Passed Indicator */}
                  {!hasFailures && (
                    <div className="mt-3 flex items-center gap-2 text-sm text-green-700 bg-green-50 rounded p-2">
                      <CheckCircle className="h-4 w-4" />
                      <span>All requirements passed across all vendors</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Mitigation Guidance */}
        <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <strong className="text-sm text-blue-900">💡 Mitigation Strategy:</strong>
          <p className="text-sm text-blue-800 mt-2">
            These controls are designed to mitigate this risk. Priority should be given to
            Control #{riskImpact.highestRiskControl?.controlId} ({riskImpact.highestRiskControl?.controlName})
            which has the lowest compliance at {riskImpact.highestRiskControl?.compliance}%.
            Address the {riskImpact.totalFailures} failed requirement{riskImpact.totalFailures !== 1 ? 's' : ''} above to reduce risk exposure.
          </p>
        </div>
      </DialogContent>
    </Dialog>
  )
}

RiskDialog.propTypes = {
  risk: PropTypes.shape({
    id: PropTypes.string.isRequired,
    name: PropTypes.string.isRequired,
    severity: PropTypes.oneOf(['critical', 'high', 'medium', 'low']).isRequired,
    description: PropTypes.string.isRequired,
    affectedControls: PropTypes.arrayOf(PropTypes.number).isRequired,
  }),
  controls: PropTypes.arrayOf(PropTypes.object).isRequired,
  vendors: PropTypes.arrayOf(PropTypes.object).isRequired,
  open: PropTypes.bool.isRequired,
  onOpenChange: PropTypes.func.isRequired,
}

export default RiskDialog
