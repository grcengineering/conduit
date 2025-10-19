import { useState } from 'react'
import PropTypes from 'prop-types'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { CheckCircle, AlertTriangle, XCircle, ChevronDown, ChevronUp } from 'lucide-react'

/**
 * VendorDialog Component
 *
 * Full-featured dialog matching vanilla dashboard functionality.
 * Shows: compliance, requirements list, risks, metadata, and raw JSON dropdown.
 */
function VendorDialog({ vendor, open, onOpenChange }) {
  // Track which control's JSON is expanded
  const [expandedJson, setExpandedJson] = useState({})

  if (!vendor) return null

  // Calculate overall compliance
  const totalPassed = vendor.controls.reduce((sum, c) => sum + c.passed, 0)
  const totalRequirements = vendor.controls.reduce((sum, c) => sum + c.total, 0)
  const compliance = ((totalPassed / totalRequirements) * 100).toFixed(1)

  // Toggle XML expansion for a control
  const toggleJson = (controlId) => {
    setExpandedJson(prev => ({ ...prev, [controlId]: !prev[controlId] }))
  }

  // Convert structured data to XML format (mimics backend XML extraction)
  const convertToXML = (structuredData) => {
    if (!structuredData) return ''

    const evidenceType = structuredData.evidence_type || 'unknown_evidence'
    let xml = `<${evidenceType}>\n`

    // Recursively convert object to XML
    const objectToXML = (obj, indent = '  ') => {
      let result = ''
      for (const [key, value] of Object.entries(obj)) {
        if (key === 'evidence_type') continue // Already used as root element

        if (Array.isArray(value)) {
          // Handle arrays
          result += `${indent}<${key}>\n`
          value.forEach(item => {
            if (typeof item === 'object') {
              result += `${indent}  <item>\n`
              result += objectToXML(item, indent + '    ')
              result += `${indent}  </item>\n`
            } else {
              result += `${indent}  <item>${item}</item>\n`
            }
          })
          result += `${indent}</${key}>\n`
        } else if (typeof value === 'object' && value !== null) {
          // Handle nested objects
          result += `${indent}<${key}>\n`
          result += objectToXML(value, indent + '  ')
          result += `${indent}</${key}>\n`
        } else {
          // Handle primitives
          result += `${indent}<${key}>${value}</${key}>\n`
        }
      }
      return result
    }

    xml += objectToXML(structuredData)
    xml += `</${evidenceType}>`
    return xml
  }

  // Get status icon and color
  const getStatusInfo = (status) => {
    switch (status) {
      case 'compliant':
        return { icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-50', label: 'Compliant' }
      case 'partially_compliant':
        return { icon: AlertTriangle, color: 'text-yellow-600', bg: 'bg-yellow-50', label: 'Partially Compliant' }
      default:
        return { icon: XCircle, color: 'text-red-600', bg: 'bg-red-50', label: 'Non-Compliant' }
    }
  }

  // Get criticality variant
  const getCriticalityVariant = (criticality) => {
    switch (criticality) {
      case 'critical': return 'destructive'
      case 'high': return 'warning'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'default'
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto bg-white text-gray-900">
        <DialogHeader>
          <DialogTitle className="text-2xl">{vendor.name}</DialogTitle>
          <DialogDescription>
            Detailed compliance and control information
          </DialogDescription>
        </DialogHeader>

        {/* Vendor Summary */}
        <div className="bg-gray-50 rounded-lg p-4 mt-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Vendor ID: {vendor.id}</h3>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-sm text-gray-600">Criticality:</span>
                <Badge variant={getCriticalityVariant(vendor.criticality)}>
                  {vendor.criticality}
                </Badge>
              </div>
            </div>
            <div className="text-right">
              <div className="text-4xl font-bold text-gray-900">{compliance}%</div>
              <p className="text-xs text-gray-600">overall compliance</p>
            </div>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-4 text-sm text-gray-700">
            <div>
              <strong>Requirements:</strong> {totalPassed}/{totalRequirements} passed
            </div>
            <div>
              <strong>Risk Score:</strong> {(vendor.riskScore * 100).toFixed(0)}%
            </div>
            <div>
              <strong>Controls:</strong> {vendor.controls.length} evaluated
            </div>
            <div>
              <strong>Subprocessors:</strong> {vendor.subprocessors?.length || 0}
            </div>
          </div>
        </div>

        {/* Controls Breakdown */}
        <div className="mt-6 space-y-4">
          <h3 className="text-lg font-semibold text-gray-900">Controls Evaluation</h3>

          {vendor.controls.map((control) => {
            const statusInfo = getStatusInfo(control.status)
            const StatusIcon = statusInfo.icon

            return (
              <div key={control.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-semibold text-gray-900">
                    Control #{control.id}: {control.name}
                  </h4>
                  <div className={`flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${statusInfo.bg} ${statusInfo.color}`}>
                    <StatusIcon className="h-3 w-3" />
                    <span>{statusInfo.label}</span>
                  </div>
                </div>

                <div className="flex items-center justify-between text-sm text-gray-700 mb-3">
                  <span>
                    <strong>Requirements:</strong> {control.passed}/{control.total} passed
                  </span>
                  <span>
                    <strong>Compliance:</strong> {control.percentage.toFixed(1)}%
                  </span>
                </div>

                {/* Progress Bar */}
                <div className="w-full bg-gray-200 rounded-full h-2 mb-3">
                  <div
                    className={`h-2 rounded-full ${
                      control.percentage >= 85 ? 'bg-green-500' :
                      control.percentage >= 50 ? 'bg-yellow-500' :
                      'bg-red-500'
                    }`}
                    style={{ width: `${control.percentage}%` }}
                  />
                </div>

                {/* Requirements List */}
                <div className="space-y-2 mt-3">
                  <p className="text-xs font-semibold text-gray-700 uppercase">Requirements:</p>
                  {control.requirements?.map((req, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-sm">
                      <span className={`${req.passed ? 'text-green-600' : 'text-red-600'} font-bold flex-shrink-0`}>
                        {req.passed ? '✓' : '✗'}
                      </span>
                      <div className="flex-1">
                        <p className={`font-medium ${req.passed ? 'text-gray-700' : 'text-gray-900'}`}>
                          {req.name}
                        </p>
                        {req.detail && (
                          <p className="text-xs text-gray-600 mt-0.5">{req.detail}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Risks */}
                {control.risks && control.risks.length > 0 && (
                  <div className="mt-3 p-2 bg-red-50 rounded text-xs">
                    <strong className="text-red-900">Risks Identified:</strong>
                    <ul className="list-disc list-inside text-red-800 mt-1">
                      {control.risks.map((risk, idx) => (
                        <li key={idx}>{risk}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Metadata: Source, Confidence, SOC2 Overlap */}
                <div className="mt-3 text-xs text-gray-500 space-y-1">
                  <p>
                    <strong>Source:</strong> {control.source_document || 'N/A'}
                  </p>
                  <p>
                    <strong>Confidence:</strong> {control.extraction_confidence ? `${(control.extraction_confidence * 100).toFixed(0)}%` : 'N/A'} |{' '}
                    <strong>SOC 2 Overlap:</strong> {control.soc2_overlap ? `${control.soc2_overlap}%` : 'N/A'}
                  </p>
                </div>

                {/* Extracted XML Dropdown */}
                {control.structuredData && (
                  <div className="mt-3 border-t border-gray-200 pt-3">
                    <button
                      onClick={() => toggleJson(control.id)}
                      className="flex items-center gap-1 text-sm font-medium text-blue-600 hover:text-blue-700 transition-colors"
                    >
                      {expandedJson[control.id] ? (
                        <>
                          <ChevronUp className="h-4 w-4" />
                          <span>Hide Extracted XML</span>
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-4 w-4" />
                          <span>View Extracted XML</span>
                        </>
                      )}
                    </button>

                    {expandedJson[control.id] && (
                      <pre className="mt-2 bg-gray-900 text-green-400 p-3 rounded text-xs overflow-x-auto max-h-96 overflow-y-auto">
                        {convertToXML(control.structuredData)}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </DialogContent>
    </Dialog>
  )
}

VendorDialog.propTypes = {
  vendor: PropTypes.shape({
    id: PropTypes.string.isRequired,
    name: PropTypes.string.isRequired,
    criticality: PropTypes.oneOf(['critical', 'high', 'medium', 'low']).isRequired,
    riskScore: PropTypes.number.isRequired,
    subprocessors: PropTypes.arrayOf(PropTypes.string),
    controls: PropTypes.arrayOf(
      PropTypes.shape({
        id: PropTypes.number.isRequired,
        name: PropTypes.string.isRequired,
        passed: PropTypes.number.isRequired,
        total: PropTypes.number.isRequired,
        percentage: PropTypes.number.isRequired,
        status: PropTypes.oneOf(['compliant', 'partially_compliant', 'non_compliant']).isRequired,
        requirements: PropTypes.arrayOf(
          PropTypes.shape({
            name: PropTypes.string.isRequired,
            status: PropTypes.string.isRequired,
            evidence: PropTypes.string,
          })
        ),
        risks: PropTypes.arrayOf(PropTypes.string),
      })
    ).isRequired,
  }),
  open: PropTypes.bool.isRequired,
  onOpenChange: PropTypes.func.isRequired,
}

export default VendorDialog
