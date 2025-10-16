import PropTypes from 'prop-types'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { AlertTriangle } from 'lucide-react'

/**
 * RiskDialog Component
 *
 * Shows risk details, severity, description, and affected controls.
 */
function RiskDialog({ risk, controls, open, onOpenChange }) {
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
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

        {/* Affected Controls */}
        <div className="mt-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Affected Controls ({risk.affectedControls.length})
          </h3>
          <div className="border border-gray-200 rounded-lg p-4">
            <div className="space-y-2">
              {risk.affectedControls.map((controlId) => {
                const control = controls.find(c => c.id === controlId)
                if (!control) return null

                return (
                  <div key={controlId} className="flex items-start gap-2 text-sm">
                    <span className="text-blue-600 font-medium">•</span>
                    <p className="text-gray-700">
                      <strong>Control #{controlId}:</strong> {control.name}
                    </p>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Additional Info */}
        <div className="mt-4 p-3 bg-blue-50 rounded text-sm text-blue-800">
          <strong>💡 Mitigation:</strong> These controls are designed to mitigate this risk.
          Ensure all controls are compliant to reduce risk exposure.
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
  open: PropTypes.bool.isRequired,
  onOpenChange: PropTypes.func.isRequired,
}

export default RiskDialog
