import PropTypes from 'prop-types'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { CheckCircle, XCircle } from 'lucide-react'
import { getControlAvgCompliance } from '@/lib/utils'

/**
 * ControlDialog Component
 *
 * Shows control details and all vendors evaluated against this control.
 * Displays average compliance and per-vendor breakdown.
 */
function ControlDialog({ control, vendors, open, onOpenChange }) {
  if (!control) return null

  // Get all vendors that have this control
  const vendorsWithControl = vendors.filter(v =>
    v.controls.some(c => c.id === control.id)
  )

  // Calculate average compliance across all vendors
  const avgCompliance = getControlAvgCompliance(control.id, vendors)

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
          <DialogTitle className="text-2xl">
            Control #{control.id}: {control.name}
          </DialogTitle>
          <DialogDescription>
            Control details and vendor evaluations
          </DialogDescription>
        </DialogHeader>

        {/* Control Summary */}
        <div className="bg-gray-50 rounded-lg p-4 mt-4">
          <div className="space-y-2">
            <div className="flex items-center gap-4 text-sm text-gray-700">
              <div>
                <strong>Category:</strong> {control.category}
              </div>
              <div className="flex items-center gap-2">
                <strong>Criticality:</strong>
                <Badge variant={getCriticalityVariant(control.criticality)}>
                  {control.criticality}
                </Badge>
              </div>
            </div>
            <div className="text-sm text-gray-700">
              <strong>Average Compliance:</strong>{' '}
              <span className="text-2xl font-bold text-gray-900">{avgCompliance}%</span>
            </div>
            <div className="text-sm text-gray-700">
              <strong>Vendors Evaluated:</strong> {vendorsWithControl.length}
            </div>
          </div>
        </div>

        {/* Vendor Evaluations */}
        <div className="mt-6 space-y-4">
          <h3 className="text-lg font-semibold text-gray-900">Vendor Evaluations</h3>

          {vendorsWithControl.map((vendor) => {
            const ctrl = vendor.controls.find(c => c.id === control.id)
            if (!ctrl) return null

            const statusColor = ctrl.percentage >= 85 ? 'text-green-600' :
                               ctrl.percentage >= 50 ? 'text-yellow-600' :
                               'text-red-600'

            return (
              <div key={vendor.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between mb-3">
                  <h4 className="font-semibold text-gray-900">{vendor.name}</h4>
                  <div className="text-right">
                    <div className={`text-3xl font-bold ${statusColor}`}>
                      {ctrl.percentage.toFixed(1)}%
                    </div>
                    <p className="text-xs text-gray-600">
                      {ctrl.passed}/{ctrl.total} passed
                    </p>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="w-full bg-gray-200 rounded-full h-2 mb-3">
                  <div
                    className={`h-2 rounded-full ${
                      ctrl.percentage >= 85 ? 'bg-green-500' :
                      ctrl.percentage >= 50 ? 'bg-yellow-500' :
                      'bg-red-500'
                    }`}
                    style={{ width: `${ctrl.percentage}%` }}
                  />
                </div>

                {/* Requirements List */}
                <div className="space-y-1">
                  {ctrl.requirements?.map((req, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-sm">
                      {req.status === 'passed' ? (
                        <CheckCircle className="h-4 w-4 text-green-600 mt-0.5" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-600 mt-0.5" />
                      )}
                      <p className="text-gray-700">{req.name}</p>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      </DialogContent>
    </Dialog>
  )
}

ControlDialog.propTypes = {
  control: PropTypes.shape({
    id: PropTypes.number.isRequired,
    name: PropTypes.string.isRequired,
    category: PropTypes.string.isRequired,
    criticality: PropTypes.oneOf(['critical', 'high', 'medium', 'low']).isRequired,
  }),
  vendors: PropTypes.arrayOf(PropTypes.object).isRequired,
  open: PropTypes.bool.isRequired,
  onOpenChange: PropTypes.func.isRequired,
}

export default ControlDialog
