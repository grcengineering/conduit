import { motion } from 'framer-motion'
import PropTypes from 'prop-types'
import { AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { getVendorCompliance } from '@/lib/utils'

/**
 * VendorCard Component
 *
 * Displays a vendor's compliance information in a card format.
 * Shows vendor name, criticality, risk score, compliance percentage, and controls summary.
 *
 * Features:
 * - Clickable card with hover effect
 * - Color-coded criticality badges
 * - Risk score visualization
 * - Compliance percentage with visual indicator
 * - Controls evaluation summary
 * - Framer Motion hover animation
 *
 * @param {object} props - Component props
 * @param {object} props.vendor - Vendor data object
 * @param {string} props.vendor.id - Vendor ID
 * @param {string} props.vendor.name - Vendor name
 * @param {string} props.vendor.criticality - Vendor criticality (critical, high, medium, low)
 * @param {number} props.vendor.riskScore - Risk score (0-1)
 * @param {Array} props.vendor.controls - Array of control objects
 * @param {Function} [props.onClick] - Optional click handler
 *
 * @example
 * <VendorCard
 *   vendor={vendorData}
 *   onClick={(vendor) => console.log('Clicked:', vendor)}
 * />
 */
function VendorCard({ vendor, onClick }) {
  // Calculate overall compliance percentage from vendor controls
  const compliancePercentage = parseFloat(getVendorCompliance(vendor))

  // Calculate totals for controls summary
  const totalControls = vendor.controls.length
  const totalRequirements = vendor.controls.reduce((sum, c) => sum + c.total, 0)
  const passedRequirements = vendor.controls.reduce((sum, c) => sum + c.passed, 0)

  /**
   * Get badge variant based on criticality level
   * Returns the appropriate color scheme for the criticality badge
   */
  const getCriticalityVariant = (criticality) => {
    switch (criticality) {
      case 'critical':
        return 'destructive'
      case 'high':
        return 'warning'
      case 'medium':
        return 'default'
      case 'low':
        return 'secondary'
      default:
        return 'default'
    }
  }

  /**
   * Get compliance status icon and color
   * Returns icon component and color based on compliance percentage
   */
  const getComplianceIcon = () => {
    if (compliancePercentage >= 85) {
      return { icon: CheckCircle, color: 'text-green-500' }
    } else if (compliancePercentage >= 50) {
      return { icon: AlertTriangle, color: 'text-yellow-500' }
    } else {
      return { icon: XCircle, color: 'text-red-500' }
    }
  }

  const { icon: ComplianceIcon, color: complianceColor } = getComplianceIcon()

  /**
   * Get color class for compliance percentage text
   */
  const getComplianceColor = () => {
    if (compliancePercentage >= 85) return 'text-green-600'
    if (compliancePercentage >= 50) return 'text-yellow-600'
    return 'text-red-600'
  }

  return (
    <motion.div
      // Hover animation: slight scale up and shadow increase
      whileHover={{ scale: 1.02, y: -4 }}
      transition={{ duration: 0.2 }}
      onClick={() => onClick && onClick(vendor)}
      className="cursor-pointer"
    >
      <Card className="h-full hover:shadow-lg transition-shadow">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div className="flex-1">
              {/* Vendor Name */}
              <CardTitle className="text-lg">{vendor.name}</CardTitle>

              {/* Risk Score */}
              <CardDescription className="mt-1">
                Risk Score: <span className="font-semibold">{(vendor.riskScore * 100).toFixed(0)}%</span>
              </CardDescription>
            </div>

            {/* Criticality Badge */}
            <Badge variant={getCriticalityVariant(vendor.criticality)}>
              {vendor.criticality.toUpperCase()}
            </Badge>
          </div>
        </CardHeader>

        <CardContent>
          {/* Compliance Percentage Section */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ComplianceIcon className={`h-5 w-5 ${complianceColor}`} />
              <span className={`text-2xl font-bold ${getComplianceColor()}`}>
                {compliancePercentage}%
              </span>
            </div>
            <span className="text-sm text-muted-foreground">Compliance</span>
          </div>

          {/* Visual Progress Bar */}
          <div className="w-full bg-gray-200 rounded-full h-2 mb-4">
            <div
              className={`h-2 rounded-full transition-all ${
                compliancePercentage >= 85
                  ? 'bg-green-500'
                  : compliancePercentage >= 50
                  ? 'bg-yellow-500'
                  : 'bg-red-500'
              }`}
              style={{ width: `${compliancePercentage}%` }}
            />
          </div>

          {/* Controls Summary */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground">Controls Evaluated</p>
              <p className="font-semibold">{totalControls}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Requirements</p>
              <p className="font-semibold">
                {passedRequirements}/{totalRequirements} passed
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}

VendorCard.propTypes = {
  vendor: PropTypes.shape({
    id: PropTypes.string.isRequired,
    name: PropTypes.string.isRequired,
    criticality: PropTypes.oneOf(['critical', 'high', 'medium', 'low']).isRequired,
    riskScore: PropTypes.number.isRequired,
    controls: PropTypes.arrayOf(
      PropTypes.shape({
        id: PropTypes.number.isRequired,
        name: PropTypes.string.isRequired,
        passed: PropTypes.number.isRequired,
        total: PropTypes.number.isRequired,
        percentage: PropTypes.number.isRequired,
      })
    ).isRequired,
  }).isRequired,
  onClick: PropTypes.func,
}

export default VendorCard
