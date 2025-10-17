/**
 * Compliance Card - Shows compliance percentage and status
 */
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Calculator, TrendingUp, TrendingDown } from 'lucide-react'

const ComplianceCard = ({ percentage, passed, total, status, note }) => {
  const isCompliant = status === 'compliant'
  const isPartial = status === 'partially_compliant'

  let statusColor = 'bg-red-100 text-red-800'
  let statusText = 'Non-Compliant'
  let icon = TrendingDown

  if (isCompliant) {
    statusColor = 'bg-green-100 text-green-800'
    statusText = 'Compliant'
    icon = TrendingUp
  } else if (isPartial) {
    statusColor = 'bg-yellow-100 text-yellow-800'
    statusText = 'Partially Compliant'
    icon = TrendingUp
  }

  const Icon = icon

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-start mb-4"
    >
      <Card className="p-4 max-w-2xl bg-blue-50">
        <div className="flex items-center gap-2 mb-3">
          <Calculator className="w-5 h-5 text-blue-600" />
          <span className="font-semibold text-blue-900">Compliance Calculated</span>
        </div>

        <div className="flex items-center gap-6">
          {/* Percentage Circle */}
          <div className="relative">
            <svg className="w-24 h-24 transform -rotate-90">
              {/* Background circle */}
              <circle
                cx="48"
                cy="48"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                fill="none"
                className="text-gray-200"
              />
              {/* Progress circle */}
              <motion.circle
                cx="48"
                cy="48"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                fill="none"
                strokeDasharray={`${2 * Math.PI * 40}`}
                strokeDashoffset={`${2 * Math.PI * 40 * (1 - percentage / 100)}`}
                className={isCompliant ? 'text-green-500' : (isPartial ? 'text-yellow-500' : 'text-red-500')}
                strokeLinecap="round"
                initial={{ strokeDashoffset: 2 * Math.PI * 40 }}
                animate={{ strokeDashoffset: 2 * Math.PI * 40 * (1 - percentage / 100) }}
                transition={{ duration: 1, ease: 'easeOut' }}
              />
            </svg>
            {/* Percentage text */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-900">{percentage}%</div>
              </div>
            </div>
          </div>

          {/* Details */}
          <div className="flex-1">
            <Badge className={`${statusColor} mb-2`}>
              <Icon className="w-3 h-3 mr-1" />
              {statusText}
            </Badge>

            <div className="text-sm text-gray-700 space-y-1">
              <div>
                <span className="font-medium">Requirements Passed:</span>{' '}
                <span className="font-mono">{passed}/{total}</span>
              </div>

              {note && (
                <div className="text-xs text-yellow-700 bg-yellow-50 p-2 rounded mt-2">
                  ⚠️ {note}
                </div>
              )}
            </div>
          </div>
        </div>
      </Card>
    </motion.div>
  )
}

export default ComplianceCard
