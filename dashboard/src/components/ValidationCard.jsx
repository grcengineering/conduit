/**
 * Validation Card - Shows pass/fail validation checks
 */
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { ShieldCheck, CheckCircle, XCircle, AlertCircle } from 'lucide-react'

const ValidationCard = ({ checks }) => {
  const allPassed = checks.every(check => check.passed)

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-start mb-4"
    >
      <Card className={`p-4 max-w-2xl ${allPassed ? 'bg-green-50' : 'bg-red-50'}`}>
        <div className="flex items-center gap-2 mb-3">
          <ShieldCheck className={`w-5 h-5 ${allPassed ? 'text-green-600' : 'text-red-600'}`} />
          <span className={`font-semibold ${allPassed ? 'text-green-900' : 'text-red-900'}`}>
            Validation {allPassed ? 'Passed' : 'Failed'}
          </span>
        </div>

        <div className="space-y-3">
          {checks.map((check, idx) => (
            <div key={idx} className="flex gap-3">
              {check.passed ? (
                <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              )}

              <div className="flex-1">
                <div className={`font-medium text-sm ${check.passed ? 'text-green-900' : 'text-red-900'}`}>
                  {check.rule}
                </div>
                <div className="text-xs text-gray-600 mt-1">
                  {check.detail}
                </div>
                {check.error && (
                  <div className="flex items-start gap-1 mt-1 text-xs text-red-700 bg-red-100 p-2 rounded">
                    <AlertCircle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                    <span>{check.error}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </motion.div>
  )
}

export default ValidationCard
