/**
 * Extraction Card - Shows extracted fields from AI
 */
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Sparkles } from 'lucide-react'

const ExtractionCard = ({ data }) => {
  // Handle different extraction formats
  const fields = []

  if (data.test_date) {
    // BCP/DR format
    fields.push(
      { label: 'Test Date', value: data.test_date },
      { label: 'Test Result', value: data.test_result },
      { label: 'Test Type', value: data.test_type },
      { label: 'Scope', value: data.scope },
      { label: 'RTO Met', value: data.recovery_time_objective_met !== null ? (data.recovery_time_objective_met ? 'Yes' : 'No') : 'Not specified' }
    )
  } else if (data.scans) {
    // Vulnerability format
    fields.push(
      { label: 'Vulnerability Scans', value: `${data.scans.length} scans in last 90 days` },
      { label: 'Scanner Tool', value: data.scans[0]?.tool || 'Unknown' },
      { label: 'Latest Scan', value: data.scans[0]?.date || 'Unknown' },
      { label: 'Pentest Date', value: data.pentest?.date || 'Not specified' },
      { label: 'Pentest Firm', value: data.pentest?.firm || 'Not specified' }
    )
  } else if (data.sso_available !== undefined) {
    // SSO/MFA format
    fields.push(
      { label: 'SSO Available', value: data.sso_available ? 'Yes' : 'No' },
      { label: 'SSO Paywall', value: data.sso_requires_paid_plan ? 'Yes (Paid Plan Required)' : 'No (Free)' },
      { label: 'SSO Protocols', value: data.sso_protocols?.join(', ') || 'Not specified' },
      { label: 'MFA Available', value: data.mfa_available ? 'Yes' : 'No' },
      { label: 'Phishing-Resistant MFA', value: data.phishing_resistant_mfa_available ? `Yes (${data.phishing_resistant_types?.join(', ')})` : 'No' }
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-start mb-4"
    >
      <Card className="p-4 max-w-2xl bg-gray-50">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-5 h-5 text-blue-500" />
          <span className="font-semibold text-blue-900">Extraction Complete</span>
        </div>

        <div className="space-y-2">
          {fields.map((field, idx) => (
            <div key={idx} className="flex justify-between gap-4 text-sm">
              <span className="text-gray-600 font-medium">{field.label}:</span>
              <span className="text-gray-900 font-mono text-right">{field.value || 'null'}</span>
            </div>
          ))}
        </div>
      </Card>
    </motion.div>
  )
}

export default ExtractionCard
