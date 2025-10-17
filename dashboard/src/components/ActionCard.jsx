/**
 * Action Card - Shows action button to add to dashboard
 */
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Button } from './ui/button'
import { BarChart3, Download } from 'lucide-react'

const ActionCard = ({ data, onAddToDashboard }) => {
  const handleAddToDashboard = () => {
    if (onAddToDashboard && data) {
      onAddToDashboard(data)
    }
  }

  const handleDownloadJSON = () => {
    const json = JSON.stringify(data, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${data.vendor_name.toLowerCase().replace(/\s+/g, '_')}_evidence.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex justify-start mb-4"
    >
      <Card className="p-4 max-w-2xl bg-gradient-to-r from-green-50 to-blue-50">
        <div className="flex items-center gap-2 mb-3">
          <BarChart3 className="w-5 h-5 text-green-600" />
          <span className="font-semibold text-green-900">Evidence Ready!</span>
        </div>

        <p className="text-sm text-gray-700 mb-4">
          ✅ Evidence has been extracted and validated. Add it to the dashboard to see it visualized alongside other vendors.
        </p>

        <div className="flex gap-3">
          <Button
            onClick={handleAddToDashboard}
            className="bg-blue-600 hover:bg-blue-700 text-white"
          >
            <BarChart3 className="w-4 h-4 mr-2" />
            Add to Dashboard
          </Button>

          <Button
            onClick={handleDownloadJSON}
            variant="outline"
          >
            <Download className="w-4 h-4 mr-2" />
            Download JSON
          </Button>
        </div>
      </Card>
    </motion.div>
  )
}

export default ActionCard
