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

  const handleDownloadXML = () => {
    // Convert all controls' structured data to XML and combine
    let fullXML = '<?xml version="1.0" encoding="UTF-8"?>\n<vendor_evidence>\n'
    fullXML += `  <vendor_name>${data.vendor_name}</vendor_name>\n`
    fullXML += `  <vendor_id>${data.vendor_id}</vendor_id>\n`
    fullXML += '  <controls>\n'

    data.controls?.forEach(control => {
      if (control.structuredData) {
        const controlXML = convertToXML(control.structuredData)
        // Indent each line by 4 spaces
        const indentedXML = controlXML.split('\n').map(line => '    ' + line).join('\n')
        fullXML += indentedXML + '\n'
      }
    })

    fullXML += '  </controls>\n'
    fullXML += '</vendor_evidence>'

    const blob = new Blob([fullXML], { type: 'application/xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${data.vendor_name.toLowerCase().replace(/\s+/g, '_')}_evidence.xml`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
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
            onClick={handleDownloadXML}
            variant="outline"
            className="border-green-600 text-green-700 hover:bg-green-50"
          >
            <Download className="w-4 h-4 mr-2" />
            Download XML
          </Button>

          <Button
            onClick={handleDownloadJSON}
            variant="outline"
            className="text-gray-600 hover:bg-gray-50"
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
