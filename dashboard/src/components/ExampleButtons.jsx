/**
 * Example Buttons Grid - Clickable example selector
 */
import { Button } from './ui/button'
import { CheckCircle, XCircle, Shield, Lock, AlertTriangle } from 'lucide-react'
import { demoExamples } from '@/data/demoExamples'

const ExampleButtons = ({ onSelect, disabled }) => {
  const getIcon = (example) => {
    const hasXIcon = example.title.includes('✗')
    const hasCheckIcon = example.title.includes('✓')

    if (example.category === 'vulnerability') {
      return Shield
    } else if (example.category === 'sso_mfa') {
      return Lock
    } else if (example.id === 'edge_case_missing_data') {
      return AlertTriangle
    } else if (hasCheckIcon) {
      return CheckCircle
    } else if (hasXIcon) {
      return XCircle
    }
    return CheckCircle
  }

  const getColor = (example) => {
    if (example.title.includes('✗')) {
      return 'text-red-500'
    } else if (example.title.includes('✓')) {
      return 'text-green-500'
    }
    return 'text-gray-500'
  }

  const examples = Object.values(demoExamples)

  return (
    <div className="space-y-4">
      <div className="text-sm text-gray-600">
        Click an example below to see the complete CONDUIT workflow:
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {examples.map((example) => {
          const Icon = getIcon(example)
          const colorClass = getColor(example)

          return (
            <Button
              key={example.id}
              onClick={() => onSelect(example.id)}
              disabled={disabled}
              variant="outline"
              className="h-auto py-4 px-4 flex flex-col items-start text-left hover:border-blue-300 hover:bg-blue-50 transition-colors"
            >
              <div className="flex items-center gap-2 mb-1 w-full">
                <Icon className={`w-5 h-5 ${colorClass} flex-shrink-0`} />
                <span className="font-semibold text-sm">{example.title}</span>
              </div>
              <span className="text-xs text-gray-500 mt-1">
                {example.description}
              </span>
            </Button>
          )
        })}
      </div>

      <div className="text-xs text-gray-500 bg-blue-50 p-3 rounded border border-blue-200">
        ℹ️ <strong>Note:</strong> These are pre-computed demo examples. To extract from your own text,
        install the CLI: <code className="bg-white px-1 py-0.5 rounded">pip install conduit</code>
      </div>
    </div>
  )
}

export default ExampleButtons
