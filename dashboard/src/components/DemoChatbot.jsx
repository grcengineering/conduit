/**
 * Demo Chatbot - Interactive CONDUIT workflow demonstration
 *
 * Shows the complete 5-step workflow using pre-computed examples
 */
import { useState } from 'react'
import { motion } from 'framer-motion'
import { Card } from './ui/card'
import { Sparkles } from 'lucide-react'
import StepProgress from './StepProgress'
import ChatMessage from './ChatMessage'
import ExampleButtons from './ExampleButtons'
import { demoExamples } from '@/data/demoExamples'

// Sleep utility for animation delays
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

const DemoChatbot = ({ onAddVendor }) => {
  const [messages, setMessages] = useState([
    {
      type: 'bot',
      content: '👋 Welcome to the CONDUIT live demo! I\'ll show you how we transform unstructured vendor text into validated evidence with compliance scoring.',
      timestamp: Date.now()
    }
  ])

  const [currentStep, setCurrentStep] = useState(0)
  const [isProcessing, setIsProcessing] = useState(false)

  const addMessage = (message) => {
    setMessages(prev => [...prev, { ...message, timestamp: Date.now() }])
  }

  const runDemo = async (exampleId) => {
    const demo = demoExamples[exampleId]
    if (!demo) return

    setIsProcessing(true)

    // Clear previous demo messages (keep welcome message)
    setMessages([{
      type: 'bot',
      content: '👋 Welcome to the CONDUIT live demo! I\'ll show you how we transform unstructured vendor text into validated evidence with compliance scoring.',
      timestamp: Date.now()
    }])

    setCurrentStep(0)

    // Small delay before starting
    await sleep(500)

    // Step 1: Show input text
    setCurrentStep(1)
    addMessage({
      type: 'user',
      content: demo.inputText
    })

    // Step 2: Extraction (1.5s delay)
    await sleep(1500)
    setCurrentStep(2)
    addMessage({
      type: 'bot',
      subtype: 'extraction',
      content: '🤖 Extraction complete! Here\'s what I found:',
      data: demo.extraction
    })

    // Step 3: Validation (1s delay)
    await sleep(1000)
    setCurrentStep(3)
    addMessage({
      type: 'bot',
      subtype: 'validation',
      content: '🛡️ Validation complete! Checking business rules:',
      data: demo.validation
    })

    // Step 4: Compliance (0.5s delay)
    await sleep(500)
    setCurrentStep(4)
    addMessage({
      type: 'bot',
      subtype: 'compliance',
      content: '📊 Compliance calculated:',
      data: demo.compliance
    })

    // Step 5: Action (0.5s delay)
    await sleep(500)
    setCurrentStep(5)
    addMessage({
      type: 'bot',
      subtype: 'action',
      content: '✅ Evidence validated and ready to visualize!',
      data: demo.dashboardData
    })

    setIsProcessing(false)
  }

  const handleAddToDashboard = (dashboardData) => {
    if (onAddVendor) {
      onAddVendor(dashboardData)

      // Show success message
      addMessage({
        type: 'bot',
        content: `✅ Success! ${dashboardData.vendor_name} has been added to the dashboard. Switch to the "Vendor-Control View" tab to see it visualized.`
      })
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center">
            <Sparkles className="w-6 h-6 text-white" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">CONDUIT Live Demo</h2>
            <p className="text-sm text-gray-600">Interactive extraction & validation workflow</p>
          </div>
        </div>
      </div>

      {/* Step Progress */}
      <Card className="p-4 mb-6">
        <StepProgress currentStep={currentStep} />
      </Card>

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto mb-6 space-y-4">
        {messages.map((message, idx) => (
          <ChatMessage
            key={`${message.timestamp}-${idx}`}
            message={message}
            onAddToDashboard={handleAddToDashboard}
          />
        ))}

        {/* Processing indicator */}
        {isProcessing && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex justify-start"
          >
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                >
                  <Sparkles className="w-5 h-5 text-gray-600" />
                </motion.div>
              </div>
              <Card className="p-3 bg-gray-50">
                <p className="text-sm text-gray-600">Processing...</p>
              </Card>
            </div>
          </motion.div>
        )}
      </div>

      {/* Example Buttons */}
      <div className="border-t pt-6">
        <ExampleButtons onSelect={runDemo} disabled={isProcessing} />
      </div>
    </div>
  )
}

export default DemoChatbot
