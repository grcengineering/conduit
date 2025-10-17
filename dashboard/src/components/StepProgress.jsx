/**
 * Step Progress Indicator
 * Shows the 5-step CONDUIT workflow with visual progress
 */
import { FileText, Sparkles, ShieldCheck, Calculator, BarChart3 } from 'lucide-react'
import { motion } from 'framer-motion'

const StepProgress = ({ currentStep = 0 }) => {
  const steps = [
    { num: 1, label: 'Input', icon: FileText, description: 'Raw vendor text' },
    { num: 2, label: 'Extract', icon: Sparkles, description: 'AI extraction' },
    { num: 3, label: 'Validate', icon: ShieldCheck, description: 'Business rules' },
    { num: 4, label: 'Calculate', icon: Calculator, description: 'Compliance %' },
    { num: 5, label: 'Visualize', icon: BarChart3, description: 'Dashboard ready' }
  ]

  return (
    <div className="w-full py-6">
      <div className="flex items-center justify-between relative">
        {/* Progress line background */}
        <div className="absolute left-0 right-0 top-6 h-1 bg-gray-200 -z-10"
             style={{ left: '2.5rem', right: '2.5rem' }} />

        {/* Active progress line */}
        <motion.div
          className="absolute top-6 h-1 bg-blue-500 -z-10"
          style={{ left: '2.5rem' }}
          initial={{ width: 0 }}
          animate={{
            width: currentStep > 0
              ? `calc(${((currentStep - 1) / (steps.length - 1)) * 100}% - 2.5rem)`
              : 0
          }}
          transition={{ duration: 0.5, ease: 'easeInOut' }}
        />

        {steps.map((step, idx) => (
          <StepCircle
            key={step.num}
            {...step}
            active={currentStep === step.num}
            completed={currentStep > step.num}
          />
        ))}
      </div>
    </div>
  )
}

const StepCircle = ({ num, label, icon: Icon, description, active, completed }) => {
  let bgColor = 'bg-gray-200'
  let textColor = 'text-gray-500'
  let iconColor = 'text-gray-400'

  if (completed) {
    bgColor = 'bg-blue-500'
    textColor = 'text-blue-600'
    iconColor = 'text-white'
  } else if (active) {
    bgColor = 'bg-blue-100 ring-4 ring-blue-200'
    textColor = 'text-blue-600'
    iconColor = 'text-blue-600'
  }

  return (
    <div className="flex flex-col items-center relative">
      <motion.div
        className={`w-12 h-12 rounded-full flex items-center justify-center ${bgColor} transition-colors`}
        initial={{ scale: 0.8 }}
        animate={{ scale: active ? 1.1 : 1 }}
        transition={{ duration: 0.3 }}
      >
        <Icon className={`w-6 h-6 ${iconColor}`} />
      </motion.div>

      <div className={`mt-2 text-xs font-medium ${textColor} transition-colors`}>
        {label}
      </div>

      {active && (
        <motion.div
          initial={{ opacity: 0, y: -5 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute -bottom-6 text-xs text-gray-500 whitespace-nowrap"
        >
          {description}
        </motion.div>
      )}
    </div>
  )
}

export default StepProgress
