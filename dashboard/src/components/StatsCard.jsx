import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import { Card, CardContent } from '@/components/ui/card'

/**
 * StatsCard Component
 *
 * Displays a key metric with an animated count-up effect and icon.
 * Used in the dashboard header to show important statistics at a glance.
 *
 * Features:
 * - Animated count-up effect when the component mounts
 * - Color-coded based on variant
 * - Icon support from lucide-react
 * - Responsive design
 *
 * @param {object} props - Component props
 * @param {string|number} props.value - The metric value to display
 * @param {string} props.label - Description of the metric
 * @param {React.Component} props.icon - Lucide icon component
 * @param {string} [props.variant='default'] - Color variant (default, success, warning, destructive)
 *
 * @example
 * import { Users } from 'lucide-react'
 * <StatsCard value={15} label="Total Vendors" icon={Users} variant="default" />
 */
function StatsCard({ value, label, icon: Icon, variant = 'default' }) {
  // Reference to the displayed value for animation
  const valueRef = useRef(null)
  const isNumber = typeof value === 'number'

  useEffect(() => {
    // Only animate if the value is a number
    if (!isNumber || !valueRef.current) return

    const finalValue = value
    const duration = 1000 // Animation duration in milliseconds
    const steps = 60 // Number of animation frames
    const increment = finalValue / steps
    const stepDuration = duration / steps

    let currentValue = 0
    let currentStep = 0

    // Animate the count-up effect
    const timer = setInterval(() => {
      currentStep++
      currentValue += increment

      if (currentStep >= steps) {
        // Animation complete - set final value
        if (valueRef.current) {
          valueRef.current.textContent = finalValue
        }
        clearInterval(timer)
      } else {
        // Update with intermediate value
        if (valueRef.current) {
          valueRef.current.textContent = Math.floor(currentValue)
        }
      }
    }, stepDuration)

    // Cleanup timer on unmount
    return () => clearInterval(timer)
  }, [value, isNumber])

  // Color schemes for different variants
  const variantStyles = {
    default: {
      icon: 'text-blue-500',
      bg: 'bg-blue-50',
    },
    success: {
      icon: 'text-green-500',
      bg: 'bg-green-50',
    },
    warning: {
      icon: 'text-yellow-500',
      bg: 'bg-yellow-50',
    },
    destructive: {
      icon: 'text-red-500',
      bg: 'bg-red-50',
    },
  }

  const styles = variantStyles[variant] || variantStyles.default

  return (
    <motion.div
      // Fade in animation when component mounts
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-between">
            {/* Left side: Value and Label */}
            <div>
              <div className="text-3xl font-bold" ref={valueRef}>
                {isNumber ? 0 : value}
              </div>
              <p className="text-sm text-muted-foreground mt-1">{label}</p>
            </div>

            {/* Right side: Icon with colored background */}
            {Icon && (
              <div className={`rounded-full p-3 ${styles.bg}`}>
                <Icon className={`h-6 w-6 ${styles.icon}`} />
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}

export default StatsCard
