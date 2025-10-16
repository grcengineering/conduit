import { clsx } from "clsx"
import { twMerge } from "tailwind-merge"

/**
 * Merge Tailwind CSS classes with proper precedence
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs))
}

/**
 * Calculate vendor overall compliance percentage
 */
export function getVendorCompliance(vendor) {
  const totalRequirements = vendor.controls.reduce((sum, c) => sum + c.total, 0)
  const passedRequirements = vendor.controls.reduce((sum, c) => sum + c.passed, 0)
  return ((passedRequirements / totalRequirements) * 100).toFixed(1)
}

/**
 * Calculate average compliance across all vendors for a specific control
 */
export function getControlAvgCompliance(controlId, vendors) {
  const vendorsWithControl = vendors.filter(v =>
    v.controls.some(c => c.id === controlId)
  )

  if (vendorsWithControl.length === 0) return 0

  const totalPassed = vendorsWithControl.reduce((sum, v) => {
    const ctrl = v.controls.find(c => c.id === controlId)
    return sum + ctrl.passed
  }, 0)

  const totalRequirements = vendorsWithControl.reduce((sum, v) => {
    const ctrl = v.controls.find(c => c.id === controlId)
    return sum + ctrl.total
  }, 0)

  return ((totalPassed / totalRequirements) * 100).toFixed(1)
}

/**
 * Get compliance status from percentage
 */
export function getComplianceStatus(percentage) {
  if (percentage >= 85) return 'compliant'
  if (percentage >= 50) return 'partially_compliant'
  return 'non_compliant'
}

/**
 * Get edge color based on percentage
 */
export function getEdgeColor(percentage) {
  if (percentage >= 85) return '#10b981'  // Green
  if (percentage >= 70) return '#f59e0b'  // Orange
  return '#ef4444'  // Red
}

/**
 * Get edge style (solid or dashed)
 */
export function getEdgeStyle(percentage) {
  return percentage >= 70 ? 'solid' : 'dash'
}

/**
 * Get status badge variant
 */
export function getStatusVariant(status) {
  switch (status) {
    case 'compliant':
      return 'success'
    case 'partially_compliant':
      return 'warning'
    case 'non_compliant':
      return 'destructive'
    default:
      return 'secondary'
  }
}

/**
 * Format status text
 */
export function formatStatus(status) {
  return status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())
}
