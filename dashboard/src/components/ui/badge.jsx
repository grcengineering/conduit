import * as React from "react"
import { cva } from "class-variance-authority"
import { cn } from "@/lib/utils"

/**
 * Badge component variants
 * Provides different color schemes for status indicators
 */
const badgeVariants = cva(
  // Base styles - small rounded pill with bold text
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        // Default gray badge
        default:
          "border-transparent bg-primary text-primary-foreground shadow hover:bg-primary/80",
        // Red badge for errors/destructive actions
        destructive:
          "border-transparent bg-destructive text-destructive-foreground shadow hover:bg-destructive/80",
        // Outlined badge with border
        outline: "text-foreground",
        // Light gray secondary badge
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        // Green badge for success states
        success:
          "border-transparent bg-green-500 text-white shadow hover:bg-green-600",
        // Yellow/orange badge for warnings
        warning:
          "border-transparent bg-yellow-500 text-white shadow hover:bg-yellow-600",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

/**
 * Badge Component
 *
 * Small status indicator or label component.
 * Used to highlight important information or status.
 *
 * @param {object} props - Component props
 * @param {string} props.variant - Visual style (default, destructive, outline, secondary, success, warning)
 * @param {string} props.className - Additional CSS classes
 *
 * @example
 * <Badge variant="success">Compliant</Badge>
 * <Badge variant="warning">Partial</Badge>
 * <Badge variant="destructive">Non-Compliant</Badge>
 */
function Badge({ className, variant, ...props }) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
