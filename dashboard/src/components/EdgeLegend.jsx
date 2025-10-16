/**
 * EdgeLegend Component
 *
 * Displays the color-coded legend for graph edges showing compliance levels.
 * Matches the vanilla dashboard's edge legend styling.
 */
function EdgeLegend() {
  return (
    <div className="text-right">
      <label className="block text-sm font-medium text-gray-700 mb-2">
        Edge Legend
      </label>
      <div className="text-sm text-gray-600 space-y-1">
        <div className="flex items-center gap-2 justify-end">
          <div className="w-4 h-0.5 bg-green-500"></div>
          <span>Compliant (≥85%)</span>
        </div>
        <div className="flex items-center gap-2 justify-end">
          <div className="w-4 h-0.5 bg-orange-500"></div>
          <span>Partial (70-84%)</span>
        </div>
        <div className="flex items-center gap-2 justify-end">
          <div className="w-4 h-0.5 border-t-2 border-dashed border-red-500"></div>
          <span>Non-Compliant (&lt;70%)</span>
        </div>
      </div>
    </div>
  )
}

export default EdgeLegend
