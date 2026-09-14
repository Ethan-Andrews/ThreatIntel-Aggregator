const SEVERITIES = [
  { value: "critical", label: "Critical", color: "border-red-600 text-red-400 bg-red-950/40" },
  { value: "high", label: "High", color: "border-orange-600 text-orange-400 bg-orange-950/40" },
  { value: "medium", label: "Medium", color: "border-yellow-600 text-yellow-400 bg-yellow-950/40" },
  { value: "low", label: "Low", color: "border-green-600 text-green-400 bg-green-950/40" },
];

/**
 * Multi-selectable severity cards (Workstream E) -- no existing generic
 * multi-select-card component in this codebase to reuse, confirmed by
 * inspecting frontend/components/ before writing this.
 *
 * `selected` is an array of lowercase severity strings, or null/undefined
 * to mean "no restriction" (every severity, matching the backend's own
 * severities=NULL convention) -- rendered as every card selected, since
 * that's the state's actual effect, not as no cards selected.
 */
export default function SeverityCards({ selected, onChange }) {
  const effectiveSelected = selected && selected.length > 0 ? selected : SEVERITIES.map((s) => s.value);

  function toggle(value) {
    // Always toggle against what's actually rendered as selected --
    // when `selected` is null (no restriction), every card displays as
    // selected, so clicking one must deselect just that one, leaving the
    // other three, not start from an empty set and add only the one
    // clicked.
    const next = effectiveSelected.includes(value)
      ? effectiveSelected.filter((v) => v !== value)
      : [...effectiveSelected, value];
    // Selecting all four is equivalent to "no restriction" -- send null,
    // matching the backend's own convention (and avoiding a form that
    // silently drifts from "every severity picked" vs "no filter" being
    // treated differently server-side when they mean the same thing).
    onChange(next.length === SEVERITIES.length ? null : next);
  }

  return (
    <div className="flex gap-2 flex-wrap">
      {SEVERITIES.map((sev) => {
        const isSelected = effectiveSelected.includes(sev.value);
        return (
          <button
            key={sev.value}
            type="button"
            onClick={() => toggle(sev.value)}
            className={`text-xs px-3 py-1.5 rounded border transition-colors ${
              isSelected ? sev.color : "border-border text-text-dim hover:text-text"
            }`}
          >
            {sev.label}
          </button>
        );
      })}
    </div>
  );
}
