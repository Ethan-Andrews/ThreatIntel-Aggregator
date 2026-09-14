import { useState, useEffect } from "react";

const INTERVAL_PRESETS = [30, 60, 120, 240, 1440];
const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]; // 0=Sunday, matches Postgres's date_part('dow', ...)

function minutesToTimeInput(minutes) {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

function timeInputToMinutes(value) {
  const [h, m] = value.split(":").map(Number);
  return h * 60 + m;
}

/**
 * Shared interval/daily-window(UTC)/day-of-week cadence picker -- the same
 * shape SettingsPanel.js's own orchestrator schedule form already proved
 * out, extracted here so Workstream E's Hunt Sentinel Sync cadence
 * (docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md)
 * doesn't duplicate the ~100 lines of interval/window/day-picker JSX a
 * second time. The orchestrator's own inline form is left as-is (it has
 * its own dedicated test file, SettingsPanel.schedule.test.js, asserting
 * exact DOM text/structure) -- only new cadence UI (this component) uses
 * the extracted version, rather than retrofitting existing, already-
 * tested code for no functional gain.
 *
 * Purely controlled by the caller: seeds its local form state once from
 * `settings`, and calls `onSave(payload)` on submit -- the caller owns
 * the actual fetch/PATCH and any resulting state update, keeping this
 * component API-agnostic (it doesn't know or care which endpoint it's
 * feeding).
 */
export default function CadencePicker({ settings, onSave, saving, error, helpText }) {
  const [form, setForm] = useState(null);

  useEffect(() => {
    if (!settings || form) return;
    const interval = settings.interval_minutes ?? 30;
    setForm({
      intervalPreset: INTERVAL_PRESETS.includes(interval) ? interval : "custom",
      customMinutes: INTERVAL_PRESETS.includes(interval) ? "" : String(interval),
      windowEnabled: settings.window_start_minute != null,
      windowStart: minutesToTimeInput(settings.window_start_minute ?? 9 * 60),
      windowEnd: minutesToTimeInput(settings.window_end_minute ?? 17 * 60),
      days: settings.days_of_week && settings.days_of_week.length > 0
        ? settings.days_of_week
        : [0, 1, 2, 3, 4, 5, 6],
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings]);

  if (!form) return null;

  function toggleDay(day) {
    setForm((prev) => ({
      ...prev,
      days: prev.days.includes(day)
        ? prev.days.filter((d) => d !== day)
        : [...prev.days, day].sort((a, b) => a - b),
    }));
  }

  function handleSave() {
    const interval = form.intervalPreset === "custom"
      ? parseInt(form.customMinutes, 10)
      : form.intervalPreset;
    if (!interval || interval <= 0) {
      onSave(null); // caller surfaces its own validation error
      return;
    }
    onSave({
      interval_minutes: interval,
      window_start_minute: form.windowEnabled ? timeInputToMinutes(form.windowStart) : null,
      window_end_minute: form.windowEnabled ? timeInputToMinutes(form.windowEnd) : null,
      // A full 7-day selection means "no restriction" -- send null rather
      // than an explicit all-days array, matching the backend's own
      // "empty/null means every day" convention.
      days_of_week: form.days.length === 7 ? null : form.days,
    });
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <label className="text-text-dim w-40 shrink-0">Run every</label>
        <select
          value={form.intervalPreset}
          onChange={(e) => {
            const v = e.target.value === "custom" ? "custom" : Number(e.target.value);
            setForm((prev) => ({ ...prev, intervalPreset: v }));
          }}
          className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
        >
          <option value={30}>30 Min</option>
          <option value={60}>1 Hour</option>
          <option value={120}>2 Hours</option>
          <option value={240}>4 Hours</option>
          <option value={1440}>1 Day</option>
          <option value="custom">Custom…</option>
        </select>
        {form.intervalPreset === "custom" && (
          <input
            type="number"
            min="1"
            max="10080"
            value={form.customMinutes}
            onChange={(e) => setForm((prev) => ({ ...prev, customMinutes: e.target.value }))}
            placeholder="minutes"
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text w-24"
          />
        )}
      </div>
      {helpText && <p className="text-[10px] text-text-dim leading-relaxed">{helpText}</p>}

      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          id="cadence-window-enabled"
          checked={form.windowEnabled}
          onChange={(e) => setForm((prev) => ({ ...prev, windowEnabled: e.target.checked }))}
        />
        <label htmlFor="cadence-window-enabled" className="text-text-dim">
          Restrict to a daily time window (UTC)
        </label>
      </div>
      {form.windowEnabled && (
        <div className="flex items-center gap-2 pl-6">
          <input
            type="time"
            value={form.windowStart}
            onChange={(e) => setForm((prev) => ({ ...prev, windowStart: e.target.value }))}
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
          />
          <span className="text-text-dim">to</span>
          <input
            type="time"
            value={form.windowEnd}
            onChange={(e) => setForm((prev) => ({ ...prev, windowEnd: e.target.value }))}
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
          />
        </div>
      )}

      <div className="flex items-center gap-1.5 flex-wrap">
        <label className="text-text-dim w-40 shrink-0">Days</label>
        {DAY_LABELS.map((label, day) => (
          <button
            key={day}
            type="button"
            onClick={() => toggleDay(day)}
            className={`text-[10px] px-2 py-1 rounded border transition-colors ${
              form.days.includes(day)
                ? "border-accent text-accent"
                : "border-border text-text-dim hover:text-text"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save schedule"}
        </button>
        {error && (
          <span className="text-xs text-red-400">Failed to save — check the values and try again.</span>
        )}
      </div>
    </div>
  );
}
