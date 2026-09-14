'use client';
import { useState } from 'react';

// Shared across every panel that shows these three columns (All Detections
// today; Sentinel Analytics Rules/Sentinel Hunts show the same backtest/
// review concepts and can adopt this directly later). Kept as plain data,
// not sourced from the backend, since these are fixed pipeline-stage
// descriptions, not something that varies per row.
export const METRIC_INFO = {
  static_gate: {
    label: 'Static gate',
    definition: 'A pass/fail structural check on the rule body itself, before any query runs against real data -- the cheapest possible check, so it runs first.',
    formula: 'PASS unless the rule body trips a specific reject rule: a hash literal of the wrong length, a filter on a column no ingested table actually has, a filename/path/IP literal unlikely to ever fire, a memory-risk aggregation, or a predicate known to be dead. See backend/detection_pipeline/static_gate.py.',
  },
  backtest: {
    label: 'Backtest',
    definition: 'Runs the rule against real telemetry over a lookback window and counts how many times it would have fired.',
    formula: '0 hits → CLEAN. 1–3 hits (READABLE_HITS) → TUNABLE, few enough for a human to review by hand. 4+ hits → NEEDS_TUNING, too many to review one by one -- the bounded auto-tune loop narrows the rule automatically. A failure running the backtest itself → BACKTEST_ERROR. See backend/detection_pipeline/backtest.py’s BacktestOutcome.disposition.',
  },
  review: {
    label: 'Review',
    definition: 'The human review decision on this detection -- independent of the two automated checks above.',
    formula: 'Starts PENDING for every new detection. An admin sets it to APPROVED or REJECTED via the Review control; never computed automatically.',
  },
};

export default function MetricInfoIcon({ metric }) {
  const [open, setOpen] = useState(false);
  const info = METRIC_INFO[metric];
  if (!info) return null;

  return (
    <span className="relative inline-block ml-1 font-normal normal-case">
      <button
        type="button"
        title={info.definition}
        onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
        aria-label={`${info.label} info`}
        className="w-3.5 h-3.5 inline-flex items-center justify-center rounded-full border border-border text-text-dim hover:text-text hover:border-accent text-[9px] leading-none"
      >
        i
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute z-50 left-0 top-full mt-1 w-72 bg-surface border border-border rounded-sm shadow-lg p-3 text-left">
            <div className="flex items-center justify-between mb-1">
              <div className="text-xs font-bold text-text">{info.label}</div>
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setOpen(false); }}
                aria-label="Close"
                className="text-text-dim hover:text-text text-[11px] leading-none"
              >
                ✕
              </button>
            </div>
            <div className="text-[11px] text-text-dim mb-2">{info.definition}</div>
            <div className="text-[10px] font-bold text-text-dim tracking-wider mb-1">HOW IT&rsquo;S CALCULATED</div>
            <div className="text-[11px] text-text">{info.formula}</div>
          </div>
        </>
      )}
    </span>
  );
}
