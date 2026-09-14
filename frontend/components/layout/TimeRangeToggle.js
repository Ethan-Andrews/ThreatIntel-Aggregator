'use client';
import { useState } from 'react';

const WINDOWS = [
  { value: '1d', label: '1D' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
  { value: '90d', label: '90D' },
  { value: 'all', label: 'All' },
];

/**
 * Shared 1D/7D/30D/90D/All/Custom toggle -- used by Dashboard (Workstream
 * D), Audit Log trend (Workstream B), and RunZero Metrics (Workstream F).
 * One implementation so the three tabs' time-window UI can't drift, per
 * docs/superpowers/specs/2026-09-04-live-feedback-round-6-design.md's
 * cross-cutting notes.
 *
 * Emits {window, from, to} via onChange -- from/to are only meaningful
 * when window === 'custom', matching the backend's time_windows.
 * window_to_range() contract exactly (the caller passes window straight
 * through as a query param, along with from/to when set).
 */
export default function TimeRangeToggle({ value, onChange }) {
  const [customFrom, setCustomFrom] = useState(value?.from || '');
  const [customTo, setCustomTo] = useState(value?.to || '');
  // Which button is highlighted / whether the custom inputs are revealed.
  // Deliberately local state, not derived straight from the `value` prop:
  // clicking "Custom" must reveal the date inputs immediately so the user
  // can fill them in, before onChange ever fires (a custom range isn't
  // meaningful with empty from/to) -- a prop-derived highlight would need
  // the parent to already have committed window: 'custom' back down for
  // the inputs to appear, which can't happen before the user has entered
  // anything. Initialized from `value` once, on mount, so a caller that
  // passes a starting window still gets it highlighted correctly.
  const [activeWindow, setActiveWindow] = useState(value?.window || '30d');

  const selectWindow = (w) => {
    setActiveWindow(w);
    if (w === 'custom') {
      return; // wait for Apply -- an incomplete range isn't a real selection.
    }
    onChange({ window: w, from: null, to: null });
  };

  const applyCustom = () => {
    if (customFrom && customTo) {
      onChange({ window: 'custom', from: customFrom, to: customTo });
    }
  };

  return (
    <div className="flex items-center gap-1 flex-wrap">
      {WINDOWS.map((w) => (
        <button
          key={w.value}
          onClick={() => selectWindow(w.value)}
          className={`text-xs px-2 py-1 rounded border transition-colors ${
            activeWindow === w.value
              ? 'bg-gray-700 border-gray-500 text-white'
              : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
          }`}
        >
          {w.label}
        </button>
      ))}
      <button
        onClick={() => selectWindow('custom')}
        className={`text-xs px-2 py-1 rounded border transition-colors ${
          activeWindow === 'custom'
            ? 'bg-gray-700 border-gray-500 text-white'
            : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
        }`}
      >
        Custom
      </button>
      {activeWindow === 'custom' && (
        <div className="flex items-center gap-1.5 text-xs text-gray-400">
          <input
            type="date"
            value={customFrom}
            onChange={(e) => setCustomFrom(e.target.value)}
            className="text-xs px-1.5 py-1 rounded bg-gray-900 border border-gray-700 text-gray-200 focus:outline-hidden focus:border-blue-600"
            aria-label="Custom range start"
          />
          <span>to</span>
          <input
            type="date"
            value={customTo}
            onChange={(e) => setCustomTo(e.target.value)}
            className="text-xs px-1.5 py-1 rounded bg-gray-900 border border-gray-700 text-gray-200 focus:outline-hidden focus:border-blue-600"
            aria-label="Custom range end"
          />
          <button
            onClick={applyCustom}
            disabled={!customFrom || !customTo}
            className="text-xs px-2 py-1 rounded-sm border bg-blue-900 text-blue-300 border-blue-700 hover:bg-blue-800 disabled:opacity-50"
          >
            Apply
          </button>
        </div>
      )}
    </div>
  );
}
