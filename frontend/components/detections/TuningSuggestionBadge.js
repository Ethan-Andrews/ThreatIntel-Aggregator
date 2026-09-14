'use client';
import { useState } from 'react';

/**
 * "Tuning suggestion available" badge + expandable proposed-KQL section +
 * multi-select checkbox for one analytic row's `tuning_suggestion` (see
 * useTuningSuggestions.js and tuning_actions.suggestion_view() on the
 * backend). Shared between HuntsPanel.js and DetectionsCatalogPanel.js so
 * the two views can't drift on what this looks like or how it behaves.
 *
 * Renders nothing when there is no suggestion at all (tune.py never ran, or
 * ran and landed on a disposition with nothing to show -- suggestion is
 * null or has no final_body). Apply/Dismiss controls only show for an
 * admin, and only while the suggestion is still pending (not yet actioned).
 */
export default function TuningSuggestionBadge({
  item, isAdmin, selected, onToggleSelect, onApply, onDismiss, busy,
}) {
  const [expanded, setExpanded] = useState(false);
  const suggestion = item.tuning_suggestion;
  if (!suggestion || !suggestion.final_body) return null;

  const label = item.name || `Unnamed — ${item.technique_id}`;

  return (
    <div
      className="mt-2 border border-border rounded bg-background p-2"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          {isAdmin && onToggleSelect && suggestion.pending && (
            <input
              type="checkbox"
              checked={!!selected}
              onChange={() => onToggleSelect(item.id)}
              aria-label={`Select tuning suggestion for ${label}`}
            />
          )}
          {suggestion.pending && suggestion.action !== 'apply_failed' && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-accent/10 text-accent border-accent/40">
              TUNING SUGGESTION AVAILABLE
            </span>
          )}
          {suggestion.action === 'apply_failed' && (
            <span
              title={suggestion.error || 'The last apply attempt failed.'}
              className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-red-950 text-red-300 border-red-800"
            >
              LAST APPLY FAILED — RETRY?
            </span>
          )}
          {!suggestion.pending && suggestion.action === 'applied' && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-green-950 text-green-300 border-green-800">
              TUNING APPLIED
            </span>
          )}
          {!suggestion.pending && suggestion.action === 'dismissed' && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-surface text-text-dim border-border">
              TUNING DISMISSED
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-[10px] text-accent hover:underline"
        >
          {expanded ? 'Hide proposed KQL' : 'Show proposed KQL'}
        </button>
      </div>

      {expanded && (
        <pre className="text-[10px] bg-surface border border-border rounded p-2 mt-2 overflow-x-auto whitespace-pre-wrap">
          {suggestion.final_body}
        </pre>
      )}

      {isAdmin && suggestion.pending && (onApply || onDismiss) && (
        <div className="flex gap-2 mt-2">
          {onApply && (
            <button
              type="button"
              disabled={busy}
              onClick={() => onApply(item.id)}
              className="text-[10px] border border-accent text-accent rounded px-2 py-0.5 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Apply
            </button>
          )}
          {onDismiss && (
            <button
              type="button"
              disabled={busy}
              onClick={() => onDismiss(item.id)}
              className="text-[10px] border border-border text-text-dim rounded px-2 py-0.5 hover:bg-surface transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Dismiss
            </button>
          )}
        </div>
      )}

      {(!suggestion.pending || suggestion.action === 'apply_failed') && suggestion.performed_by && (
        <div className="text-[10px] text-text-dim mt-1">
          {suggestion.action} by {suggestion.performed_by}
          {suggestion.action === 'apply_failed' && suggestion.error && `: ${suggestion.error}`}
        </div>
      )}
    </div>
  );
}

export function TuningBulkActionBar({ count, busy, error, onApply, onDismiss, onClear }) {
  if (count === 0) return null;
  return (
    <div className="flex items-center gap-2 mb-3 p-2 border border-accent/40 bg-accent/10 rounded text-xs">
      <span className="text-text font-bold">{count} selected</span>
      <button
        type="button"
        disabled={busy}
        onClick={onApply}
        className="border border-accent text-accent rounded px-2 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {busy ? 'Pushing…' : `Push ${count} update${count === 1 ? '' : 's'} to Sentinel`}
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={onDismiss}
        className="border border-border text-text-dim rounded px-2 py-1 hover:bg-surface transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
      >
        Dismiss selected
      </button>
      <button
        type="button"
        onClick={onClear}
        className="text-text-dim hover:underline ml-auto"
      >
        Clear selection
      </button>
      {error && <span className="text-red-400">{error}</span>}
    </div>
  );
}
