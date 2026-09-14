'use client';
import { useState, useEffect, useCallback } from 'react';
import TuningSuggestionBadge, { TuningBulkActionBar } from './TuningSuggestionBadge';
import useTuningSuggestions from './useTuningSuggestions';
import MetricInfoIcon from './MetricInfoIcon';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const PAGE_SIZE = 50;

const DISPOSITIONS = ['clean', 'tunable', 'needs_tuning', 'backtest_error'];
const REVIEW_STATES = ['pending', 'approved', 'rejected'];
const DETECTION_TYPES = [
  { value: 'sentinel', label: 'Analytic rule' },
  { value: 'mde', label: 'Defender custom detection' },
  { value: 'unbounded', label: 'Unbounded' },
];

function detectionTypeLabel(type) {
  const match = DETECTION_TYPES.find((t) => t.value === type);
  return match ? match.label : type;
}

const GOOD_VALUES = { disposition: 'clean', review_state: 'approved', static_gate: 'pass' };
const BAD_VALUES = { disposition: 'backtest_error', review_state: 'rejected', static_gate: 'fail' };

function pillClass(kind, value) {
  if (GOOD_VALUES[kind] === value) return 'bg-green-950 text-green-300 border-green-800';
  if (BAD_VALUES[kind] === value) return 'bg-red-950 text-red-300 border-red-800';
  return 'bg-yellow-950 text-yellow-300 border-yellow-800';
}

function Pill({ kind, value }) {
  if (!value) return <span className="text-text-dim">—</span>;
  return (
    <span className={['inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border', pillClass(kind, value)].join(' ')}>
      {value.toUpperCase()}
    </span>
  );
}

function detectionLabel(item) {
  return item.name || `Unnamed — ${item.technique_id}`;
}

function DetectionRow({
  item, expanded, onToggle, isAdmin, selected, onToggleSelect, onApply, onDismiss, tuningBusy,
}) {
  const hasSuggestion = !!(item.tuning_suggestion && item.tuning_suggestion.final_body);
  const hasDetail = !!(item.description || item.kql_body || hasSuggestion);
  return (
    <>
      <tr
        className={['border-t border-border', hasDetail ? 'cursor-pointer hover:bg-surface/60' : ''].join(' ')}
        onClick={hasDetail ? onToggle : undefined}
      >
        <td className="px-2 py-1.5 text-text">
          <span className={['font-bold', hasDetail ? 'underline decoration-dotted' : ''].join(' ')}>
            {detectionLabel(item)}
          </span>
          <div className="text-[10px] text-text-dim mt-0.5">{item.technique_id} — {item.technique_name}</div>
        </td>
        <td
          className="px-2 py-1.5 text-text-dim max-w-xs truncate whitespace-nowrap overflow-hidden"
          title={
            item.objective_is_fallback
              ? "MITRE hasn't published a Detection Strategy objective for this technique yet -- this isn't corrupted or broken data, just a gap in MITRE's own catalog."
              : (item.objective || '')
          }
        >
          {item.objective_is_fallback
            ? <span className="italic text-text-dim/70">No MITRE objective yet</span>
            : (item.objective || '—')}
        </td>
        <td className="px-2 py-1.5 text-text-dim">
          {item.detection_type ? detectionTypeLabel(item.detection_type) : <span className="text-text-dim">—</span>}
        </td>
        <td className="px-2 py-1.5"><Pill kind="static_gate" value={item.static_gate_verdict} /></td>
        <td className="px-2 py-1.5"><Pill kind="disposition" value={item.backtest_disposition} /></td>
        <td className="px-2 py-1.5"><Pill kind="review_state" value={item.review_state} /></td>
        <td className="px-2 py-1.5 text-text-dim font-mono">{item.created_at}</td>
      </tr>
      {expanded && hasDetail && (
        <tr className="border-t border-border bg-background">
          <td colSpan={7} className="px-2 py-2">
            {item.description && (
              <div className="text-[11px] text-text-dim mb-2">{item.description}</div>
            )}
            {item.kql_body && (
              <pre className="text-[10px] bg-surface border border-border rounded-sm p-2 overflow-x-auto whitespace-pre-wrap">
                {item.kql_body}
              </pre>
            )}
            <TuningSuggestionBadge
              item={item}
              isAdmin={isAdmin}
              selected={selected}
              onToggleSelect={onToggleSelect}
              onApply={onApply}
              onDismiss={onDismiss}
              busy={tuningBusy}
            />
          </td>
        </tr>
      )}
    </>
  );
}

export default function DetectionsCatalogPanel({ authFetch, userRole, lockedDetectionType }) {
  const [items, setItems]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [offset, setOffset]   = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const [search, setSearch]           = useState('');
  const [disposition, setDisposition] = useState('');
  const [reviewState, setReviewState] = useState('');
  // lockedDetectionType: used by the "Defender Custom Detections" sub-tab
  // to pin this view to detection_type=mde without exposing the selector
  // below -- same list endpoint/component as All Detections, just scoped
  // for organization.
  const [detectionType, setDetectionType] = useState(lockedDetectionType || '');
  const [expandedId, setExpandedId] = useState(null);

  const isAdmin = userRole === 'admin';

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (search) params.set('search', search.trim());
    if (disposition) params.set('disposition', disposition);
    if (reviewState) params.set('review_state', reviewState);
    if (detectionType) params.set('detection_type', detectionType);

    authFetch(`${API}/api/detections?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load detections.'))
      .finally(() => setLoading(false));
  }, [authFetch, offset, search, disposition, reviewState, detectionType]);

  useEffect(() => { load(); }, [load]);

  const tuning = useTuningSuggestions(authFetch, load);

  function applyFilters(e) {
    e.preventDefault();
    setOffset(0);
    load();
  }

  const canPrev = offset > 0;
  const canNext = offset + PAGE_SIZE < total;

  return (
    <div className="p-4 overflow-y-auto">
      <form onSubmit={applyFilters} className="flex flex-wrap items-center gap-2 mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Technique ID or detection name…"
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text w-56"
        />
        <select
          value={disposition}
          onChange={(e) => setDisposition(e.target.value)}
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text"
        >
          <option value="">All dispositions</option>
          {DISPOSITIONS.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        <select
          value={reviewState}
          onChange={(e) => setReviewState(e.target.value)}
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text"
        >
          <option value="">All review states</option>
          {REVIEW_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {!lockedDetectionType && (
          <select
            value={detectionType}
            onChange={(e) => setDetectionType(e.target.value)}
            className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text"
          >
            <option value="">All types</option>
            {DETECTION_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        )}
        <button type="submit" className="text-xs border border-border rounded-sm px-3 py-1 text-text hover:bg-surface transition-colors">
          Filter
        </button>
      </form>

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {loading && <div className="text-xs text-text-dim">Loading detections…</div>}

      {isAdmin && (
        <TuningBulkActionBar
          count={tuning.selectedIds.size}
          busy={tuning.busy}
          error={tuning.error}
          onApply={tuning.applySelected}
          onDismiss={tuning.dismissSelected}
          onClear={tuning.clearSelected}
        />
      )}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">No detections match these filters.</div>
      )}

      {!loading && items.length > 0 && (
        <div className="border border-border rounded-sm overflow-hidden">
          <table className="w-full text-[11px]">
            <thead className="bg-surface text-text-dim">
              <tr>
                <th className="text-left px-2 py-1.5 font-bold">Detection</th>
                <th className="text-left px-2 py-1.5 font-bold">Objective</th>
                <th className="text-left px-2 py-1.5 font-bold">Type</th>
                <th className="text-left px-2 py-1.5 font-bold">Static gate<MetricInfoIcon metric="static_gate" /></th>
                <th className="text-left px-2 py-1.5 font-bold">Backtest<MetricInfoIcon metric="backtest" /></th>
                <th className="text-left px-2 py-1.5 font-bold">Review<MetricInfoIcon metric="review" /></th>
                <th className="text-left px-2 py-1.5 font-bold">Created</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <DetectionRow
                  key={item.id}
                  item={item}
                  expanded={expandedId === item.id}
                  onToggle={() => setExpandedId(expandedId === item.id ? null : item.id)}
                  isAdmin={isAdmin}
                  selected={tuning.selectedIds.has(item.id)}
                  onToggleSelect={tuning.toggleSelected}
                  onApply={tuning.applyOne}
                  onDismiss={tuning.dismissOne}
                  tuningBusy={tuning.busy}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && total > 0 && (
        <div className="flex items-center justify-between mt-3 text-xs text-text-dim">
          <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={!canPrev}
              className="border border-border rounded-sm px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
            >
              Prev
            </button>
            <button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={!canNext}
              className="border border-border rounded-sm px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
