'use client';
import { useState, useEffect, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const PAGE_SIZE = 50;

const OUTCOME_LABEL = {
  now_firing: 'NOW FIRING',
  telemetry_decayed: 'TELEMETRY DECAYED',
};

const DETECTION_TYPES = [
  { value: 'sentinel', label: 'Analytic rule' },
  { value: 'mde', label: 'Defender custom detection' },
  { value: 'unbounded', label: 'Unbounded' },
  { value: 'hunt', label: 'Hunt' },
];

function detectionTypeLabel(type) {
  const match = DETECTION_TYPES.find((t) => t.value === type);
  return match ? match.label : type;
}

function OutcomeBadge({ outcome }) {
  const isFiring = outcome === 'now_firing';
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border',
      isFiring ? 'bg-orange-950 text-orange-300 border-orange-800' : 'bg-red-950 text-red-300 border-red-800',
    ].join(' ')}>
      {OUTCOME_LABEL[outcome] || outcome.toUpperCase()}
    </span>
  );
}

function detectionLabel(item) {
  return item.name || `Unnamed — ${item.technique_id}`;
}

// `detail` varies by outcome: check_error carries a plain {error} string
// worth surfacing directly, other outcomes (telemetry_decayed) carry a
// full control-probe result row. Render the common case in plain text and
// fall back to indented JSON rather than a single-line brace blob.
function formatDetail(detail) {
  if (typeof detail.error === 'string') return `Error: ${detail.error}`;
  return JSON.stringify(detail, null, 2);
}

function AlertCard({ item }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetail = !!(item.description || item.kql_body);

  return (
    <div className="border border-border rounded-sm p-3 mb-3 bg-surface">
      <div className="flex items-start justify-between mb-1 gap-2">
        <div>
          <div className="text-sm font-bold text-text">{detectionLabel(item)}</div>
          <div className="text-[10px] text-text-dim mt-0.5">{item.technique_id} — {item.technique_name}</div>
        </div>
        <div className="flex items-center gap-2">
          {item.detection_type && (
            <span className="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border bg-background text-text-dim border-border">
              {detectionTypeLabel(item.detection_type)}
            </span>
          )}
          <OutcomeBadge outcome={item.outcome} />
        </div>
      </div>
      <div className="text-[11px] text-text-dim mb-1 mt-2">
        Checked {item.checked_at} · {item.hits} hits over {item.window_hours}h window
      </div>
      <div className="text-[11px] text-text-dim">
        Control probe: <span className="text-text">{item.control_probe_disposition || '—'}</span>
        {' · '}
        Backtest: <span className="text-text">{item.backtest_disposition || '—'}</span>
      </div>
      {item.detail && Object.keys(item.detail).length > 0 && (
        <pre className="text-[11px] text-text mt-2 whitespace-pre-wrap font-mono">{formatDetail(item.detail)}</pre>
      )}
      {hasDetail && (
        <button
          onClick={() => setExpanded((e) => !e)}
          className="text-[10px] text-accent mt-2 hover:underline"
        >
          {expanded ? 'Hide detection details' : 'View detection details'}
        </button>
      )}
      {expanded && hasDetail && (
        <div className="mt-2 border-t border-border pt-2">
          {item.description && (
            <div className="text-[11px] text-text-dim mb-2">{item.description}</div>
          )}
          {item.kql_body && (
            <pre className="text-[10px] bg-background border border-border rounded-sm p-2 overflow-x-auto whitespace-pre-wrap">
              {item.kql_body}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default function DispositionAlertsPanel({ authFetch }) {
  const [items, setItems]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [offset, setOffset]   = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [detectionType, setDetectionType] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (detectionType) params.set('detection_type', detectionType);
    authFetch(`${API}/api/detections/disposition-alerts?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load disposition alerts.'))
      .finally(() => setLoading(false));
  }, [authFetch, offset, detectionType]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setOffset(0); }, [detectionType]);

  const canPrev = offset > 0;
  const canNext = offset + PAGE_SIZE < total;

  return (
    <div className="p-4 overflow-y-auto">
      <div className="text-xs font-bold text-text-dim mb-2 tracking-wider">
        ▸ ROTTED DETECTIONS ({total})
      </div>
      <div className="text-[11px] text-text-dim mb-4">
        Previously-clean analytics that started firing or lost their telemetry, most recently checked first.
      </div>

      <div className="flex items-center gap-2 mb-4">
        <select
          value={detectionType}
          onChange={(e) => setDetectionType(e.target.value)}
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text"
        >
          <option value="">All types</option>
          {DETECTION_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
      </div>

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {loading && <div className="text-xs text-text-dim">Loading disposition alerts…</div>}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">No rot detected — every rechecked analytic is still clean.</div>
      )}

      {!loading && items.map((item) => <AlertCard key={item.id} item={item} />)}

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
