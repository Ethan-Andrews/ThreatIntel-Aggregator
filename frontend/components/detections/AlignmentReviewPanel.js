'use client';
import { useState, useEffect, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';

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

function StatusPill({ ok, label }) {
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border',
      ok ? 'bg-green-950 text-green-300 border-green-800' : 'bg-red-950 text-red-300 border-red-800',
    ].join(' ')}>
      {label}
    </span>
  );
}

function ValidationSummary({ validation }) {
  if (!validation) return null;
  const v = typeof validation === 'string' ? JSON.parse(validation) : validation;

  return (
    <div className="mt-2 border-t border-border pt-2 space-y-1">
      <div className="text-[10px] font-bold text-text-dim tracking-wider">TELEMETRY &amp; VALIDATION</div>

      {(v.log_source_checks || []).map((c, i) => (
        <div key={i} className="text-[11px] flex items-center gap-2">
          <StatusPill ok={!!c.resolved} label={c.resolved ? c.resolved.table : 'UNMAPPED'} />
          <span className="text-text-dim">{c.name}{c.channel ? `/${c.channel}` : ''}</span>
        </div>
      ))}

      {Array.isArray(v.telemetry_probes) && v.telemetry_probes.map((p, i) => (
        <div key={i} className="text-[11px] flex items-center gap-2">
          <StatusPill ok={p.ok} label={p.ok ? 'TELEMETRY CONFIRMED' : 'NO DATA'} />
          <span className="text-text-dim">{p.table}</span>
        </div>
      ))}
      {typeof v.telemetry_probes === 'string' && (
        <div className="text-[11px] text-text-dim italic">{v.telemetry_probes}</div>
      )}

      {v.static_gate && (
        <div className="text-[11px] flex items-center gap-2">
          <StatusPill ok={v.static_gate.verdict === 'pass'} label={`STATIC GATE: ${v.static_gate.verdict.toUpperCase()}`} />
          <span className="text-text-dim">durability {v.static_gate.durability}</span>
        </div>
      )}

      {v.backtest && (
        <div className="text-[11px] text-text-dim">Backtest disposition: {v.backtest.disposition}</div>
      )}

      {v.gap_reason && (
        <div className="text-[11px] text-yellow-400 italic">{v.gap_reason}</div>
      )}
    </div>
  );
}

function ReviewCard({ item, isAdmin, onAccept, onReject, busy }) {
  return (
    <div className="border border-border rounded-sm p-3 mb-3 bg-surface">
      <div className="flex items-center justify-between mb-1">
        <div>
          <div className="text-sm font-bold text-text">
            {item.detection_name || (
              <span className="italic text-text-dim font-normal">No deployed analytic yet</span>
            )}
          </div>
          <div className="text-[10px] text-text-dim mt-0.5">{item.technique_id} — {item.technique_name}</div>
        </div>
        <div className="flex items-center gap-2">
          {item.detection_type && (
            <span className="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border bg-surface text-text-dim border-border">
              {detectionTypeLabel(item.detection_type)}
            </span>
          )}
          <span className="text-[10px] text-text-dim font-mono">review #{item.id}</span>
        </div>
      </div>

      <div className="text-[11px] text-text-dim mb-1 mt-2">
        <span className="font-bold">Our objective:</span> {item.our_objective || '—'}
      </div>
      {item.detection_description && (
        <div className="text-[11px] text-text-dim mb-1">
          <span className="font-bold">Deployed detection:</span> {item.detection_description}
        </div>
      )}
      <div className="text-[11px] text-text mb-2">
        <span className="font-bold text-text-dim">AI reasoning:</span> {item.ai_reasoning}
      </div>

      {item.deployed_kql_body && (
        <>
          <div className="text-[10px] font-bold text-text-dim tracking-wider mt-2">CURRENTLY DEPLOYED KQL</div>
          <pre className="text-[10px] bg-background border border-border rounded-sm p-2 overflow-x-auto whitespace-pre-wrap">
            {item.deployed_kql_body}
          </pre>
        </>
      )}

      {item.suggested_kql && (
        <>
          <div className="text-[10px] font-bold text-text-dim tracking-wider mt-2">SUGGESTED KQL</div>
          <pre className="text-[10px] bg-background border border-border rounded-sm p-2 overflow-x-auto whitespace-pre-wrap">
            {item.suggested_kql}
          </pre>
        </>
      )}

      <ValidationSummary validation={item.validation_result} />

      {isAdmin && item.status === 'pending_review' && (
        <div className="flex gap-2 mt-3">
          <button
            onClick={() => onAccept(item.id)}
            disabled={busy || !item.suggested_kql}
            title={!item.suggested_kql ? 'No validated fix to accept' : undefined}
            className="text-xs border border-green-800 text-green-300 rounded-sm px-3 py-1 hover:bg-green-950 transition-colors disabled:opacity-40"
          >
            Accept
          </button>
          <button
            onClick={() => onReject(item.id)}
            disabled={busy}
            className="text-xs border border-red-800 text-red-300 rounded-sm px-3 py-1 hover:bg-red-950 transition-colors disabled:opacity-40"
          >
            Reject
          </button>
        </div>
      )}
    </div>
  );
}

export default function AlignmentReviewPanel({ authFetch, userRole }) {
  const [pending, setPending]   = useState([]);
  const [partial, setPartial]   = useState([]);
  const [pendingTotal, setPendingTotal]           = useState(0);
  const [pendingReadyTotal, setPendingReadyTotal] = useState(0);
  const [partialTotal, setPartialTotal]           = useState(0);
  const [loading, setLoading]   = useState(true);
  const [busyId,  setBusyId]    = useState(null);
  const [error,   setError]     = useState(null);
  const [detectionType, setDetectionType] = useState('');

  // Both groups start collapsed -- a reviewer sees the counts first and
  // opens the one they actually want to work, rather than every review's
  // full card (KQL bodies, telemetry validation, etc.) rendering at once.
  const [pendingExpanded, setPendingExpanded] = useState(false);
  const [partialExpanded, setPartialExpanded] = useState(false);
  // "Ready to accept" only ever applies to the pending bucket -- every
  // awaiting-re-check row is written with no suggested_kql at all (see
  // alignment_reviews.py's ready_only comment), so there is nothing for
  // this checkbox to filter there.
  const [readyOnly, setReadyOnly] = useState(false);

  const isAdmin = userRole === 'admin';

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams();
    if (detectionType) params.set('detection_type', detectionType);
    const qs = params.toString() ? `?${params.toString()}` : '';
    const readyParams = new URLSearchParams(params);
    readyParams.set('ready_only', 'true');
    readyParams.set('limit', '1');
    Promise.all([
      authFetch(`${API}/api/detections/alignment/pending${qs}`).then((r) => r.json()),
      authFetch(`${API}/api/detections/alignment/partial${qs}`).then((r) => r.json()),
      authFetch(`${API}/api/detections/alignment/pending?${readyParams.toString()}`).then((r) => r.json()),
    ])
      .then(([pendingData, partialData, pendingReadyData]) => {
        setPending(pendingData.items || []);
        setPendingTotal(pendingData.total || 0);
        setPartial(partialData.items || []);
        setPartialTotal(partialData.total || 0);
        setPendingReadyTotal(pendingReadyData.total || 0);
      })
      .catch(() => setError('Failed to load alignment reviews.'))
      .finally(() => setLoading(false));
  }, [authFetch, detectionType]);

  useEffect(() => { load(); }, [load]);

  const visiblePending = readyOnly ? pending.filter((item) => !!item.suggested_kql) : pending;

  function handleAccept(reviewId) {
    setBusyId(reviewId);
    authFetch(`${API}/api/detections/alignment/${reviewId}/accept`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => load())
      .catch(() => setError('Failed to accept review.'))
      .finally(() => setBusyId(null));
  }

  function handleReject(reviewId) {
    setBusyId(reviewId);
    authFetch(`${API}/api/detections/alignment/${reviewId}/reject`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => load())
      .catch(() => setError('Failed to reject review.'))
      .finally(() => setBusyId(null));
  }

  if (loading) return <div className="p-4 text-xs text-text-dim">Loading alignment reviews…</div>;

  return (
    <div className="p-4 overflow-y-auto">
      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}

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

      <div className="mb-6">
        <button
          type="button"
          onClick={() => setPendingExpanded((v) => !v)}
          className="w-full text-left text-xs font-bold text-text-dim mb-2 tracking-wider hover:text-text transition-colors"
        >
          {pendingExpanded ? '▾' : '▸'} PENDING REVIEW ({pendingTotal} total, {pendingReadyTotal} ready to accept)
        </button>
        {pendingExpanded && (
          <>
            <label className="flex items-center gap-1.5 text-[11px] text-text-dim cursor-pointer mb-2">
              <input
                type="checkbox"
                checked={readyOnly}
                onChange={(e) => setReadyOnly(e.target.checked)}
              />
              Ready to accept only
            </label>
            {visiblePending.length === 0 && (
              <div className="text-xs text-text-dim italic">
                {readyOnly ? 'No reviews ready to accept.' : 'No divergent detections awaiting review.'}
              </div>
            )}
            {visiblePending.map((item) => (
              <ReviewCard
                key={item.id}
                item={item}
                isAdmin={isAdmin}
                busy={busyId === item.id}
                onAccept={handleAccept}
                onReject={handleReject}
              />
            ))}
          </>
        )}
      </div>

      <div>
        <button
          type="button"
          onClick={() => setPartialExpanded((v) => !v)}
          className="w-full text-left text-xs font-bold text-text-dim mb-2 tracking-wider hover:text-text transition-colors"
        >
          {partialExpanded ? '▾' : '▸'} AWAITING RE-CHECK ({partialTotal} total)
        </button>
        {partialExpanded && (
          <>
            {partial.length === 0 && (
              <div className="text-xs text-text-dim italic">Nothing queued for re-review.</div>
            )}
            {partial.map((item) => (
              <ReviewCard key={item.id} item={item} isAdmin={false} busy={false} onAccept={() => {}} onReject={() => {}} />
            ))}
          </>
        )}
      </div>
    </div>
  );
}
