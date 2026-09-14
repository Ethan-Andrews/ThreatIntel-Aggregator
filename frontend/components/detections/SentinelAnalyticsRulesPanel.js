'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import TuningSuggestionBadge from './TuningSuggestionBadge';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const PAGE_SIZE = 25;

const SEV_CLASSES = {
  High:     'bg-red-950 text-red-300 border-red-800',
  Medium:   'bg-yellow-950 text-yellow-300 border-yellow-800',
  Low:      'bg-gray-800 text-gray-400 border-gray-600',
  Informational: 'bg-surface text-text-dim border-border',
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          // Clipboard API unavailable -- the KQL is still visible/selectable.
        }
      }}
      className="text-[10px] border border-border rounded px-2 py-0.5 text-text-dim hover:text-text hover:bg-background transition-colors"
    >
      {copied ? 'Copied' : 'Copy KQL'}
    </button>
  );
}

function ReviewStateBadge({ state }) {
  const colors = {
    approved: 'bg-green-950 text-green-300 border-green-800',
    rejected: 'bg-red-950 text-red-300 border-red-800',
    pending: 'bg-surface text-text-dim border-border',
  };
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border',
      colors[state] || colors.pending,
    ].join(' ')}>
      {(state || 'pending').toUpperCase()}
    </span>
  );
}

function SeverityBadge({ severity }) {
  if (!severity) return null;
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border shrink-0',
      SEV_CLASSES[severity] || SEV_CLASSES.Informational,
    ].join(' ')}>
      {severity.toUpperCase()}
    </span>
  );
}

function RuleRow({
  rule, isAdmin, expanded, onToggleExpand, onTest, onTune, onReview,
  onApplyTune, onDismissTune, busy,
}) {
  return (
    <div className="border border-border rounded bg-surface">
      <div
        onClick={onToggleExpand}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter') onToggleExpand(); }}
        className="flex items-center justify-between gap-2 p-3 cursor-pointer hover:bg-background transition-colors"
      >
        <div className="min-w-0 flex items-center gap-2">
          <SeverityBadge severity={rule.severity} />
          <div className="min-w-0">
            <div className="text-xs font-bold text-text truncate">{rule.display_name}</div>
            {rule.description && (
              <div className="text-[10px] text-text-dim truncate">{rule.description}</div>
            )}
          </div>
          {!rule.enabled && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface text-text-dim border border-border shrink-0">
              DISABLED
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {rule.backtest_disposition && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-surface text-text-dim border-border">
              {rule.backtest_disposition.toUpperCase()}
            </span>
          )}
          <ReviewStateBadge state={rule.review_state} />
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border p-3">
          {rule.kql_body == null ? (
            <div className="text-[11px] text-text-dim italic">Loading…</div>
          ) : (
            <>
              <div className="flex items-center gap-1 flex-wrap mb-2">
                {(rule.tactics || []).map((t) => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-background text-text-dim border border-border">
                    {t}
                  </span>
                ))}
                {(rule.techniques || []).map((t) => (
                  <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/40 font-bold">
                    {t}
                  </span>
                ))}
              </div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] font-bold text-text-dim tracking-wider">KQL</div>
                <CopyButton text={rule.kql_body} />
              </div>
              <pre className="text-[10px] bg-background border border-border rounded p-2 overflow-x-auto whitespace-pre-wrap mb-3">
                {rule.kql_body || '—'}
              </pre>

              {rule.control_probe_result && (
                <div className="text-[10px] text-text-dim mb-2">
                  gate: {rule.control_probe_result.gate_verdict}
                  {rule.control_probe_result.disposition && ` · telemetry: ${rule.control_probe_result.disposition}`}
                  {rule.control_probe_result.error && ` · error: ${rule.control_probe_result.error}`}
                </div>
              )}
              {rule.tune_history && (
                <div className="text-[10px] text-text-dim mb-2">
                  tune: {rule.tune_history.disposition}
                </div>
              )}
              <TuningSuggestionBadge
                item={{ ...rule, name: rule.display_name, technique_id: rule.sentinel_rule_id }}
                isAdmin={isAdmin}
                onApply={onApplyTune}
                onDismiss={onDismissTune}
                busy={busy}
              />

              {isAdmin && (
                <div className="flex items-center gap-2 mt-2">
                  <button
                    onClick={() => onTest(rule.id)}
                    disabled={busy}
                    className="text-[10px] border border-accent text-accent rounded px-2 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => onTune(rule.id)}
                    disabled={busy || rule.backtest_disposition !== 'needs_tuning'}
                    className="text-[10px] border border-border rounded px-2 py-1 text-text hover:bg-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Tune
                  </button>
                  <select
                    value={rule.review_state || 'pending'}
                    onChange={(e) => onReview(rule.id, e.target.value)}
                    disabled={busy}
                    className="text-[10px] bg-background border border-border rounded px-1.5 py-1 text-text"
                  >
                    <option value="pending">Pending</option>
                    <option value="approved">Approved</option>
                    <option value="rejected">Rejected</option>
                  </select>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Pager({ offset, pageSize, total, onPrev, onNext }) {
  if (total === 0) return null;
  return (
    <div className="flex items-center justify-between mt-4 text-xs text-text-dim">
      <span>{offset + 1}–{Math.min(offset + pageSize, total)} of {total}</span>
      <div className="flex gap-2">
        <button
          onClick={onPrev}
          disabled={offset === 0}
          className="border border-border rounded px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
        >
          Prev
        </button>
        <button
          onClick={onNext}
          disabled={offset + pageSize >= total}
          className="border border-border rounded px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

export default function SentinelAnalyticsRulesPanel({ authFetch, userRole }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [reviewFilter, setReviewFilter] = useState('');
  const [needsTuningOnly, setNeedsTuningOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [expandedDetail, setExpandedDetail] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [actionError, setActionError] = useState(null);

  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);
  const [syncError, setSyncError] = useState(null);

  const isAdmin = userRole === 'admin';

  // Same request-sequencing guard as SentinelHuntsPanel.js -- a slow,
  // in-flight detail fetch must not clobber a fresher Test/Tune/Review
  // response that resolved first.
  const requestSeqRef = useRef({});
  const bumpSeq = (id) => { const s = (requestSeqRef.current[id] || 0) + 1; requestSeqRef.current[id] = s; return s; };
  const isCurrent = (id, seq) => requestSeqRef.current[id] === seq;

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    if (reviewFilter) params.set('review_state', reviewFilter);
    if (needsTuningOnly) params.set('disposition', 'needs_tuning');
    if (search) params.set('search', search);

    authFetch(`${API}/api/sentinel-analytics-rules?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load Sentinel analytics rules.'))
      .finally(() => setLoading(false));
  }, [authFetch, offset, reviewFilter, needsTuningOnly, search]);

  useEffect(() => { load(); }, [load]);

  function handleSearchSubmit(e) {
    e.preventDefault();
    setOffset(0);
    setSearch(searchInput.trim());
  }

  function toggleExpand(ruleId) {
    if (expandedId === ruleId) {
      setExpandedId(null);
      setExpandedDetail(null);
      return;
    }
    setExpandedId(ruleId);
    setExpandedDetail(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => { if (isCurrent(ruleId, seq)) setExpandedDetail(data); })
      .catch(() => setActionError('Failed to load rule detail.'));
  }

  function refreshExpanded(ruleId, seq, data) {
    if (!isCurrent(ruleId, seq)) return;
    setExpandedDetail(data);
    setItems((prev) => prev.map((r) => (r.id === data.id ? { ...r, ...data } : r)));
  }

  function handleTest(ruleId) {
    setBusyId(ruleId);
    setActionError(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}/test`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Test failed.');
        }
        return r.json();
      })
      .then((data) => refreshExpanded(ruleId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleTune(ruleId) {
    setBusyId(ruleId);
    setActionError(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}/tune`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Tune failed.');
        }
        return r.json();
      })
      .then((data) => refreshExpanded(ruleId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleReview(ruleId, reviewState) {
    setBusyId(ruleId);
    setActionError(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}/review`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ review_state: reviewState }),
    })
      .then(async (r) => {
        if (!r.ok) throw new Error('Review update failed.');
        return r.json();
      })
      .then((data) => refreshExpanded(ruleId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleApplyTune(ruleId) {
    setBusyId(ruleId);
    setActionError(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}/tuning-suggestion/apply`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Apply failed.');
        }
        return r.json();
      })
      .then(({ result, rule }) => {
        refreshExpanded(ruleId, seq, rule);
        if (!result.success) setActionError(result.reason || 'Apply failed.');
      })
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleDismissTune(ruleId) {
    setBusyId(ruleId);
    setActionError(null);
    const seq = bumpSeq(ruleId);
    authFetch(`${API}/api/sentinel-analytics-rules/${ruleId}/tuning-suggestion/dismiss`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Dismiss failed.');
        }
        return r.json();
      })
      .then(({ result, rule }) => {
        refreshExpanded(ruleId, seq, rule);
        if (!result.success) setActionError(result.reason || 'Dismiss failed.');
      })
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleSync() {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    authFetch(`${API}/api/sentinel-analytics-rules/sync`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Sync failed.');
        }
        return r.json();
      })
      .then((data) => {
        setSyncResult(data);
        load();
      })
      .catch((err) => setSyncError(err.message || 'Sync failed.'))
      .finally(() => setSyncing(false));
  }

  return (
    <div className="p-4 overflow-y-auto">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-xs font-bold text-text-dim tracking-wider">
          ▸ SENTINEL ANALYTICS RULES ({total})
        </div>
        {isAdmin && (
          <button
            onClick={handleSync}
            disabled={syncing}
            className="shrink-0 text-xs border border-accent text-accent rounded px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {syncing ? 'Syncing…' : 'Sync now'}
          </button>
        )}
      </div>
      <div className="text-[11px] text-text-dim mb-4">
        Scheduled Analytics Rules already in Microsoft Sentinel — the rules that create incidents,
        pulled read-only. Distinct from Generated Hunts (this app&rsquo;s own AI-generated
        detections) and Sentinel Hunts (hunting queries) — this is Sentinel&rsquo;s
        incident-generating rule set, a different resource type from a hunting query.
      </div>

      {syncError && <div className="text-xs text-red-400 mb-3">{syncError}</div>}
      {syncResult && syncResult.enabled === false && (
        <div className="text-xs text-text-dim mb-3 italic">
          Sentinel sync isn&rsquo;t enabled yet — set SENTINEL_HUNTING_SYNC_ENABLED to sync real data.
        </div>
      )}
      {syncResult && syncResult.enabled && (
        <div className="text-xs text-text-dim mb-3">
          Synced {syncResult.rules_synced} rule{syncResult.rules_synced === 1 ? '' : 's'}
          {syncResult.skipped_kinds > 0 && ` (${syncResult.skipped_kinds} non-Scheduled rule(s) skipped — no KQL to test)`}.
          {syncResult.errors.length > 0 && ` ${syncResult.errors.length} error(s) — see logs.`}
        </div>
      )}

      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <label className="text-[11px] text-text-dim">Filter:</label>
        <select
          value={reviewFilter}
          onChange={(e) => { setReviewFilter(e.target.value); setOffset(0); }}
          className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
        >
          <option value="">All</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
        <label className="flex items-center gap-1.5 text-[11px] text-text-dim cursor-pointer">
          <input
            type="checkbox"
            checked={needsTuningOnly}
            onChange={(e) => { setNeedsTuningOnly(e.target.checked); setOffset(0); }}
          />
          Needs tuning only
        </label>
        <form onSubmit={handleSearchSubmit} className="flex items-center gap-1.5 ml-auto">
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search rule names…"
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text w-56"
          />
          <button
            type="submit"
            className="text-[10px] border border-border rounded px-2 py-1 text-text-dim hover:text-text hover:bg-background transition-colors"
          >
            Search
          </button>
        </form>
      </div>

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {actionError && <div className="text-xs text-red-400 mb-3">{actionError}</div>}
      {loading && <div className="text-xs text-text-dim">Loading…</div>}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">
          No Sentinel analytics rules synced yet{isAdmin ? ' — click "Sync now" to pull the workspace’s rule set.' : '.'}
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="flex flex-col gap-2">
          {items.map((rule) => (
            <RuleRow
              key={rule.id}
              rule={expandedId === rule.id && expandedDetail ? expandedDetail : rule}
              isAdmin={isAdmin}
              expanded={expandedId === rule.id}
              onToggleExpand={() => toggleExpand(rule.id)}
              onTest={handleTest}
              onTune={handleTune}
              onReview={handleReview}
              onApplyTune={handleApplyTune}
              onDismissTune={handleDismissTune}
              busy={busyId === rule.id}
            />
          ))}
        </div>
      )}

      <Pager
        offset={offset}
        pageSize={PAGE_SIZE}
        total={total}
        onPrev={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        onNext={() => setOffset(offset + PAGE_SIZE)}
      />
    </div>
  );
}
