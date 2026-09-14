'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import TuningSuggestionBadge from './TuningSuggestionBadge';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const HUNT_PAGE_SIZE = 24;
const QUERY_PAGE_SIZE = 25;

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

function ReviewStateSummary({ counts }) {
  const entries = Object.entries(counts || {});
  if (entries.length === 0) return null;
  return (
    <div className="flex gap-1.5 flex-wrap">
      {entries.map(([state, count]) => (
        <span key={state} className="text-[10px] text-text-dim">
          {count} {state}
        </span>
      ))}
    </div>
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

function SentinelHuntCard({ hunt, onOpen }) {
  return (
    <div
      onClick={onOpen}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') onOpen(); }}
      className="border border-border rounded bg-surface p-4 flex flex-col cursor-pointer hover:border-accent transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-sm font-bold text-text leading-tight underline decoration-dotted">{hunt.display_name}</div>
        <div className="shrink-0 flex items-center gap-1.5">
          {hunt.tunable_count > 0 && (
            <span
              title="Queries where Tune is currently enabled (backtest disposition: needs_tuning)"
              className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-yellow-950 text-yellow-300 border-yellow-800"
            >
              {hunt.tunable_count} tunable
            </span>
          )}
          {hunt.status && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-accent/10 text-accent border-accent/40">
              {hunt.status}
            </span>
          )}
        </div>
      </div>
      {hunt.description && (
        <div className="text-[11px] text-text-dim mb-3 line-clamp-3">{hunt.description}</div>
      )}
      <div className="flex flex-wrap gap-1 mb-2">
        {(hunt.attack_techniques || []).map((t) => (
          <span
            key={t}
            className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-accent/10 text-accent border-accent/40"
          >
            {t}
          </span>
        ))}
      </div>
      <div className="mt-auto flex items-center justify-between text-[11px] text-text-dim">
        <span>{hunt.query_count} quer{hunt.query_count === 1 ? 'y' : 'ies'}</span>
        <ReviewStateSummary counts={hunt.review_state_counts} />
      </div>
    </div>
  );
}

function QueryRow({
  query, isAdmin, expanded, onToggleExpand, onTest, onTune, onReview,
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
        <div className="min-w-0">
          <div className="text-xs font-bold text-text truncate">{query.display_name}</div>
          {query.description && (
            <div className="text-[10px] text-text-dim truncate">{query.description}</div>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {query.backtest_disposition && (
            <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-surface text-text-dim border-border">
              {query.backtest_disposition.toUpperCase()}
            </span>
          )}
          <ReviewStateBadge state={query.review_state} />
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border p-3">
          {query.kql_body == null ? (
            <div className="text-[11px] text-text-dim italic">Loading…</div>
          ) : (
            <>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] font-bold text-text-dim tracking-wider">KQL</div>
                <CopyButton text={query.kql_body} />
              </div>
              <pre className="text-[10px] bg-background border border-border rounded p-2 overflow-x-auto whitespace-pre-wrap mb-3">
                {query.kql_body || '—'}
              </pre>

              {query.control_probe_result && (
                <div className="text-[10px] text-text-dim mb-2">
                  gate: {query.control_probe_result.gate_verdict}
                  {query.control_probe_result.disposition && ` · telemetry: ${query.control_probe_result.disposition}`}
                  {query.control_probe_result.error && ` · error: ${query.control_probe_result.error}`}
                </div>
              )}
              {query.tune_history && (
                <div className="text-[10px] text-text-dim mb-2">
                  tune: {query.tune_history.disposition}
                </div>
              )}
              <TuningSuggestionBadge
                item={{ ...query, name: query.display_name, technique_id: query.sentinel_saved_search_id }}
                isAdmin={isAdmin}
                onApply={onApplyTune}
                onDismiss={onDismissTune}
                busy={busy}
              />

              {isAdmin && (
                <div className="flex items-center gap-2 mt-2">
                  <button
                    onClick={() => onTest(query.id)}
                    disabled={busy}
                    className="text-[10px] border border-accent text-accent rounded px-2 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40"
                  >
                    Test
                  </button>
                  <button
                    onClick={() => onTune(query.id)}
                    disabled={busy || query.backtest_disposition !== 'needs_tuning'}
                    className="text-[10px] border border-border rounded px-2 py-1 text-text hover:bg-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Tune
                  </button>
                  <select
                    value={query.review_state || 'pending'}
                    onChange={(e) => onReview(query.id, e.target.value)}
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

function HuntQueryList({ hunt, authFetch, isAdmin, onBack }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reviewFilter, setReviewFilter] = useState('');
  const [needsTuningOnly, setNeedsTuningOnly] = useState(false);
  const [querySearch, setQuerySearch] = useState('');
  const [querySearchInput, setQuerySearchInput] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [expandedDetail, setExpandedDetail] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [actionError, setActionError] = useState(null);

  // Expand/collapse (GET) and the Test/Tune/Review actions (POST/PATCH) for
  // the same query race independently -- nothing stops a user from
  // collapsing and re-expanding a row while a slow Test call is still in
  // flight. Without sequencing, whichever response resolves LAST wins the
  // `setExpandedDetail` call, even if it's the stale pre-test snapshot the
  // earlier GET fetched before the test's write ever committed -- confirmed
  // live 2026-09-01: a fresh Test result (last_tested_at from the POST
  // response) got silently clobbered by an in-flight GET's older
  // last_tested_at once the row was re-expanded. requestSeqRef tracks the
  // most recent request issued per query id so a response can check "am I
  // still the latest?" before applying itself.
  const requestSeqRef = useRef({});

  function bumpSeq(queryId) {
    const seq = (requestSeqRef.current[queryId] || 0) + 1;
    requestSeqRef.current[queryId] = seq;
    return seq;
  }

  function isCurrent(queryId, seq) {
    return requestSeqRef.current[queryId] === seq;
  }

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(QUERY_PAGE_SIZE), offset: String(offset) });
    if (reviewFilter) params.set('review_state', reviewFilter);
    if (needsTuningOnly) params.set('disposition', 'needs_tuning');
    if (querySearch) params.set('search', querySearch);

    authFetch(`${API}/api/sentinel-hunts/${hunt.id}/queries?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load queries.'))
      .finally(() => setLoading(false));
  }, [authFetch, hunt.id, offset, reviewFilter, needsTuningOnly, querySearch]);

  useEffect(() => { load(); }, [load]);

  function handleQuerySearchSubmit(e) {
    e.preventDefault();
    setOffset(0);
    setQuerySearch(querySearchInput.trim());
  }

  function toggleExpand(queryId) {
    if (expandedId === queryId) {
      setExpandedId(null);
      setExpandedDetail(null);
      return;
    }
    setExpandedId(queryId);
    setExpandedDetail(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => { if (isCurrent(queryId, seq)) setExpandedDetail(data); })
      .catch(() => setActionError('Failed to load query detail.'));
  }

  function refreshExpanded(queryId, seq, data) {
    if (!isCurrent(queryId, seq)) return;
    setExpandedDetail(data);
    setItems((prev) => prev.map((q) => (q.id === data.id ? { ...q, ...data } : q)));
  }

  function handleTest(queryId) {
    setBusyId(queryId);
    setActionError(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}/test`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Test failed.');
        }
        return r.json();
      })
      .then((data) => refreshExpanded(queryId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleTune(queryId) {
    setBusyId(queryId);
    setActionError(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}/tune`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Tune failed.');
        }
        return r.json();
      })
      .then((data) => refreshExpanded(queryId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleApplyTune(queryId) {
    setBusyId(queryId);
    setActionError(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}/tuning-suggestion/apply`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Apply failed.');
        }
        return r.json();
      })
      .then(({ result, query }) => {
        refreshExpanded(queryId, seq, query);
        if (!result.success) setActionError(result.reason || 'Apply failed.');
      })
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleDismissTune(queryId) {
    setBusyId(queryId);
    setActionError(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}/tuning-suggestion/dismiss`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Dismiss failed.');
        }
        return r.json();
      })
      .then(({ result, query }) => {
        refreshExpanded(queryId, seq, query);
        if (!result.success) setActionError(result.reason || 'Dismiss failed.');
      })
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  function handleReview(queryId, reviewState) {
    setBusyId(queryId);
    setActionError(null);
    const seq = bumpSeq(queryId);
    authFetch(`${API}/api/sentinel-hunts/queries/${queryId}/review`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ review_state: reviewState }),
    })
      .then(async (r) => {
        if (!r.ok) throw new Error('Review update failed.');
        return r.json();
      })
      .then((data) => refreshExpanded(queryId, seq, data))
      .catch((err) => setActionError(err.message))
      .finally(() => setBusyId(null));
  }

  return (
    <div>
      <button onClick={onBack} className="text-xs text-accent mb-4 hover:underline">
        ← Back to Sentinel hunts
      </button>

      <div className="mb-4">
        <div className="text-lg font-bold text-text">{hunt.display_name}</div>
        {hunt.description && <div className="text-[11px] text-text-dim mt-1">{hunt.description}</div>}
      </div>

      <div className="text-xs font-bold text-text-dim mb-2 tracking-wider">
        ▸ QUERIES IN THIS HUNT ({total})
      </div>

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
        <form onSubmit={handleQuerySearchSubmit} className="flex items-center gap-1.5 ml-auto">
          <input
            type="text"
            value={querySearchInput}
            onChange={(e) => setQuerySearchInput(e.target.value)}
            placeholder="Search query names…"
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
      {loading && <div className="text-xs text-text-dim">Loading queries…</div>}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">No queries match this filter.</div>
      )}

      {!loading && items.length > 0 && (
        <div className="flex flex-col gap-2">
          {items.map((query) => (
            <QueryRow
              key={query.id}
              query={expandedId === query.id && expandedDetail ? expandedDetail : query}
              isAdmin={isAdmin}
              expanded={expandedId === query.id}
              onToggleExpand={() => toggleExpand(query.id)}
              onTest={handleTest}
              onTune={handleTune}
              onReview={handleReview}
              onApplyTune={handleApplyTune}
              onDismissTune={handleDismissTune}
              busy={busyId === query.id}
            />
          ))}
        </div>
      )}

      <Pager
        offset={offset}
        pageSize={QUERY_PAGE_SIZE}
        total={total}
        onPrev={() => setOffset(Math.max(0, offset - QUERY_PAGE_SIZE))}
        onNext={() => setOffset(offset + QUERY_PAGE_SIZE)}
      />
    </div>
  );
}

export default function SentinelHuntsPanel({ authFetch, userRole }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [selectedHunt, setSelectedHunt] = useState(null);

  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);
  const [syncError, setSyncError] = useState(null);

  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');

  const isAdmin = userRole === 'admin';

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(HUNT_PAGE_SIZE), offset: String(offset) });
    if (search) params.set('search', search);

    authFetch(`${API}/api/sentinel-hunts?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load Sentinel hunts.'))
      .finally(() => setLoading(false));
  }, [authFetch, offset, search]);

  useEffect(() => { load(); }, [load]);

  function handleSearchSubmit(e) {
    e.preventDefault();
    setOffset(0);
    setSearch(searchInput.trim());
  }

  function handleSync() {
    setSyncing(true);
    setSyncError(null);
    setSyncResult(null);
    authFetch(`${API}/api/sentinel-hunts/sync`, { method: 'POST' })
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

  if (selectedHunt != null) {
    return (
      <div className="p-4 overflow-y-auto">
        <HuntQueryList
          hunt={selectedHunt}
          authFetch={authFetch}
          isAdmin={isAdmin}
          onBack={() => setSelectedHunt(null)}
        />
      </div>
    );
  }

  return (
    <div className="p-4 overflow-y-auto">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-xs font-bold text-text-dim tracking-wider">
          ▸ SENTINEL HUNTS ({total})
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
        The actual hunts and stored hunting queries already in Microsoft Sentinel — pulled
        read-only, separate from this app&rsquo;s own AI-generated Generated Hunts tab. Click a
        hunt to page through its queries. For Sentinel&rsquo;s incident-generating Analytics
        Rules (a different resource type from a hunting query), see the Sentinel Analytics
        Rules tab instead.
      </div>

      <form onSubmit={handleSearchSubmit} className="flex items-center gap-1.5 mb-3">
        <input
          type="text"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search hunt names…"
          className="text-xs bg-background border border-border rounded px-2 py-1 text-text w-56"
        />
        <button
          type="submit"
          className="text-[10px] border border-border rounded px-2 py-1 text-text-dim hover:text-text hover:bg-background transition-colors"
        >
          Search
        </button>
      </form>

      {syncError && <div className="text-xs text-red-400 mb-3">{syncError}</div>}
      {syncResult && syncResult.enabled === false && (
        <div className="text-xs text-text-dim mb-3 italic">
          Sentinel Hunting sync isn&rsquo;t enabled yet — set SENTINEL_HUNTING_SYNC_ENABLED to sync real data.
        </div>
      )}
      {syncResult && syncResult.enabled && (
        <div className="text-xs text-text-dim mb-3">
          Synced {syncResult.hunts_synced} hunt{syncResult.hunts_synced === 1 ? '' : 's'},{' '}
          {syncResult.queries_synced} quer{syncResult.queries_synced === 1 ? 'y' : 'ies'}.
          {(syncResult.hunts_removed > 0 || syncResult.queries_removed > 0) && (
            <>
              {' '}Removed {syncResult.hunts_removed} hunt{syncResult.hunts_removed === 1 ? '' : 's'}{' '}
              and {syncResult.queries_removed} quer{syncResult.queries_removed === 1 ? 'y' : 'ies'}{' '}
              no longer in Sentinel.
            </>
          )}
          {syncResult.errors.length > 0 && ` ${syncResult.errors.length} error(s) — see logs.`}
          {syncResult.sweep_skipped_hunts && syncResult.sweep_skipped_hunts.length > 0 && (
            <div className="text-amber-400 mt-1">
              {syncResult.sweep_skipped_hunts.length} hunt{syncResult.sweep_skipped_hunts.length === 1 ? '' : 's'}{' '}
              skipped this sweep (fetch error) — their queries were left unchanged.
            </div>
          )}
        </div>
      )}

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {loading && <div className="text-xs text-text-dim">Loading Sentinel hunts…</div>}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">
          No Sentinel hunts synced yet{isAdmin ? ' — click "Sync now" to pull the workspace’s inventory.' : '.'}
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {items.map((hunt) => (
            <SentinelHuntCard key={hunt.id} hunt={hunt} onOpen={() => setSelectedHunt(hunt)} />
          ))}
        </div>
      )}

      <Pager
        offset={offset}
        pageSize={HUNT_PAGE_SIZE}
        total={total}
        onPrev={() => setOffset(Math.max(0, offset - HUNT_PAGE_SIZE))}
        onNext={() => setOffset(offset + HUNT_PAGE_SIZE)}
      />
    </div>
  );
}
