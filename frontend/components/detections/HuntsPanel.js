'use client';
import { useState, useEffect, useCallback } from 'react';
import TuningSuggestionBadge, { TuningBulkActionBar } from './TuningSuggestionBadge';
import useTuningSuggestions from './useTuningSuggestions';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const PAGE_SIZE = 24;

function safeHref(url) {
  if (!url) return '#';
  try { return ['http:', 'https:'].includes(new URL(url).protocol) ? url : '#'; }
  catch { return '#'; }
}

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
          // Clipboard API unavailable (e.g. insecure context) -- no-op,
          // the KQL is still fully visible and selectable in the <pre>.
        }
      }}
      className="text-[10px] border border-border rounded-sm px-2 py-0.5 text-text-dim hover:text-text hover:bg-background transition-colors"
    >
      {copied ? 'Copied' : 'Copy KQL'}
    </button>
  );
}

function detectionLabel(item) {
  return item.name || `Unnamed — ${item.technique_id}`;
}

function SentinelSyncBadge({ hunt }) {
  const synced = !!hunt.sentinel_hunt_id;
  return (
    <span
      title={synced ? `Synced ${hunt.sentinel_synced_at}` : 'Not yet synced to Sentinel'}
      className={[
        'inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border',
        synced
          ? 'bg-green-950 text-green-300 border-green-800'
          : 'bg-surface text-text-dim border-border',
      ].join(' ')}
    >
      {synced ? 'SYNCED TO SENTINEL' : 'NOT SYNCED'}
    </span>
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

function HuntCard({ hunt, onOpen }) {
  return (
    <div
      onClick={onOpen}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') onOpen(); }}
      className="border border-border rounded-sm bg-surface p-4 flex flex-col cursor-pointer hover:border-accent transition-colors"
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-sm font-bold text-text leading-tight underline decoration-dotted">{hunt.title}</div>
        <SentinelSyncBadge hunt={hunt} />
      </div>
      {hunt.source_name && (
        <div className="text-[10px] text-text-dim mb-2">
          {hunt.source_name}{hunt.source_severity ? ` · ${hunt.source_severity}` : ''}
        </div>
      )}
      {hunt.description && (
        <div className="text-[11px] text-text-dim mb-3 line-clamp-3">{hunt.description}</div>
      )}
      <div className="flex flex-wrap gap-1 mb-2">
        {(hunt.techniques || []).map((t) => (
          <span
            key={t.technique_id}
            className="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border bg-accent/10 text-accent border-accent/40"
          >
            {t.technique_id}
          </span>
        ))}
      </div>
      <div className="mt-auto flex items-center justify-between text-[11px] text-text-dim">
        <span>{hunt.detection_count} detection{hunt.detection_count === 1 ? '' : 's'}</span>
        <ReviewStateSummary counts={hunt.review_state_counts} />
      </div>
      {hunt.eligible_count > 0 && (
        <div className="mt-1.5 text-[10px] font-bold text-green-400">
          {hunt.eligible_count} ready to deploy
        </div>
      )}
    </div>
  );
}

function DetectionCard({ item, isAdmin, selected, onToggleSelect, onApply, onDismiss, tuningBusy }) {
  return (
    <div className="border border-border rounded-sm bg-surface p-4 flex flex-col">
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="text-sm font-bold text-text leading-tight">{detectionLabel(item)}</div>
        <span className="shrink-0 inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border bg-accent/10 text-accent border-accent/40">
          {item.technique_id}
        </span>
      </div>
      <div className="text-[11px] text-text-dim mb-3">{item.technique_name}</div>
      {item.description && (
        <div className="text-[11px] text-text-dim mb-3">{item.description}</div>
      )}
      <div className="flex items-center justify-between mb-1">
        <div className="text-[10px] font-bold text-text-dim tracking-wider">KQL</div>
        {item.kql_body && <CopyButton text={item.kql_body} />}
      </div>
      <pre className="text-[10px] bg-background border border-border rounded-sm p-2 overflow-x-auto whitespace-pre-wrap flex-1">
        {item.kql_body || '—'}
      </pre>
      <div className="flex items-center gap-2 mt-3 text-[10px] text-text-dim">
        <span className="inline-block px-1.5 py-0.5 rounded-sm font-bold border bg-green-950 text-green-300 border-green-800">
          {(item.review_state || 'pending').toUpperCase()}
        </span>
        {item.backtest_disposition && (
          <span className="inline-block px-1.5 py-0.5 rounded-sm font-bold border bg-surface text-text-dim border-border">
            {item.backtest_disposition.toUpperCase()}
          </span>
        )}
        <span className="font-mono">created {item.created_at}</span>
      </div>
      <TuningSuggestionBadge
        item={item}
        isAdmin={isAdmin}
        selected={selected}
        onToggleSelect={onToggleSelect}
        onApply={onApply}
        onDismiss={onDismiss}
        busy={tuningBusy}
      />
    </div>
  );
}

function DeployTargetPicker({ hunt, sentinelTargets, onSetTarget, targetSaving, targetError }) {
  const targets = sentinelTargets?.hunts || [];
  return (
    <div className="mt-2">
      <label className="flex items-center gap-1.5 text-[10px] text-text-dim">
        Deploy target
        <select
          value={hunt.target_sentinel_hunt_id || ''}
          onChange={(e) => onSetTarget(e.target.value || null)}
          disabled={targetSaving}
          className="bg-background border border-border rounded-sm px-1.5 py-0.5 text-[10px] text-text disabled:opacity-40"
        >
          <option value="">Create new Sentinel Hunt</option>
          {targets.map((t) => (
            <option key={t.id} value={t.id}>{t.display_name || t.id}</option>
          ))}
        </select>
      </label>
      {targetError && <div className="text-[10px] text-red-400 mt-0.5">{targetError}</div>}
    </div>
  );
}

function HuntDetail({
  hunt, onBack, isAdmin, onDeploy, deploying, deployError, tuning,
  sentinelTargets, onSetTarget, targetSaving, targetError,
}) {
  const synced = !!hunt.sentinel_hunt_id;
  return (
    <div>
      <button
        onClick={onBack}
        className="text-xs text-accent mb-4 hover:underline"
      >
        ← Back to hunts
      </button>

      <div className="mb-4">
        <div className="flex items-start justify-between gap-2">
          <div className="text-lg font-bold text-text">{hunt.title}</div>
          {isAdmin && (
            <button
              onClick={onDeploy}
              disabled={deploying}
              className="shrink-0 text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {deploying ? 'Deploying…' : synced ? 'Re-deploy to Sentinel' : 'Deploy to Sentinel'}
            </button>
          )}
        </div>
        {hunt.source_link && (
          <a
            href={safeHref(hunt.source_link)}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] text-accent hover:underline"
          >
            {hunt.source_title || hunt.source_link}
          </a>
        )}
        <div className="text-[10px] text-text-dim mt-1">
          {hunt.source_name}{hunt.source_severity ? ` · ${hunt.source_severity}` : ''}
        </div>
        {hunt.description && (
          <div className="text-[11px] text-text-dim mt-2">{hunt.description}</div>
        )}
        <div className="mt-2 flex items-center gap-2">
          <SentinelSyncBadge hunt={hunt} />
          {deployError && <span className="text-[11px] text-red-400">{deployError}</span>}
        </div>
        {isAdmin && (
          <DeployTargetPicker
            hunt={hunt}
            sentinelTargets={sentinelTargets}
            onSetTarget={onSetTarget}
            targetSaving={targetSaving}
            targetError={targetError}
          />
        )}
      </div>

      <div className="text-xs font-bold text-text-dim mb-2 tracking-wider">
        ▸ DETECTIONS / QUERIES IN THIS HUNT ({(hunt.detections || []).length})
      </div>

      {isAdmin && tuning && (
        <TuningBulkActionBar
          count={tuning.selectedIds.size}
          busy={tuning.busy}
          error={tuning.error}
          onApply={tuning.applySelected}
          onDismiss={tuning.dismissSelected}
          onClear={tuning.clearSelected}
        />
      )}

      {(hunt.detections || []).length === 0 && (
        <div className="text-xs text-text-dim italic">No detections registered under this hunt yet.</div>
      )}

      {(hunt.detections || []).length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {hunt.detections.map((item) => (
            <DetectionCard
              key={item.id}
              item={item}
              isAdmin={isAdmin}
              selected={tuning ? tuning.selectedIds.has(item.id) : false}
              onToggleSelect={tuning?.toggleSelected}
              onApply={tuning?.applyOne}
              onDismiss={tuning?.dismissOne}
              tuningBusy={tuning?.busy}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// origin_filter values recognized by the client-side filter below (see the
// load() comment for why this is client-side, not a backend query param).
const LOCAL_IMPORT_SOURCE_NAME = 'local-import';

export default function HuntsPanel({
  authFetch, userRole, originFilter,
  title = 'GENERATED HUNTS',
  description,
}) {
  const [items, setItems]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [offset, setOffset]   = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const [techniqueId, setTechniqueId] = useState('');
  const [search, setSearch] = useState('');
  const [readyOnly, setReadyOnly] = useState(false);

  const [selectedHuntId, setSelectedHuntId] = useState(null);
  const [huntDetail, setHuntDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const [deploying, setDeploying] = useState(false);
  const [deployError, setDeployError] = useState(null);

  const [sentinelTargets, setSentinelTargets] = useState(null);
  const [targetSaving, setTargetSaving] = useState(false);
  const [targetError, setTargetError] = useState(null);

  const [deployingAll, setDeployingAll] = useState(false);
  const [deployAllError, setDeployAllError] = useState(null);
  const [deployAllResult, setDeployAllResult] = useState(null);

  const isAdmin = userRole === 'admin';

  // originFilter (e.g. "local_import", from the Local Detections tab) scopes
  // this list to hunts of one origin. GET /api/detections/hunts has no
  // origin query param and its own row shape doesn't even select an
  // `origin` column (see hunts.py's _HUNT_LIST_COLUMNS/list_hunts) -- adding
  // one is a backend change out of scope for this component. Every
  // locally-imported hunt is created with source_name hardcoded to the
  // literal "local-import" (detection_pipeline/local_import.py's
  // get_or_create_hunt() call, never a user-controlled value), and no other
  // hunt-creation path ever sets that exact string (orchestrator.py sets
  // source_name from the TI feed's own name) -- so filtering on the
  // already-returned source_name field client-side is a reliable proxy for
  // origin='local_import' with no backend change needed. Because the filter
  // runs after the page is fetched, a filtered load widens the page to the
  // backend's own 200-row cap and pins offset at 0, and the UI below hides
  // Prev/Next rather than showing confusingly partial pages.
  const effectiveLimit = originFilter ? 200 : PAGE_SIZE;
  const effectiveOffset = originFilter ? 0 : offset;

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(effectiveLimit), offset: String(effectiveOffset) });
    if (techniqueId) params.set('technique_id', techniqueId.trim());
    if (search) params.set('search', search.trim());
    if (readyOnly) params.set('ready_only', 'true');

    authFetch(`${API}/api/detections/hunts?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        const rawItems = data.items || [];
        const scoped = originFilter === 'local_import'
          ? rawItems.filter((h) => h.source_name === LOCAL_IMPORT_SOURCE_NAME)
          : rawItems;
        setItems(scoped);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load hunts.'))
      .finally(() => setLoading(false));
  }, [authFetch, effectiveLimit, effectiveOffset, techniqueId, search, readyOnly, originFilter]);

  useEffect(() => { load(); }, [load]);

  function handleToggleReadyOnly() {
    setReadyOnly((v) => !v);
    setOffset(0);
  }

  const loadHuntDetail = useCallback(() => {
    if (selectedHuntId == null) return;
    setDetailLoading(true);
    setDetailError(null);
    authFetch(`${API}/api/detections/hunts/${selectedHuntId}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => setHuntDetail(data))
      .catch(() => setDetailError('Failed to load hunt detail.'))
      .finally(() => setDetailLoading(false));
  }, [authFetch, selectedHuntId]);

  useEffect(() => { loadHuntDetail(); }, [loadHuntDetail]);

  useEffect(() => {
    if (selectedHuntId == null || !isAdmin) { setSentinelTargets(null); return; }
    authFetch(`${API}/api/detections/hunts/sentinel-targets`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setSentinelTargets)
      .catch(() => setSentinelTargets({ enabled: false, hunts: [], error: 'Failed to load Sentinel hunts.' }));
  }, [authFetch, selectedHuntId, isAdmin]);

  function handleSetTarget(targetSentinelHuntId) {
    if (selectedHuntId == null) return;
    setTargetSaving(true);
    setTargetError(null);
    authFetch(`${API}/api/detections/hunts/${selectedHuntId}/target`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_sentinel_hunt_id: targetSentinelHuntId }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Failed to set deploy target.');
        }
        return r.json();
      })
      .then((data) => setHuntDetail(data))
      .catch((err) => setTargetError(err.message || 'Failed to set deploy target.'))
      .finally(() => setTargetSaving(false));
  }

  const tuning = useTuningSuggestions(authFetch, loadHuntDetail);

  function applyFilters(e) {
    e.preventDefault();
    setOffset(0);
    load();
  }

  function handleDeploy() {
    if (selectedHuntId == null) return;
    setDeploying(true);
    setDeployError(null);
    authFetch(`${API}/api/detections/hunts/${selectedHuntId}/deploy`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Deploy failed.');
        }
        return r.json();
      })
      .then((data) => setHuntDetail(data))
      .catch((err) => setDeployError(err.message || 'Deploy failed.'))
      .finally(() => setDeploying(false));
  }

  function handleDeployAll() {
    setDeployingAll(true);
    setDeployAllError(null);
    setDeployAllResult(null);
    authFetch(`${API}/api/detections/hunts/deploy-all`, { method: 'POST' })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Deploy All failed.');
        }
        return r.json();
      })
      .then((data) => {
        setDeployAllResult(data);
        load();
      })
      .catch((err) => setDeployAllError(err.message || 'Deploy All failed.'))
      .finally(() => setDeployingAll(false));
  }

  if (selectedHuntId != null) {
    return (
      <div className="p-4 overflow-y-auto">
        {detailError && <div className="text-xs text-red-400 mb-3">{detailError}</div>}
        {detailLoading && !huntDetail && <div className="text-xs text-text-dim">Loading hunt…</div>}
        {huntDetail && (
          <HuntDetail
            hunt={huntDetail}
            onBack={() => {
              setSelectedHuntId(null); setHuntDetail(null); setDeployError(null);
              setTargetError(null); tuning.clearSelected();
            }}
            isAdmin={isAdmin}
            onDeploy={handleDeploy}
            deploying={deploying}
            deployError={deployError}
            tuning={tuning}
            sentinelTargets={sentinelTargets}
            onSetTarget={handleSetTarget}
            targetSaving={targetSaving}
            targetError={targetError}
          />
        )}
      </div>
    );
  }

  const canPrev = !originFilter && offset > 0;
  const canNext = !originFilter && offset + PAGE_SIZE < total;
  // Filtering happens client-side after a capped 200-row fetch (see load()),
  // so `items.length` -- not the server's unfiltered `total` -- is the
  // honest count for a scoped view.
  const displayCount = originFilter ? items.length : total;

  return (
    <div className="p-4 overflow-y-auto">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-xs font-bold text-text-dim tracking-wider">
          ▸ {title} ({displayCount})
        </div>
        {/* Deploy All has no origin scoping of its own on the backend -- it
            deploys every eligible hunt, not just the ones shown in a
            filtered view -- so it's hidden here rather than implying it's
            scoped to what's on screen. */}
        {isAdmin && !originFilter && (
          <button
            onClick={handleDeployAll}
            disabled={deployingAll}
            className="shrink-0 text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {deployingAll ? 'Deploying…' : 'Deploy All'}
          </button>
        )}
      </div>
      <div className="text-[11px] text-text-dim mb-4">
        {description || (
          <>
            This app&rsquo;s own AI-generated detections, one hunt per source TI article — click a hunt
            to see every detection/query generated from it. For hunts and queries that already exist in
            the real Sentinel workspace (however they got there), see the Sentinel Hunts tab instead.
          </>
        )}
      </div>
      {originFilter && total > 200 && (
        <div className="text-[10px] text-text-dim italic mb-3">
          Showing local-import hunts found within the 200 most recently created hunts overall —
          older local-import hunts past that cutoff may not appear here.
        </div>
      )}

      {deployAllError && <div className="text-xs text-red-400 mb-3">{deployAllError}</div>}
      {deployAllResult && deployAllResult.enabled === false && (
        <div className="text-xs text-text-dim mb-3 italic">
          Sentinel sync isn&rsquo;t enabled yet — set SENTINEL_HUNTING_SYNC_ENABLED to deploy real hunts.
        </div>
      )}
      {deployAllResult && deployAllResult.enabled && (
        <div className="text-xs text-text-dim mb-3">
          {deployAllResult.total === 0 ? (
            'Every hunt is already up to date — nothing needed deploying.'
          ) : (
            <>
              {deployAllResult.succeeded} succeeded, {deployAllResult.failed.length} failed
              {deployAllResult.failed.length > 0 && ' — see below'}.
              {deployAllResult.failed.length > 0 && (
                <ul className="mt-1 ml-4 list-disc">
                  {deployAllResult.failed.map((f) => (
                    <li key={f.hunt_id}>hunt #{f.hunt_id}: {f.reason}</li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      )}

      <form onSubmit={applyFilters} className="flex flex-wrap items-center gap-2 mb-4">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Hunt name…"
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text w-48"
        />
        <input
          type="text"
          value={techniqueId}
          onChange={(e) => setTechniqueId(e.target.value)}
          placeholder="Technique ID (e.g. T1059)"
          className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text w-48"
        />
        <button type="submit" className="text-xs border border-border rounded-sm px-3 py-1 text-text hover:bg-surface transition-colors">
          Filter
        </button>
        <label className="flex items-center gap-1.5 text-xs text-text-dim cursor-pointer ml-2">
          <input type="checkbox" checked={readyOnly} onChange={handleToggleReadyOnly} />
          Ready to deploy only
        </label>
      </form>

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {loading && <div className="text-xs text-text-dim">Loading hunts…</div>}

      {!loading && items.length === 0 && readyOnly && (
        <div className="text-xs text-text-dim italic">No hunts have a detection ready to deploy yet.</div>
      )}
      {!loading && items.length === 0 && !readyOnly && originFilter && (
        <div className="text-xs text-text-dim italic">No local-import hunts yet — run an import above.</div>
      )}
      {!loading && items.length === 0 && !readyOnly && !originFilter && (
        <div className="text-xs text-text-dim italic">No hunts yet — nothing has been generated into a hunt.</div>
      )}

      {!loading && items.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {items.map((hunt) => (
            <HuntCard key={hunt.id} hunt={hunt} onOpen={() => setSelectedHuntId(hunt.id)} />
          ))}
        </div>
      )}

      {/* Prev/Next only make sense against the server's own unfiltered
          pagination -- a filtered view fetches its single capped page (see
          load()) and has nothing to page through. */}
      {!loading && !originFilter && total > 0 && (
        <div className="flex items-center justify-between mt-4 text-xs text-text-dim">
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
