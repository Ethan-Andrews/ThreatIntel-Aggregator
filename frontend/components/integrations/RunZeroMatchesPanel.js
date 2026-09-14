'use client';
import { useState, useEffect, useCallback, useRef } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const CST = 'America/Chicago';

function safeLinkHref(link) {
  if (!link) return '#';
  try {
    const url = new URL(link);
    if (url.protocol === 'https:' || url.protocol === 'http:') return link;
  } catch {}
  return '#';
}

function parseMatchDetails(raw) {
  let details = [];
  if (Array.isArray(raw)) {
    details = raw;
  } else if (typeof raw === 'string') {
    try { details = JSON.parse(raw); } catch { details = []; }
  }
  const byAsset = {};
  for (const d of details) {
    const id = d.asset_id || '';
    if (!byAsset[id]) {
      byAsset[id] = { ...d, reasons: [] };
    }
    byAsset[id].reasons.push({ type: d.match_type, detail: d.detail });
  }
  return Object.values(byAsset);
}

const MATCH_ICON = { cve: '🔴', software: '🟡', os: '🟡', ip: '🟡' };
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

function buildRunZeroSearchUrl(matchDetails) {
  const assets = parseMatchDetails(matchDetails);
  if (!assets.length) return null;
  const terms = [];
  for (const a of assets) {
    if (a.hostname) {
      terms.push(`name:=${a.hostname}`);
    } else {
      try {
        const ips = JSON.parse(a.addresses || '[]');
        if (ips[0]) terms.push(`address:${ips[0]}`);
      } catch {}
    }
  }
  if (!terms.length) return null;
  return `https://console.runzero.com/inventory?search=${encodeURIComponent(terms.join(' OR '))}`;
}

function AssetDetailPanel({ matchDetails }) {
  const assets = parseMatchDetails(matchDetails);
  if (!assets.length) return null;
  return (
    <div className="mt-2 border-t border-gray-700 pt-2 space-y-2">
      {assets.map((a) => {
        let addresses = [];
        try { addresses = JSON.parse(a.addresses || '[]'); } catch {}
        let tags = [];
        try { tags = JSON.parse(a.tags || '[]'); } catch {}
        const label = a.hostname || a.asset_id;
        const orgSite = [a.org, a.site].filter(Boolean).join(' / ');
        return (
          <div key={a.asset_id} className="bg-gray-900 rounded-sm p-2 text-xs">
            <div className="flex items-start justify-between gap-2 mb-0.5">
              <span className="text-white font-medium">{label}</span>
              <span className="text-gray-400 text-right">{orgSite}</span>
            </div>
            {addresses.length > 0 && (
              <div className="text-gray-400 mb-0.5">{addresses.join(', ')}</div>
            )}
            {a.os && <div className="text-gray-500 mb-0.5">{a.os}</div>}
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {tags.map(t => (
                  <span key={t} className="px-1 py-0.5 rounded-sm bg-gray-700 text-gray-300 border border-gray-600 text-[10px]">
                    {t}
                  </span>
                ))}
              </div>
            )}
            <div className="space-y-0.5">
              {(a.reasons || []).map((r, i) => (
                <div key={i} className="text-gray-400">
                  {MATCH_ICON[r.type] || '•'} {r.detail}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function RunZeroMatchesPanel({ apiKey, userRole }) {
  const [status, setStatus]               = useState({});
  const [matches, setMatches]             = useState([]);
  const [filter, setFilter]               = useState('all');
  const [syncing, setSyncing]             = useState(false);
  const [loading, setLoading]             = useState(true);
  const [expandedHash, setExpandedHash]   = useState(null);
  const [searchInput, setSearchInput]     = useState('');
  const [assetSearch, setAssetSearch]     = useState('');
  const [severities, setSeverities]       = useState([]);
  const [dateFrom, setDateFrom]           = useState('');
  const [dateTo, setDateTo]               = useState('');
  const [kevOnly, setKevOnly]             = useState(false);
  const debounceRef = useRef(null);

  const headers = { Authorization: `Bearer ${apiKey}` };

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/integrations/runzero/status`, { headers });
      if (res.ok) setStatus(await res.json());
    } catch {}
  }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchMatches = useCallback(async (conf = null, search = '', sevs = [], from = '', to = '', kev = false) => {
    try {
      const params = new URLSearchParams({ limit: '200' });
      if (conf && conf !== 'all') params.set('confidence', conf);
      if (search) params.set('asset_search', search);
      for (const sev of sevs) params.append('severity', sev);
      if (from) params.set('date_from', from);
      if (to) params.set('date_to', to);
      if (kev) params.set('kev_only', 'true');
      const res = await fetch(`${API}/api/integrations/runzero/matches?${params}`, { headers });
      if (res.ok) {
        const data = await res.json();
        setMatches(data.matches || []);
      }
    } catch {}
  }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    Promise.all([fetchStatus(), fetchMatches()]).finally(() => setLoading(false));
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchMatches]);

  useEffect(() => {
    fetchMatches(filter === 'all' ? null : filter, assetSearch, severities, dateFrom, dateTo, kevOnly);
  }, [filter, assetSearch, severities, dateFrom, dateTo, kevOnly, fetchMatches]);

  const toggleSeverity = (sev) => {
    setSeverities((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  };

  const handleSearchChange = (e) => {
    const val = e.target.value;
    setSearchInput(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setAssetSearch(val);
      setExpandedHash(null);
    }, 300);
  };

  const handleFilterChange = (f) => {
    setFilter(f);
    setSearchInput('');
    setAssetSearch('');
    setExpandedHash(null);
  };

  const handleSyncNow = async () => {
    setSyncing(true);
    try {
      await fetch(`${API}/api/integrations/runzero/sync`, { method: 'POST', headers });
      setTimeout(() => { fetchStatus(); setSyncing(false); }, 2000);
    } catch { setSyncing(false); }
  };

  const statusDotClass = !status.configured
    ? 'bg-gray-500'
    : status.status === 'ok'
      ? 'bg-green-500'
      : status.status === 'error'
        ? 'bg-red-500'
        : 'bg-gray-500';

  const lastSyncText = status.last_sync
    ? `synced ${new Date(status.last_sync).toLocaleString()}`
    : '';

  if (loading) return <div className="p-4 text-gray-400 text-sm">Loading…</div>;

  return (
    <div className="p-4">
      <div className="bg-gray-800 rounded-lg border border-gray-700 p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${statusDotClass}`} />
            <a
              href="https://console.runzero.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-white font-semibold text-sm hover:text-blue-300"
            >
              RunZero
            </a>
            {lastSyncText && (
              <span className="text-gray-400 text-xs">{lastSyncText}</span>
            )}
          </div>
          {userRole === 'admin' && (
            <button
              onClick={handleSyncNow}
              disabled={syncing}
              className="text-xs px-2 py-1 rounded-sm bg-blue-800 hover:bg-blue-700 text-blue-300 disabled:opacity-50"
            >
              {syncing ? 'Syncing…' : 'Sync Now'}
            </button>
          )}
        </div>
        <div className="flex gap-6 text-xs text-gray-400 mb-2">
          <span>{status.asset_count ?? 0} Assets</span>
          <span>{status.org_count ?? 0} Orgs</span>
          <span>{status.vuln_count ?? 0} Vulns</span>
        </div>
        <div className="flex gap-2">
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-red-900 text-red-400 border border-red-600">
            {status.confirmed_matches ?? 0} CONFIRMED
          </span>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-yellow-900 text-yellow-400 border border-yellow-600">
            {status.possible_matches ?? 0} POSSIBLE
          </span>
        </div>
      </div>

      <input
        type="text"
        value={searchInput}
        onChange={handleSearchChange}
        placeholder="Search by threat intel name, asset name, or org…"
        className="w-full text-xs px-2 py-1.5 rounded bg-gray-900 border border-gray-700 text-gray-200
                   placeholder-gray-500 focus:outline-hidden focus:border-blue-600 mb-3"
      />

      <div className="flex flex-wrap items-center gap-3 mb-3">
        <div className="flex gap-2">
          {['all', 'confirmed', 'possible'].map(f => (
            <button
              key={f}
              onClick={() => handleFilterChange(f)}
              className={`text-xs px-2 py-1 rounded border ${
                filter === f
                  ? 'bg-gray-700 border-gray-500 text-white'
                  : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        <div className="flex gap-1">
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              onClick={() => toggleSeverity(sev)}
              className={`text-xs px-2 py-1 rounded border ${
                severities.includes(sev)
                  ? 'bg-gray-700 border-gray-500 text-white'
                  : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <button
          onClick={() => setKevOnly((prev) => !prev)}
          className={`text-xs px-2 py-1 rounded border ${
            kevOnly
              ? 'bg-red-900 border-red-600 text-red-300'
              : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'
          }`}
          title="Filter to CVEs on CISA's Known Exploited Vulnerabilities catalog"
        >
          🔴 KEV only
        </button>

        <div className="flex items-center gap-1.5 text-xs text-gray-400">
          <label htmlFor="runzero-date-from">From</label>
          <input
            id="runzero-date-from"
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            className="text-xs px-1.5 py-1 rounded bg-gray-900 border border-gray-700 text-gray-200 focus:outline-hidden focus:border-blue-600"
          />
          <label htmlFor="runzero-date-to">To</label>
          <input
            id="runzero-date-to"
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            className="text-xs px-1.5 py-1 rounded bg-gray-900 border border-gray-700 text-gray-200 focus:outline-hidden focus:border-blue-600"
          />
          {(dateFrom || dateTo) && (
            <button
              onClick={() => { setDateFrom(''); setDateTo(''); }}
              className="text-gray-500 hover:text-white"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {!status.configured ? (
        <p className="text-gray-400 text-sm">Set RUNZERO_API_TOKEN to enable the RunZero integration.</p>
      ) : status.status === 'never_synced' ? (
        <p className="text-gray-400 text-sm">Sync in progress — check back shortly.</p>
      ) : matches.length === 0 ? (
        <p className="text-gray-400 text-sm">No threat intel entries match your RunZero asset inventory.</p>
      ) : (
        matches.map(m => {
          const isExpanded = expandedHash === m.hash;
          const href = safeLinkHref(m.link);
          const searchUrl = buildRunZeroSearchUrl(m.match_details);
          return (
            <div
              key={m.hash}
              className="bg-gray-800 rounded-sm border border-gray-700 p-3 mb-2 cursor-pointer hover:border-gray-600 transition-colors"
              onClick={() => setExpandedHash(prev => prev === m.hash ? null : m.hash)}
            >
              <div className="flex items-start justify-between gap-2 mb-1">
                {href !== '#' ? (
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={e => e.stopPropagation()}
                    className="text-sm text-blue-400 hover:text-blue-300 text-left font-medium"
                  >
                    {m.title}
                  </a>
                ) : (
                  <span className="text-sm text-blue-400 font-medium">{m.title}</span>
                )}
                <div className="flex items-center gap-1 shrink-0">
                  {m.published && (
                    <span className="text-xs text-gray-500 shrink-0">
                      {new Date(m.published).toLocaleDateString(undefined, { timeZone: CST })}
                    </span>
                  )}
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                    m.confidence === 'confirmed'
                      ? 'bg-red-900 text-red-400 border-red-600'
                      : 'bg-yellow-900 text-yellow-400 border-yellow-600'
                  }`}>
                    {m.confidence.toUpperCase()}
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    m.severity === 'Critical'
                      ? 'bg-red-950 text-red-300 border-red-800'
                      : m.severity === 'High'
                        ? 'bg-orange-950 text-orange-300 border-orange-800'
                        : 'bg-gray-700 text-gray-300 border-gray-600'
                  }`}>
                    {m.severity}
                  </span>
                  {searchUrl && (
                    <a
                      href={searchUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={e => e.stopPropagation()}
                      className="text-[10px] px-1.5 py-0.5 rounded-sm border bg-blue-900 text-blue-300 border-blue-700 hover:bg-blue-800 whitespace-nowrap"
                    >
                      Search In RunZero ↗
                    </a>
                  )}
                  <span className="text-gray-500 text-xs ml-1">{isExpanded ? '▼' : '▶'}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1 mb-1">
                {(m.match_types || []).map(t => (
                  <span key={t} className="text-[10px] px-1 py-0.5 rounded-sm bg-gray-700 text-gray-300 border border-gray-600 uppercase">
                    {t}
                  </span>
                ))}
              </div>
              <div className="text-xs text-gray-400">
                {m.affected_asset_count} asset{m.affected_asset_count !== 1 ? 's' : ''}{' '}
                {m.affected_orgs && m.affected_orgs.length > 0 && `· ${m.affected_orgs.join(', ')}`}
              </div>
              {isExpanded && <AssetDetailPanel matchDetails={m.match_details} />}
            </div>
          );
        })
      )}
    </div>
  );
}
