'use client';
import { useState, useEffect, useCallback, useRef } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';

const SEV_CLASSES = {
  Critical: 'bg-red-950 text-red-300 border-red-800',
  High:     'bg-orange-950 text-orange-300 border-orange-800',
  Medium:   'bg-yellow-950 text-yellow-300 border-yellow-800',
  Low:      'bg-gray-800 text-gray-400 border-gray-600',
};

const CONF_CLASSES = {
  confirmed: 'bg-red-900 text-red-400 border-red-600',
  possible:  'bg-yellow-900 text-yellow-400 border-yellow-600',
};

const SEV_PILL = {
  C: { label: 'C', classes: 'bg-red-950 text-red-300 border-red-800' },
  H: { label: 'H', classes: 'bg-orange-950 text-orange-300 border-orange-800' },
  M: { label: 'M', classes: 'bg-yellow-950 text-yellow-300 border-yellow-800' },
  L: { label: 'L', classes: 'bg-gray-800 text-gray-400 border-gray-600' },
};

function SevPill({ label, count }) {
  const s = SEV_PILL[label];
  if (!s) return null;
  return (
    <span
      className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
        count > 0 ? s.classes : 'bg-gray-900 text-gray-600 border-gray-700'
      }`}
    >
      {label}: {count}
    </span>
  );
}

function safeLinkHref(link) {
  if (!link) return null;
  try {
    const url = new URL(link);
    if (url.protocol === 'https:' || url.protocol === 'http:') return link;
  } catch {}
  return null;
}

function groupByEntry(items) {
  const groups = new Map();
  for (const item of items) {
    if (!groups.has(item.entry_hash)) {
      groups.set(item.entry_hash, {
        entry_hash: item.entry_hash,
        title:      item.title,
        severity:   item.severity,
        confidence: item.confidence,
        match_type: item.match_type,
        link:       item.link,
        ai_summary: item.ai_summary,
        assets:     [],
      });
    }
    groups.get(item.entry_hash).assets.push(item);
  }
  return [...groups.values()];
}

function ProgressBar({ total, active, acknowledged, remediated, onTabSelect }) {
  if (total === 0) return <div className="h-2 bg-gray-700 rounded" />;
  const remPct = Math.round((remediated   / total) * 100);
  const ackPct = Math.round((acknowledged / total) * 100);
  const actPct = 100 - remPct - ackPct;
  return (
    <div className="flex h-2 rounded overflow-hidden cursor-pointer gap-px" title={`${remediated}/${total} remediated`}>
      {remPct > 0 && (
        <div className="bg-green-600 hover:bg-green-500 transition-colors" style={{ width: `${remPct}%` }}
          onClick={(e) => { e.stopPropagation(); onTabSelect('remediated'); }} />
      )}
      {ackPct > 0 && (
        <div className="bg-yellow-600 hover:bg-yellow-500 transition-colors" style={{ width: `${ackPct}%` }}
          onClick={(e) => { e.stopPropagation(); onTabSelect('active'); }} />
      )}
      {actPct > 0 && (
        <div className="bg-gray-600 hover:bg-gray-500 transition-colors" style={{ width: `${actPct}%` }}
          onClick={(e) => { e.stopPropagation(); onTabSelect('active'); }} />
      )}
    </div>
  );
}

function AuditTrail({ itemId, apiKey, open }) {
  const [log, setLog]         = useState(null);
  const [loading, setLoading] = useState(false);
  const fetched = useRef(false);

  useEffect(() => {
    if (!open || fetched.current) return;
    fetched.current = true;
    setLoading(true);
    fetch(`${API}/api/exposure/items/${itemId}/audit`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    })
      .then((r) => r.json())
      .then((d) => setLog(d.log || []))
      .catch(() => setLog([]))
      .finally(() => setLoading(false));
  }, [open, itemId, apiKey]);

  if (!open) return null;
  if (loading) return <div className="text-[10px] text-gray-500 mt-1">Loading audit trail…</div>;
  if (!log || log.length === 0) return <div className="text-[10px] text-gray-600 mt-1">No activity yet.</div>;

  const ACTION_LABEL = { status_change: 'Status', note_added: 'Note', assigned: 'Assigned' };

  return (
    <div className="mt-1 space-y-0.5">
      {log.map((entry, i) => (
        <div key={i} className="flex gap-2 text-[10px] text-gray-400">
          <span className="text-gray-500 shrink-0">{new Date(entry.created_at).toLocaleString()}</span>
          <span className="font-medium text-gray-300 shrink-0">{entry.actor}</span>
          <span className="text-gray-500 shrink-0">{ACTION_LABEL[entry.action] || entry.action}:</span>
          <span className="text-gray-400 flex-1 break-words">{entry.detail}</span>
        </div>
      ))}
    </div>
  );
}

function AssetRow({ item }) {
  const isRemediated = item.status === 'remediated';
  return (
    <div className="flex items-center gap-1.5 flex-wrap border-t border-gray-700/60 pt-1.5 first:border-t-0 first:pt-0">
      <span className="text-[11px] text-gray-200 font-mono shrink-0">{item.hostname || item.asset_id}</span>
      {item.site && (
        <span className="text-[10px] px-1 py-0.5 rounded bg-gray-700 text-gray-400 border border-gray-600 shrink-0">
          {item.site}
        </span>
      )}
      {item.os && (
        <span className="text-[10px] px-1 py-0.5 rounded bg-gray-700 text-gray-500 border border-gray-600 shrink-0">
          {item.os}
        </span>
      )}
      <span className="text-[10px] text-gray-600 shrink-0">
        {item.remediated_at
          ? <span className="text-green-700">rem {new Date(item.remediated_at).toLocaleDateString()}</span>
          : `seen ${new Date(item.last_seen).toLocaleDateString()}`}
      </span>
      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border shrink-0 ${
        isRemediated                   ? 'bg-green-900 text-green-400 border-green-700' :
        item.status === 'acknowledged' ? 'bg-yellow-900 text-yellow-400 border-yellow-700' :
                                         'bg-gray-800 text-gray-400 border-gray-600'
      }`}>
        {item.status.toUpperCase()}
      </span>
    </div>
  );
}

function GroupActivity({ items, apiKey, open }) {
  const [log, setLog]         = useState(null);
  const [loading, setLoading] = useState(false);
  const fetched = useRef(false);

  useEffect(() => {
    if (!open || fetched.current) return;
    fetched.current = true;
    setLoading(true);
    Promise.all(
      items.map((item) =>
        fetch(`${API}/api/exposure/items/${item.id}/audit`, {
          headers: { Authorization: `Bearer ${apiKey}` },
        })
          .then((r) => r.json())
          .then((d) => (d.log || []).map((e) => ({ ...e, asset: item.hostname || item.asset_id })))
          .catch(() => [])
      )
    )
      .then((results) =>
        results
          .flat()
          .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
      )
      .then(setLog)
      .finally(() => setLoading(false));
  }, [open, items, apiKey]);

  if (!open) return null;
  if (loading) return <div className="text-[10px] text-gray-500 mt-2">Loading activity…</div>;
  if (!log || log.length === 0) return <div className="text-[10px] text-gray-600 mt-2">No activity yet.</div>;

  const ACTION_LABEL = { status_change: 'Status', note_added: 'Note', assigned: 'Assigned' };

  return (
    <div className="mt-2 border-t border-gray-700 pt-2 space-y-1">
      {log.map((entry, i) => (
        <div key={i} className="flex gap-2 text-[10px] text-gray-400">
          <span className="text-gray-500 shrink-0">{new Date(entry.created_at).toLocaleString()}</span>
          <span className="font-medium text-gray-300 shrink-0">{entry.actor}</span>
          <span className="text-gray-500 shrink-0">{ACTION_LABEL[entry.action] || entry.action}:</span>
          <span className="text-gray-400 flex-1 break-words">{entry.detail}</span>
          <span className="text-gray-600 shrink-0 font-mono">{entry.asset}</span>
        </div>
      ))}
    </div>
  );
}

function EntryGroupCard({ group, users, apiKey, onUpdate }) {
  const [saving,    setSaving]    = useState(false);
  const [notesOpen, setNotesOpen] = useState(false);
  const [notesText, setNotesText] = useState('');
  const [auditOpen, setAuditOpen] = useState(false);

  const sevClass  = SEV_CLASSES[group.severity]    || 'bg-gray-800 text-gray-400 border-gray-600';
  const confClass = CONF_CLASSES[group.confidence] || 'bg-gray-700 text-gray-400 border-gray-600';
  const href      = safeLinkHref(group.link);

  const nonRemediated   = group.assets.filter((i) => i.status !== 'remediated');
  const allAcknowledged = nonRemediated.length > 0 && nonRemediated.every((i) => i.status === 'acknowledged');

  const assignees     = [...new Set(nonRemediated.map((i) => i.assigned_to || ''))];
  const assigneeValue = assignees.length === 1 ? assignees[0] : '';

  const patchOne = async (itemId, body) => {
    const res = await fetch(`${API}/api/exposure/items/${itemId}`, {
      method:  'PATCH',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const handleGroupStatus = async () => {
    setSaving(true);
    try {
      const targetStatus = allAcknowledged ? 'active' : 'acknowledged';
      const toUpdate = allAcknowledged
        ? nonRemediated
        : nonRemediated.filter((i) => i.status === 'active');
      for (const item of toUpdate) onUpdate(await patchOne(item.id, { status: targetStatus }));
    } finally {
      setSaving(false);
    }
  };

  const handleGroupAssign = async (e) => {
    const val  = e.target.value;
    const body = val === '' ? { assigned_to: null, unassign: true } : { assigned_to: val };
    setSaving(true);
    try {
      for (const item of nonRemediated) onUpdate(await patchOne(item.id, body));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNotes = async () => {
    setSaving(true);
    try {
      for (const item of nonRemediated) onUpdate(await patchOne(item.id, { notes: notesText }));
      setNotesOpen(false);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-700 rounded p-3">
      {/* Entry header */}
      <div className="flex items-center gap-1.5 flex-wrap mb-1">
        <span className={`text-[10px] font-bold px-1 py-0.5 rounded border shrink-0 ${confClass}`}>
          {(group.confidence || '').toUpperCase()}
        </span>
        <span className={`text-[10px] px-1 py-0.5 rounded border shrink-0 ${sevClass}`}>
          {group.severity}
        </span>
        <span className="text-[10px] px-1 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-600 shrink-0 uppercase">
          {group.match_type}
        </span>
        <span className="text-[10px] text-gray-600 shrink-0">
          {group.assets.length} asset{group.assets.length !== 1 ? 's' : ''}
        </span>
      </div>

      {href ? (
        <a href={href} target="_blank" rel="noopener noreferrer"
           className="text-xs text-blue-400 hover:text-blue-300 font-medium leading-tight block mb-1">
          {group.title}
        </a>
      ) : (
        <span className="text-xs text-blue-400 font-medium leading-tight block mb-1">{group.title}</span>
      )}
      {group.ai_summary && (
        <p className="text-[11px] text-gray-400 leading-relaxed line-clamp-2 mb-2">{group.ai_summary}</p>
      )}

      {/* Group-level actions */}
      {nonRemediated.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <button
            onClick={handleGroupStatus}
            disabled={saving}
            className={`text-[10px] font-bold px-2 py-1 rounded border transition-colors disabled:opacity-50 shrink-0 ${
              allAcknowledged
                ? 'bg-gray-800 text-gray-300 border-gray-600 hover:bg-gray-700'
                : 'bg-yellow-900 text-yellow-300 border-yellow-700 hover:bg-yellow-800'
            }`}
          >
            {allAcknowledged ? 'Reopen' : 'Acknowledge'}
          </button>

          <select
            value={assigneeValue}
            onChange={handleGroupAssign}
            disabled={saving}
            className="text-[10px] bg-gray-800 text-gray-300 border border-gray-600 rounded px-1.5 py-1 disabled:opacity-50"
          >
            <option value="">Unassigned</option>
            {users.map((u) => <option key={u} value={u}>{u}</option>)}
          </select>

          <button
            onClick={() => setNotesOpen((o) => !o)}
            className="text-[10px] px-2 py-1 rounded border bg-gray-800 text-gray-400 border-gray-600 hover:bg-gray-700 shrink-0"
          >
            {notesOpen ? 'Cancel' : 'Add Note'}
          </button>
        </div>
      )}

      {notesOpen && (
        <div className="mb-2 space-y-1">
          <textarea
            value={notesText}
            onChange={(e) => setNotesText(e.target.value)}
            maxLength={4000}
            rows={2}
            className="w-full text-xs bg-gray-800 text-gray-200 border border-gray-600 rounded p-1.5 resize-none focus:outline-none focus:border-gray-400"
            placeholder="Add a note to all assets for this vulnerability…"
          />
          <button
            onClick={handleSaveNotes}
            disabled={saving}
            className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-900 text-blue-300 border border-blue-700 hover:bg-blue-800 disabled:opacity-50"
          >
            Save
          </button>
        </div>
      )}

      {/* Asset rows */}
      <div className="space-y-0 mb-2">
        {group.assets.map((item) => (
          <AssetRow key={item.id} item={item} />
        ))}
      </div>

      <button
        onClick={() => setAuditOpen((o) => !o)}
        className="text-[10px] text-gray-600 hover:text-gray-400 underline"
      >
        {auditOpen ? 'Hide activity' : 'Show activity'}
      </button>
      <GroupActivity items={group.assets} apiKey={apiKey} open={auditOpen} />
    </div>
  );
}

function OrgCard({ org, users, apiKey, onSummaryRefresh }) {
  const [expanded,  setExpanded]  = useState(false);
  const [activeTab, setActiveTab] = useState('active');
  const [items,     setItems]     = useState({ active: null, remediated: null });
  const [loading,   setLoading]   = useState(false);

  const headers = { Authorization: `Bearer ${apiKey}` };

  const fetchItems = useCallback(async (status) => {
    const key = status === 'remediated' ? 'remediated' : 'active';
    if (items[key] !== null) return;
    setLoading(true);
    try {
      const statusParam = status === 'remediated' ? 'remediated' : 'all';
      const res = await fetch(
        `${API}/api/exposure/items?org=${encodeURIComponent(org.org)}&status=${statusParam}&limit=200`,
        { headers },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (statusParam === 'all') {
        const active = (data.items || []).filter(
          (i) => i.status === 'active' || i.status === 'acknowledged'
        );
        setItems((prev) => ({ ...prev, active }));
      } else {
        setItems((prev) => ({ ...prev, remediated: data.items || [] }));
      }
    } catch {
      // leave as null to allow retry on next click
    } finally {
      setLoading(false);
    }
  }, [org.org, apiKey, items]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCardClick = () => {
    if (!expanded) fetchItems('active');
    setExpanded((e) => !e);
  };

  const handleTabSelect = (tab) => {
    setActiveTab(tab);
    if (tab === 'remediated') fetchItems('remediated');
  };

  const handleItemUpdate = useCallback((updated) => {
    setItems((prev) => {
      const updateList = (list) =>
        list === null ? null : list.map((i) => (i.id === updated.id ? updated : i));
      return { active: updateList(prev.active), remediated: updateList(prev.remediated) };
    });
    onSummaryRefresh();
  }, [onSummaryRefresh]);

  const remPct       = org.total > 0 ? Math.round((org.remediated / org.total) * 100) : 0;
  const displayItems = activeTab === 'remediated' ? items.remediated : items.active;
  const groups       = displayItems ? groupByEntry(displayItems) : null;

  return (
    <div className={`bg-gray-800 rounded border transition-colors ${
      expanded ? 'border-gray-500' : 'border-gray-700 hover:border-gray-600'
    }`}>
      <div className="p-3 cursor-pointer" onClick={handleCardClick}>
        <div className="flex items-center gap-3 mb-2">
          <span className="text-white text-sm font-medium flex-1 min-w-0 truncate" title={org.org}>
            {org.org}
          </span>
          <span className="text-[10px] text-gray-400 shrink-0">
            {org.remediated}/{org.total} remediated ({remPct}%)
          </span>
          <div className="flex gap-1 text-[10px] shrink-0">
            <span className="px-1 py-0.5 rounded bg-gray-700 text-gray-400 border border-gray-600">{org.active} active</span>
            <span className="px-1 py-0.5 rounded bg-yellow-900 text-yellow-400 border border-yellow-700">{org.acknowledged} ack</span>
            <span className="px-1 py-0.5 rounded bg-green-900 text-green-400 border border-green-700">{org.remediated} done</span>
          </div>
          <span className="text-gray-500 text-xs shrink-0">{expanded ? '▼' : '▶'}</span>
        </div>
        <div className="flex items-center gap-1.5 mb-2 flex-wrap">
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-red-900 text-red-400 border-red-600">
            {org.confirmed} CONFIRMED
          </span>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border bg-yellow-900 text-yellow-400 border-yellow-600">
            {org.possible} POSSIBLE
          </span>
          {['C', 'H', 'M', 'L'].map((k) => (
            <SevPill
              key={k}
              label={k}
              count={k === 'C' ? org.critical : k === 'H' ? org.high : k === 'M' ? org.medium : org.low}
            />
          ))}
        </div>
        <ProgressBar
          total={org.total}
          active={org.active}
          acknowledged={org.acknowledged}
          remediated={org.remediated}
          onTabSelect={handleTabSelect}
        />
      </div>

      {expanded && (
        <div className="border-t border-gray-700" onClick={(e) => e.stopPropagation()}>
          <div className="flex border-b border-gray-700">
            {['active', 'remediated'].map((tab) => (
              <button
                key={tab}
                onClick={() => handleTabSelect(tab)}
                className={`px-4 py-2 text-[11px] font-bold uppercase tracking-wider border-b-2 transition-colors ${
                  activeTab === tab
                    ? 'border-blue-500 text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-300'
                }`}
              >
                {tab === 'active'
                  ? `Active / Acknowledged (${org.active + org.acknowledged})`
                  : `Remediated (${org.remediated})`}
              </button>
            ))}
          </div>

          <div className="p-3 space-y-2">
            {loading ? (
              <div className="text-xs text-gray-400">Loading…</div>
            ) : groups === null ? (
              <div className="text-xs text-gray-500">Loading…</div>
            ) : groups.length === 0 ? (
              <div className="text-xs text-gray-500">No items in this view.</div>
            ) : (
              groups.map((group) => (
                <EntryGroupCard
                  key={group.entry_hash}
                  group={group}
                  users={users}
                  apiKey={apiKey}
                  onUpdate={handleItemUpdate}
                />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ExposurePanel({ apiKey }) {
  const [orgs,    setOrgs]    = useState([]);
  const [users,   setUsers]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);

  const headers = { Authorization: `Bearer ${apiKey}` };

  const fetchSummary = useCallback(async () => {
    try {
      const [remediationRes, correlationRes] = await Promise.all([
        fetch(`${API}/api/exposure/summary`, { headers }),
        fetch(`${API}/api/integrations/runzero/exposure`, { headers }),
      ]);
      if (!remediationRes.ok) throw new Error(`HTTP ${remediationRes.status}`);
      const remediationData = await remediationRes.json();
      const correlationData = correlationRes.ok ? await correlationRes.json() : { orgs: [] };

      const correlationByOrg = new Map(
        (correlationData.orgs || []).map((o) => [o.org, o])
      );
      const merged = (remediationData.orgs || []).map((o) => {
        const c = correlationByOrg.get(o.org) || {};
        return {
          ...o,
          confirmed: c.confirmed || 0,
          possible:  c.possible  || 0,
          critical:  c.critical  || 0,
          high:      c.high      || 0,
          medium:    c.medium    || 0,
          low:       c.low       || 0,
        };
      });
      setOrgs(merged);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchSummary();
    fetch(`${API}/api/users/names`, { headers })
      .then((r) => r.json())
      .then((d) => setUsers(d.names || []))
      .catch(() => {});
  }, [fetchSummary]); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return <div className="p-4 text-gray-400 text-sm">Loading…</div>;
  if (error)   return <div className="p-4 text-red-400 text-sm">Failed to load exposure data.</div>;
  if (orgs.length === 0) {
    return (
      <div className="p-4 text-gray-400 text-sm">
        No exposure items yet — trigger a RunZero sync from the Integrations tab.
      </div>
    );
  }

  return (
    <div className="p-4">
      <h2 className="text-xs font-bold text-gray-300 tracking-wider mb-1 uppercase">
        Org Exposure & Remediation
      </h2>
      <p className="text-[11px] text-gray-500 mb-4">
        Items auto-remediate when RunZero no longer reports the vulnerability. Click a card to manage items.
      </p>
      <div className="space-y-3">
        {orgs.map((org) => (
          <OrgCard
            key={org.org}
            org={org}
            users={users}
            apiKey={apiKey}
            onSummaryRefresh={fetchSummary}
          />
        ))}
      </div>
    </div>
  );
}
