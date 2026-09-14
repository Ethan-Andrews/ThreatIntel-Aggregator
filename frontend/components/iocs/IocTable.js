import { useState, useEffect, useCallback, useRef } from "react";
import IocDetailPanel from "./IocDetailPanel";

const API = process.env.NEXT_PUBLIC_API_URL || "";

const TYPE_META = {
  "ipv4-addr":    { label: "IP",           cls: "text-red-400 border-red-900" },
  "domain-name":  { label: "Domain",       cls: "text-orange-400 border-orange-900" },
  "url":          { label: "URL",          cls: "text-yellow-400 border-yellow-900" },
  "file":         { label: "Hash",         cls: "text-purple-400 border-purple-900" },
  "vulnerability":{ label: "CVE",          cls: "text-blue-400 border-blue-900" },
  "threat-actor": { label: "Threat Actor", cls: "text-green-400 border-green-900" },
};

const TYPE_FILTERS = [
  { value: "",              label: "All" },
  { value: "ipv4-addr",    label: "IP" },
  { value: "domain-name",  label: "Domain" },
  { value: "url",          label: "URL" },
  { value: "file",         label: "Hash" },
  { value: "vulnerability",label: "CVE" },
  { value: "threat-actor", label: "Threat Actor" },
];

const SORT_OPTIONS = [
  { value: "last_seen",        label: "Last Seen" },
  { value: "occurrence_count", label: "Occurrences" },
  { value: "value",            label: "Value A–Z" },
];

function TypeChip({ type }) {
  const meta = TYPE_META[type] || { label: type, cls: "text-text-dim border-border" };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border font-mono ${meta.cls}`}>
      {meta.label}
    </span>
  );
}

export default function IocTable({ authFetch, onSwitchToFeed, userRole }) {
  const [iocs,        setIocs]        = useState([]);
  const [total,       setTotal]       = useState(0);
  const [loaded,      setLoaded]      = useState(0);
  const [loading,     setLoading]     = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [search,      setSearch]      = useState("");
  const [typeFilter,  setTypeFilter]  = useState("");
  const [sortBy,      setSortBy]      = useState("last_seen");
  const [sortDir,     setSortDir]     = useState("desc");
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [detailIoc,   setDetailIoc]   = useState(null);
  const [detailEntries, setDetailEntries] = useState([]);
  const [exportOpen,  setExportOpen]  = useState(false);
  const [isDeleting,  setIsDeleting]  = useState(false);
  const [includeBenign, setIncludeBenign] = useState(false);
  const searchTimer = useRef(null);

  const buildParams = useCallback((offset) => {
    const p = new URLSearchParams({
      limit: 100, offset,
      sort_by: sortBy,
      sort_dir: sortDir,
    });
    if (typeFilter) p.set("type", typeFilter);
    if (search)     p.set("search", search);
    if (includeBenign) p.set("include_benign", "true");
    return p;
  }, [typeFilter, search, sortBy, sortDir, includeBenign]);

  const fetchIocs = useCallback(() => {
    setLoading(true);
    authFetch(`${API}/api/iocs?${buildParams(0)}`)
      .then(r => r.json())
      .then(d => {
        const rows = d.iocs || [];
        setIocs(rows);
        setTotal(d.total || 0);
        setLoaded(rows.length);
        setSelectedIds(new Set());
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [authFetch, buildParams]);

  useEffect(() => { fetchIocs(); }, [fetchIocs]);

  function loadMore() {
    if (loadingMore || loaded >= total) return;
    setLoadingMore(true);
    authFetch(`${API}/api/iocs?${buildParams(loaded)}`)
      .then(r => r.json())
      .then(d => {
        const rows = d.iocs || [];
        setIocs(prev => [...prev, ...rows]);
        setLoaded(prev => prev + rows.length);
        setTotal(d.total || 0);
      })
      .catch(() => {})
      .finally(() => setLoadingMore(false));
  }

  function handleSearchChange(val) {
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => setSearch(val), 300);
  }

  function handleSort(field) {
    if (field === sortBy) {
      setSortDir(d => d === "desc" ? "asc" : "desc");
    } else {
      setSortBy(field);
      setSortDir(field === "value" ? "asc" : "desc");
    }
  }

  function handleRowClick(ioc) {
    setDetailIoc(ioc);
    setDetailEntries([]);
    authFetch(`${API}/api/iocs/${ioc.id}/entries`)
      .then(r => r.json())
      .then(d => setDetailEntries(d.entries || []))
      .catch(() => {});
  }

  function onIocDeleted(ioc_id) {
    setIocs(prev => prev.filter(i => i.id !== ioc_id));
    setTotal(prev => prev - 1);
    setLoaded(prev => prev - 1);
    setDetailIoc(null);
  }

  function onDeleteIoc(ioc_id) {
    if (isDeleting) return;
    setIsDeleting(true);
    authFetch(`${API}/api/iocs/${ioc_id}`, { method: "DELETE" })
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => onIocDeleted(ioc_id))
      .catch(() => fetchIocs())
      .finally(() => setIsDeleting(false));
  }

  function onRemoveEntry(ioc_id, entry_hash) {
    if (isDeleting) return;
    setIsDeleting(true);
    authFetch(`${API}/api/iocs/${ioc_id}/entries/${entry_hash}`, { method: "DELETE" })
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(result => {
        if (result.deleted) {
          onIocDeleted(ioc_id);
        } else {
          setDetailEntries(prev => prev.filter(e => e.hash !== entry_hash));
          setIocs(prev => prev.map(i =>
            i.id === ioc_id ? { ...i, occurrence_count: i.occurrence_count - 1 } : i
          ));
          setDetailIoc(prev => prev && prev.id === ioc_id
            ? { ...prev, occurrence_count: prev.occurrence_count - 1 }
            : prev
          );
        }
      })
      .catch(() => {
        fetchIocs();
        setDetailIoc(null);
      })
      .finally(() => setIsDeleting(false));
  }

  const onSetBenign = useCallback((ioc_id, benign, reason) => {
    authFetch(`${API}/api/iocs/${ioc_id}/benign`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ benign, reason }),
    })
      .then(r => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => {
        if (benign && !includeBenign) {
          onIocDeleted(ioc_id);
        } else {
          setIocs(prev => prev.map(i =>
            i.id === ioc_id ? { ...i, benign: benign ? 1 : 0, benign_reason: reason } : i
          ));
          setDetailIoc(prev => prev && prev.id === ioc_id
            ? { ...prev, benign: benign ? 1 : 0, benign_reason: reason }
            : prev
          );
        }
      })
      .catch(() => fetchIocs());
  }, [authFetch, includeBenign, fetchIocs]);

  function handleSelect(id) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function handleExport(fmt) {
    if (selectedIds.size === 0) return;
    const ids = Array.from(selectedIds).join(",");
    const ext = fmt === "stix" ? "json" : "csv";
    const mime = fmt === "stix" ? "application/json" : "text/csv";
    authFetch(`${API}/api/iocs/export?ids=${ids}&format=${fmt}`)
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(new Blob([blob], { type: mime }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `iocs.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch(() => {});
    setExportOpen(false);
  }

  const hasMore = loaded < total;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Controls bar */}
      <div className="flex items-center gap-2 flex-wrap px-4 py-2 border-b border-border bg-surface shrink-0">
        <input
          type="text"
          placeholder="Search IOCs…"
          onChange={e => handleSearchChange(e.target.value)}
          className="text-xs bg-background border border-border rounded-sm px-2 py-1 text-text placeholder-text-dim focus:border-accent outline-hidden w-48"
        />

        <span className="text-[10px] text-text-dim font-bold">TYPE</span>
        {TYPE_FILTERS.map(f => (
          <button
            key={f.value}
            onClick={() => setTypeFilter(f.value)}
            className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
              typeFilter === f.value
                ? "border-accent text-accent"
                : "border-border text-text-dim hover:text-text"
            }`}
          >
            {f.label}
          </button>
        ))}

        <span className="text-[10px] text-text-dim font-bold ml-2">SORT</span>
        {SORT_OPTIONS.map(o => {
          const active = sortBy === o.value;
          return (
            <button
              key={o.value}
              onClick={() => handleSort(o.value)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                active ? "border-accent text-accent" : "border-border text-text-dim hover:text-text"
              }`}
            >
              {o.label}{active ? (sortDir === "desc" ? " ↓" : " ↑") : ""}
            </button>
          );
        })}

        {userRole === "admin" && (
          <>
            <span className="text-[10px] text-text-dim font-bold ml-2">BENIGN</span>
            <button
              onClick={() => setIncludeBenign(v => !v)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                includeBenign
                  ? "border-accent text-accent"
                  : "border-border text-text-dim hover:text-text"
              }`}
            >
              Show
            </button>
          </>
        )}

        <span className="flex-1" />

        <span className="text-[10px] text-text-dim">
          {loaded < total ? `${loaded} / ${total}` : total} IOCs
        </span>

        {selectedIds.size > 0 && (
          <div className="relative">
            <button
              onClick={() => setExportOpen(o => !o)}
              className="text-[10px] px-2 py-0.5 rounded-sm border border-accent text-accent hover:bg-accent hover:text-background transition-colors"
            >
              Export {selectedIds.size} ↓
            </button>
            {exportOpen && (
              <div className="absolute right-0 top-full mt-1 bg-surface border border-border rounded-sm z-10 text-xs">
                <button
                  onClick={() => handleExport("csv")}
                  className="block w-full text-left px-3 py-1.5 hover:bg-background text-text"
                >
                  CSV
                </button>
                <button
                  onClick={() => handleExport("stix")}
                  className="block w-full text-left px-3 py-1.5 hover:bg-background text-text"
                >
                  STIX 2.1 Bundle
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="text-text-dim text-sm text-center py-8">Loading IOCs…</div>
        )}
        {!loading && iocs.length === 0 && (
          <div className="text-text-dim text-sm text-center py-8">No IOCs found.</div>
        )}
        {iocs.length > 0 && (
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-surface border-b border-border">
              <tr>
                <th className="w-8 px-3 py-2" />
                <th className="px-3 py-2 text-left text-text-dim font-bold tracking-wider">TYPE</th>
                <th className="px-3 py-2 text-left text-text-dim font-bold tracking-wider">VALUE</th>
                <th className="px-3 py-2 text-left text-text-dim font-bold tracking-wider">SUBTYPE</th>
                <th className="px-3 py-2 text-right text-text-dim font-bold tracking-wider">SEEN</th>
                <th className="px-3 py-2 text-left text-text-dim font-bold tracking-wider">FIRST</th>
                <th className="px-3 py-2 text-left text-text-dim font-bold tracking-wider">LAST</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map(ioc => (
                <tr
                  key={ioc.id}
                  className={`border-b border-border hover:bg-surface cursor-pointer ${ioc.benign ? "opacity-40" : ""}`}
                  onClick={() => handleRowClick(ioc)}
                >
                  <td className="px-3 py-1.5" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(ioc.id)}
                      onChange={() => handleSelect(ioc.id)}
                      className="accent-accent"
                    />
                  </td>
                  <td className="px-3 py-1.5"><TypeChip type={ioc.type} /></td>
                  <td className="px-3 py-1.5 font-mono text-text max-w-xs">
                    <div className="flex items-center gap-1 min-w-0">
                      <span className="truncate">{ioc.value}</span>
                      {ioc.benign ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-sm border font-mono text-text-dim border-border shrink-0">
                          BENIGN
                        </span>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 text-text-dim">{ioc.subtype || "—"}</td>
                  <td className="px-3 py-1.5 text-right text-text">{ioc.occurrence_count}</td>
                  <td className="px-3 py-1.5 text-text-dim">{ioc.first_seen?.slice(0, 10) || "—"}</td>
                  <td className="px-3 py-1.5 text-text-dim">{ioc.last_seen?.slice(0, 10) || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {hasMore && (
          <button
            onClick={loadMore}
            disabled={loadingMore}
            className="w-full text-xs text-text-dim border border-border rounded-sm py-2 mt-2 hover:border-accent hover:text-accent transition-colors disabled:opacity-50 px-4"
          >
            {loadingMore ? "Loading…" : `Load more (${total - loaded} remaining)`}
          </button>
        )}
      </div>

      <IocDetailPanel
        ioc={detailIoc}
        entries={detailEntries}
        onClose={() => setDetailIoc(null)}
        onSwitchToFeed={onSwitchToFeed}
        userRole={userRole}
        onDeleteIoc={onDeleteIoc}
        onRemoveEntry={onRemoveEntry}
        onSetBenign={onSetBenign}
        isDeleting={isDeleting}
      />
    </div>
  );
}
