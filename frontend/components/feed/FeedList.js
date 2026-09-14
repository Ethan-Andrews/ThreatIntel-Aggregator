import { useState, useMemo, useCallback } from "react";
import FeedCard from "./FeedCard";
import { useFilters } from "../../context/FilterContext";

const API = process.env.NEXT_PUBLIC_API_URL || "";

const SORT_OPTIONS = [
  { value: "priority",  label: "Priority ↓"   },
  { value: "ingested",  label: "Ingestion ↓"  },
  { value: "published", label: "Published ↓"  },
  { value: "trust",     label: "Trust ↓"      },
  { value: "source",    label: "Source A–Z"   },
];

function pubTime(entry) {
  if (!entry.published) return new Date(entry.ingested).getTime();
  const t = new Date(entry.published).getTime();
  return isNaN(t) ? new Date(entry.ingested).getTime() : t;
}

function makeComparator(field, dir, scoreMap) {
  const d = dir === "desc" ? -1 : 1;
  switch (field) {
    case "priority":  return (a, b) => d * ((a.priority_score || 0) - (b.priority_score || 0));
    case "trust":     return (a, b) => d * ((scoreMap[a.source] || 50) - (scoreMap[b.source] || 50));
    case "published": return (a, b) => d * (pubTime(a) - pubTime(b));
    case "source":    return (a, b) => d * a.source.localeCompare(b.source);
    default:          return (a, b) => d * (new Date(a.ingested) - new Date(b.ingested));
  }
}

export default function FeedList({
  entries, total, loadedCount, loading, loadingMore, hiddenDupes,
  sources, onLoadMore, onRetriagedSelected, apiKey, onOpenTriagePanel, activeJobCount,
  sortBy, sortDir, onPrimarySortChange,
}) {
  const { showDuplicates, toggleDuplicates, stackMatchOnly, toggleStackMatchOnly } = useFilters();
  const [selectedHashes, setSelectedHashes] = useState(new Set());

  const scoreMap = useMemo(
    () => Object.fromEntries((sources || []).map((s) => [s.name, s.score])),
    [sources]
  );

  const sortedEntries = useMemo(() => {
    const primaryComp = makeComparator(sortBy, sortDir, scoreMap);
    return entries.slice().sort(primaryComp);
  }, [entries, sortBy, sortDir, scoreMap]);

  const displayedEntries = useMemo(
    () => stackMatchOnly ? sortedEntries.filter((e) => e.stack_match) : sortedEntries,
    [sortedEntries, stackMatchOnly]
  );

  function handlePrimarySort(value) {
    if (value === sortBy) {
      const newDir = sortDir === "desc" ? "asc" : "desc";
      onPrimarySortChange(value, newDir);
    } else {
      const newDir = value === "source" ? "asc" : "desc";
      onPrimarySortChange(value, newDir);
    }
  }

  function handleSelectToggle(hash) {
    setSelectedHashes((prev) => {
      const next = new Set(prev);
      next.has(hash) ? next.delete(hash) : next.add(hash);
      return next;
    });
  }

  const handleSelectAll   = useCallback(() => setSelectedHashes(new Set(sortedEntries.map((e) => e.hash))), [sortedEntries]);
  const handleDeselectAll = useCallback(() => setSelectedHashes(new Set()), []);

  const hasMore = loadedCount < total;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-1 flex-wrap px-4 py-2 border-b border-border bg-surface shrink-0">
        <span className="text-[10px] text-text-dim font-bold mr-1">SORT BY</span>
        {SORT_OPTIONS.map((opt) => {
          const active = sortBy === opt.value;
          const arrow  = active ? (sortDir === "desc" ? " ↓" : " ↑") : "";
          return (
            <button
              key={opt.value}
              onClick={() => handlePrimarySort(opt.value)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                active ? "border-accent text-accent" : "border-border text-text-dim hover:text-text"
              }`}
            >
              {opt.label + arrow}
            </button>
          );
        })}

        <span className="flex-1" />

        <span className="text-[10px] text-text-dim">
          {loadedCount < total ? `${loadedCount} / ${total} entries` : `${sortedEntries.length} entries`}
        </span>

        {hiddenDupes > 0 && (
          <button
            onClick={toggleDuplicates}
            className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
              showDuplicates ? "border-accent text-accent" : "border-border text-text-dim hover:text-text"
            }`}
          >
            {hiddenDupes} dup{hiddenDupes !== 1 ? "s" : ""}
            {showDuplicates ? " ✓" : ""}
          </button>
        )}

        <button
          onClick={toggleStackMatchOnly}
          className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
            stackMatchOnly ? "border-green-500 text-green-400" : "border-border text-text-dim hover:text-text"
          }`}
        >
          ⚡ YOUR STACK
        </button>

        <button
          onClick={onOpenTriagePanel}
          className={`text-[10px] px-3 py-0.5 rounded border ml-2 transition-colors ${
            activeJobCount > 0
              ? "border-yellow-500 text-yellow-400 animate-pulse"
              : "border-border text-text-dim hover:border-accent hover:text-accent"
          }`}
        >
          ⟳ Retriage ▸
          {activeJobCount > 0 && (
            <span className="ml-1 bg-yellow-400 text-background rounded-full text-[9px] px-1 font-bold">
              {activeJobCount}
            </span>
          )}
        </button>
      </div>

      {selectedHashes.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-1.5 border-b border-border bg-surface shrink-0 text-xs">
          <input
            type="checkbox"
            checked
            onChange={handleDeselectAll}
            className="accent-accent"
          />
          {selectedHashes.size < sortedEntries.length && (
            <button onClick={handleSelectAll} className="text-text-dim hover:text-text underline">
              Select all ({sortedEntries.length} visible)
            </button>
          )}
          <span className="text-text-dim">{selectedHashes.size} selected</span>
          <button
            onClick={() => onRetriagedSelected(Array.from(selectedHashes))}
            className="border border-border rounded-sm px-2 py-0.5 hover:border-accent hover:text-accent transition-colors"
          >
            Retriage selected
          </button>
          <button onClick={handleDeselectAll} className="text-text-dim hover:text-text">Clear</button>
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-4 py-2">
        {loading && <div className="text-text-dim text-sm text-center py-8">Polling feeds…</div>}
        {!loading && displayedEntries.length === 0 && (
          <div className="text-text-dim text-sm text-center py-8">No entries match current filters.</div>
        )}
        {displayedEntries.map((e) => (
          <FeedCard
            key={e.hash}
            entry={e}
            apiKey={apiKey}
            selected={selectedHashes.has(e.hash)}
            onSelect={handleSelectToggle}
          />
        ))}
        {hasMore && (
          <button
            onClick={onLoadMore}
            disabled={loadingMore}
            className="w-full text-xs text-text-dim border border-border rounded-sm py-2 mt-2 hover:border-accent hover:text-accent transition-colors disabled:opacity-50"
          >
            {loadingMore ? "Loading…" : `Load more (${total - loadedCount} remaining)`}
          </button>
        )}
      </div>
    </div>
  );
}
