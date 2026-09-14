import { useState } from "react";
import { useFilters } from "../../context/FilterContext";

function countBadge(count) {
  if (!count) return null;
  return (
    <span className="ml-auto text-[10px] bg-surface border border-border rounded-sm px-1 text-text-dim">
      {count}
    </span>
  );
}

export default function Sidebar({ sources, entryCounts = {} }) {
  const { activeSources, toggleSource } = useFilters();
  const [scoresOpen, setScoresOpen] = useState(false);

  const filteredCount = activeSources.length;
  const allSelected   = activeSources.length === 0;

  return (
    <aside className="w-[220px] shrink-0 border-r border-border bg-surface flex flex-col overflow-y-auto">

      {/* Sources section */}
      <div className="px-3 py-2 border-b border-border">
        <div className="text-[10px] font-bold tracking-wider text-text-dim mb-2">
          SOURCES{filteredCount > 0 ? ` (${filteredCount})` : ""}
        </div>

        {/* "All" row */}
        <label className="flex items-center gap-2 py-0.5 cursor-pointer">
          <input
            type="checkbox"
            checked={allSelected}
            onChange={() => {
              // Clicking "All" clears all source filters
              if (!allSelected) activeSources.forEach(toggleSource);
            }}
            className="accent-accent"
          />
          <span className="text-xs text-text">All</span>
          {countBadge(Object.values(entryCounts).reduce((a, b) => a + b, 0))}
        </label>

        {sources.map((src) => {
          const active = activeSources.includes(src.name);
          return (
            <label key={src.name} className="flex items-center gap-2 py-0.5 cursor-pointer">
              <input
                type="checkbox"
                checked={active}
                onChange={() => toggleSource(src.name)}
                className="accent-accent"
              />
              <span className={`text-xs truncate ${active ? "text-accent" : "text-text"}`}>
                {src.name}
              </span>
              {countBadge(entryCounts[src.name])}
            </label>
          );
        })}
      </div>

      {/* Trust Scores collapsible */}
      <div className="px-3 py-2">
        <button
          onClick={() => setScoresOpen((v) => !v)}
          className="flex items-center gap-1 text-[10px] font-bold tracking-wider text-text-dim w-full"
        >
          <span>{scoresOpen ? "▾" : "▸"} TRUST SCORES</span>
        </button>

        {scoresOpen && (
          <div className="mt-2 space-y-1">
            {sources.map((src) => (
              <ScoreRow key={src.name} source={src} />
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

function ScoreRow({ source }) {
  const [val, setVal] = useState(source.score ?? 50);

  function commit() {
    fetch(
      `${process.env.NEXT_PUBLIC_API_URL || ""}/api/sources/${encodeURIComponent(source.name)}/score`,
      {
        method:  "PATCH",
        headers: {
          "Content-Type":  "application/json",
          Authorization:   "Bearer " + sessionStorage.getItem("ti_app_token"),
        },
        body: JSON.stringify({ score: val }),
      }
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-text-dim truncate flex-1">{source.name}</span>
      <input
        type="number"
        min={0}
        max={100}
        value={val}
        onChange={(e) => setVal(Number(e.target.value))}
        onBlur={commit}
        className="w-12 bg-background border border-border rounded-sm text-xs text-text px-1 py-0.5 text-right focus:outline-hidden focus:border-accent"
      />
    </div>
  );
}
