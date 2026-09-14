import { useFilters } from "../../context/FilterContext";
import LiveBadge from "../LiveBadge";

export default function TopBar({ lastPoll, onLogout }) {
  const { search, setSearch } = useFilters();

  return (
    <header className="flex items-center gap-4 px-4 h-12 border-b border-border bg-surface shrink-0">
      <div className="flex items-center gap-2 shrink-0">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/logo.png" alt="" aria-hidden="true" className="w-7 h-7 object-contain" />
        <span className="text-accent font-bold tracking-widest text-sm">Threat Intel Aggregator</span>
      </div>
      <input
        className="flex-1 max-w-sm bg-background border border-border rounded-sm px-3 py-1 text-sm text-text placeholder:text-text-dim focus:outline-hidden focus:border-accent"
        placeholder="Search titles / summaries…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <div className="flex-1" />
      <LiveBadge lastPoll={lastPoll} />
      <button
        onClick={onLogout}
        className="text-xs text-text-dim hover:text-text border border-border rounded-sm px-2 py-1"
      >
        Log out
      </button>
    </header>
  );
}
