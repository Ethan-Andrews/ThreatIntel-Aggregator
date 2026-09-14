import { useState, useEffect, useCallback, useRef } from "react";
import { animate, useReducedMotion } from "framer-motion";
import { useFilters } from "../../context/FilterContext";
import TimeRangeToggle from "../layout/TimeRangeToggle";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function currentToken(fallback) {
  if (typeof window === "undefined") return fallback || "";
  return sessionStorage.getItem("ti_app_token") || fallback || "";
}

function normalizeStats(raw) {
  const data = raw && typeof raw === "object" ? raw : {};
  return {
    total: data.total || 0,
    triaged: data.triaged || 0,
    pending: data.pending || 0,
    needs_retriage: data.needs_retriage || 0,
    severity: Array.isArray(data.severity) ? data.severity : [],
    ttps: Array.isArray(data.ttps) ? data.ttps : [],
    enrichment: data.enrichment || {},
    tag_distribution: data.tag_distribution || {},
    ioc_distribution: data.ioc_distribution || {},
  };
}

const SEVERITY_META = {
  Critical:      { color: "#c0392b", order: 0 },
  High:          { color: "#e17055", order: 1 },
  Medium:        { color: "#f9ca24", order: 2 },
  Low:           { color: "#00b894", order: 3 },
  Informational: { color: "#0984e3", order: 4 },
  Unknown:       { color: "#4a6a4a", order: 5 },
};

// Same category -> label/color convention TopFilterBar.js already
// established for tag/IOC filter chips -- reused here, not reinvented, so
// "Malware" (say) means the same pink everywhere in the app, not just here.
const TAG_META = {
  malware_types:      { label: "Malware Families", color: "#e84393", toggle: "tag" },
  threat_actor_types: { label: "Threat Actors",    color: "#e17055", toggle: "tag" },
  target_sectors:     { label: "Target Sectors",   color: "#a29bfe", toggle: "tag" },
  platforms:          { label: "Platforms",        color: "#74b9ff", toggle: "tag" },
};
const IOC_META = {
  cves: { label: "CVEs", color: "#fdcb6e", toggle: "ioc" },
};

function relativeTime(iso) {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "never";
  const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

// The one orchestrated motion moment on this page (see Signal masthead
// below) -- every number counts up from its previous value rather than
// snapping, echoing a live instrument locking onto a fresh reading.
// Respects prefers-reduced-motion by skipping straight to the target.
function useCountUp(target, reduceMotion) {
  const [display, setDisplay] = useState(target);
  const prevRef = useRef(target);

  useEffect(() => {
    if (reduceMotion) {
      setDisplay(target);
      prevRef.current = target;
      return;
    }
    const from = prevRef.current;
    const controls = animate(from, target, {
      duration: 0.6,
      ease: "easeOut",
      onUpdate: (v) => setDisplay(Math.round(v)),
    });
    prevRef.current = target;
    return () => controls.stop();
  }, [target, reduceMotion]);

  return display;
}

// A transient green "+N" shown next to a value when a poll finds it's gone
// up since the last one -- paired with useCountUp's own "animate from
// previous to new value" so a poll reads as "N new things arrived", not a
// silent number swap. Never fires on first mount (nothing to diff against
// yet) and never fires on a decrease -- every counter this app tracks
// (ingested/triaged/bar counts/ticker totals) is monotonically increasing
// in practice, so there's no real "-N" case to design for.
const DELTA_HOLD_MS = 1500;

// Named export purely for direct unit testing -- exercising the real
// poll-to-poll delta behavior through the full fetch/setInterval cycle
// would mean mocking fetch timing and framer-motion's rAF-driven tween
// together, which buys nothing a focused hook test doesn't already cover.
export function useDeltaCountUp(target, reduceMotion) {
  const display = useCountUp(target, reduceMotion);
  const prevRef = useRef(target);
  const [delta, setDelta] = useState(0);

  useEffect(() => {
    const prev = prevRef.current;
    prevRef.current = target;
    if (target > prev) {
      setDelta(target - prev);
      const t = setTimeout(() => setDelta(0), DELTA_HOLD_MS);
      return () => clearTimeout(t);
    }
  }, [target]);

  return { display, delta };
}

function DeltaBadge({ delta }) {
  if (!delta) return null;
  return (
    <span className="text-[10px] font-bold text-green-400 tabular-nums" aria-label={`increased by ${delta}`}>
      +{delta}
    </span>
  );
}

function Cursor() {
  const reduce = useReducedMotion();
  return (
    <span
      className={`inline-block w-[0.6em] h-[1em] bg-accent align-middle ml-1 ${reduce ? "" : "animate-pulse"}`}
      aria-hidden="true"
    />
  );
}

// Downloads exactly what's on screen -- the same `stats` object already
// fetched for rendering, not a second server round-trip -- so there's no
// way for the export to disagree with what the dashboard is showing at
// the moment of the click. JSON rather than CSV: the shape is a mix of
// scalars (total/triaged/...), ranked arrays (severity/ttps), and keyed
// distributions (tag_distribution/ioc_distribution) that don't flatten
// into one honest table without inventing a schema nobody asked for.
function downloadDashboardExport(stats, range) {
  const payload = {
    exported_at: new Date().toISOString(),
    window: range.window,
    from: range.from,
    to: range.to,
    ...stats,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const stamp = payload.exported_at.replace(/[:.]/g, "-");
  a.download = `dashboard-export-${range.window}-${stamp}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function DashboardWidgets({ apiKey, onSwitchToFeed }) {
  const [stats, setStats] = useState(null);
  const [range, setRange] = useState({ window: "all", from: null, to: null });
  const { toggleSeverity, toggleTag, toggleIoc, toggleTtp, clearAll } = useFilters();
  const reduceMotion = useReducedMotion();

  const fetchStats = useCallback(() => {
    const token = currentToken(apiKey);
    if (!token) return;
    if (range.window === "custom" && (!range.from || !range.to)) return;
    const params = new URLSearchParams({ window: range.window });
    if (range.window === "custom") {
      params.set("from", range.from);
      params.set("to", range.to);
    }
    fetch(`${API}/api/dashboard/stats?${params.toString()}`, {
      headers: { Authorization: "Bearer " + token },
    })
      .then((r) => {
        if (!r.ok) throw new Error(`stats ${r.status}`);
        return r.json();
      })
      .then((d) => setStats(normalizeStats(d)))
      .catch(() => setStats(normalizeStats({})));
  }, [apiKey, range]);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  if (!stats) return <div className="text-text-dim text-sm p-4 font-mono">Establishing link…</div>;

  const pctTriaged   = stats.total ? Math.round((stats.triaged / stats.total) * 100) : 0;
  const severityRows = stats.severity;
  const ttpRows      = stats.ttps;
  const totalSev     = severityRows.reduce((s, r) => s + (r.count || 0), 0) || 1;
  const maxTtp        = ttpRows[0]?.count || 1;

  const sortedSev = severityRows
    .slice()
    .sort((a, b) => (SEVERITY_META[a.label]?.order ?? 9) - (SEVERITY_META[b.label]?.order ?? 9));

  function goFilter(fn) {
    clearAll();
    fn();
    onSwitchToFeed();
  }

  function tagPanel(key) {
    const meta = TAG_META[key] || IOC_META[key];
    const source = TAG_META[key] ? stats.tag_distribution[key] : stats.ioc_distribution[key];
    const rows = Array.isArray(source) ? source.slice(0, 6) : [];
    if (!meta || rows.length === 0) return null;
    const max = rows[0]?.count || 1;
    return (
      <RankedPanel
        key={key}
        title={meta.label}
        color={meta.color}
        rows={rows}
        max={max}
        onSelect={(value) =>
          goFilter(() => (meta.toggle === "ioc" ? toggleIoc(key, value) : toggleTag(key, value)))
        }
        reduceMotion={reduceMotion}
      />
    );
  }

  return (
    <div className="p-4 space-y-4">
      {/* ---- Signal masthead: one continuous instrument reading, not four
          disconnected tiles -- the entry point for a shift-start glance. */}
      <div className="border border-border rounded-sm bg-surface px-4 py-3">
        <div className="flex items-center justify-between mb-2">
          <div className="text-[10px] font-bold text-accent tracking-[0.2em]">
            ▓ SIGNAL STATUS<Cursor />
          </div>
          <div className="flex items-center gap-3">
            <TimeRangeToggle value={{ window: range.window }} onChange={setRange} />
            <button
              onClick={() => downloadDashboardExport(stats, range)}
              className="text-[10px] px-2 py-1 rounded border border-border text-text-dim hover:text-text hover:border-text-dim tracking-wide"
              title="Download the current dashboard stats as JSON"
            >
              EXPORT
            </button>
            <div className="text-[10px] text-text-dim tracking-wide">
              LAST POLL {relativeTime(stats.enrichment.last_poll)}
            </div>
          </div>
        </div>
        <div className="flex items-baseline flex-wrap gap-x-8 gap-y-2">
          <Reading target={stats.total} reduceMotion={reduceMotion} label="INGESTED" />
          <Reading target={stats.triaged} reduceMotion={reduceMotion} label={`TRIAGED (${pctTriaged}%)`} accent />
          <Reading target={stats.pending} reduceMotion={reduceMotion} label="PENDING" />
          <Reading target={stats.needs_retriage} reduceMotion={reduceMotion} label="FAILED / UNKNOWN" warn={stats.needs_retriage > 0} />
        </div>
      </div>

      {/* ---- Threat landscape: severity + TTPs kept from the prior layout,
          plus the tag/IOC distribution the API already computed but no
          view ever surfaced -- real classified intelligence, not decoration. */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <RankedPanel
          title="Severity"
          color="var(--color-accent)"
          rows={sortedSev.map((r) => ({ value: r.label, count: r.count, color: SEVERITY_META[r.label]?.color }))}
          max={totalSev}
          mono={false}
          onSelect={(value) => goFilter(() => toggleSeverity(value))}
          reduceMotion={reduceMotion}
        />
        <RankedPanel
          title="Top TTPs"
          color="var(--color-accent)"
          rows={ttpRows.slice(0, 6).map((r) => ({ value: r.technique, count: r.count }))}
          max={maxTtp}
          mono
          onSelect={(value) => goFilter(() => toggleTtp(value))}
          reduceMotion={reduceMotion}
        />
        {["threat_actor_types", "malware_types", "target_sectors", "cves", "platforms"]
          .map(tagPanel)
          .filter(Boolean)}
      </div>

      {/* ---- Pipeline health: same ticker-strip language as the masthead. */}
      <div className="border border-border rounded-sm bg-surface px-4 py-2.5 flex flex-wrap gap-x-8 gap-y-1 text-[11px]">
        <Ticker label="SOURCES ACTIVE" value={stats.enrichment.sources_active ?? "—"} reduceMotion={reduceMotion} />
        <Ticker label="IOCs EXTRACTED" value={stats.enrichment.iocs_extracted ?? "—"} reduceMotion={reduceMotion} />
        <Ticker label="DUPES SUPPRESSED" value={stats.enrichment.dupes_suppressed ?? "—"} reduceMotion={reduceMotion} />
      </div>
    </div>
  );
}

function Reading({ target, reduceMotion, label, accent = false, warn = false }) {
  const { display, delta } = useDeltaCountUp(target || 0, reduceMotion);
  return (
    <div className="flex items-baseline gap-2">
      <span className={`text-2xl font-bold tabular-nums ${warn ? "text-yellow-400" : accent ? "text-accent" : "text-text"}`}>
        {display.toLocaleString()}
      </span>
      <DeltaBadge delta={delta} />
      <span className="text-[10px] text-text-dim tracking-wider">{label}</span>
    </div>
  );
}

function Ticker({ label, value, reduceMotion }) {
  const numeric = typeof value === "number";
  const { display, delta } = useDeltaCountUp(numeric ? value : 0, reduceMotion);
  return (
    <div className="text-text-dim">
      {label}{" "}
      <span className="text-text font-bold tabular-nums">{numeric ? display.toLocaleString() : value}</span>
      {numeric && <DeltaBadge delta={delta} />}
    </div>
  );
}

function RankedPanel({ title, color, rows, max, mono = true, onSelect, reduceMotion }) {
  return (
    <div className="border border-border rounded-sm p-3">
      <div className="flex items-center gap-1.5 text-[10px] font-bold text-text-dim mb-2 tracking-wider">
        <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: color }} />
        {title.toUpperCase()}
      </div>
      {rows.length === 0 && <div className="text-[10px] text-text-dim italic">No data yet.</div>}
      {rows.map((row) => (
        <RankedRow
          key={row.value}
          row={row}
          max={max}
          color={color}
          mono={mono}
          onSelect={onSelect}
          reduceMotion={reduceMotion}
        />
      ))}
    </div>
  );
}

// Its own component (not an inline .map() callback) so each row's count-up/
// delta state persists across a poll via React's key-based reconciliation --
// the same reason `Reading`/`Ticker` own their own animation state instead
// of the parent precomputing it. The bar's width transitions smoothly
// between polls via a plain CSS transition (no framer-motion needed for a
// single-property interpolation like this); `motion-reduce:transition-none`
// is Tailwind's built-in `prefers-reduced-motion` variant, matching the
// same user preference `useCountUp`/`Cursor` already respect via JS.
function RankedRow({ row, max, color, mono, onSelect, reduceMotion }) {
  const { display, delta } = useDeltaCountUp(row.count || 0, reduceMotion);
  const pct = Math.round((row.count / max) * 100);
  return (
    <div
      className="flex items-center gap-2 mb-1 cursor-pointer group"
      onClick={() => onSelect(row.value)}
      title={`Filter by ${row.value}`}
    >
      <span className={`text-[10px] w-24 truncate text-text-dim group-hover:text-text ${mono ? "font-mono" : ""}`}>
        {row.value}
      </span>
      <div className="flex-1 bg-border rounded-sm h-2 overflow-hidden">
        <div
          className="h-full rounded-sm transition-[width] duration-500 ease-out motion-reduce:transition-none"
          style={{ width: `${pct}%`, background: row.color || color }}
        />
      </div>
      <span className="text-[10px] text-text-dim w-6 text-right tabular-nums">{display}</span>
      <DeltaBadge delta={delta} />
    </div>
  );
}
