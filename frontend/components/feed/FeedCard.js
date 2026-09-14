import { useState } from "react";
import DuplicateSourcesBadge from "../DuplicateSourcesBadge";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function safeHref(url) {
  if (!url) return "#";
  try { return ["http:", "https:"].includes(new URL(url).protocol) ? url : "#"; }
  catch { return "#"; }
}
const DISPLAY_TIMEZONE = "America/Chicago";

const SEVERITY_CLASS = {
  Critical:      "bg-red-700 text-white",
  High:          "bg-orange-500 text-white",
  Medium:        "bg-yellow-400 text-black",
  Low:           "bg-emerald-600 text-white",
  Informational: "bg-blue-600 text-white",
  Unknown:       "bg-zinc-700 text-zinc-400",
};

const TAG_COLORS = {
  indicator_types:    "#00cec9",
  malware_types:      "#e84393",
  threat_actor_types: "#e17055",
  target_sectors:     "#a29bfe",
  platforms:          "#74b9ff",
};

const TAG_LABELS = {
  indicator_types:    "TYPE",
  malware_types:      "MALWARE",
  threat_actor_types: "ACTOR",
  target_sectors:     "TARGET",
  platforms:          "PLATFORM",
};

function parseIocs(raw) {
  try {
    const p = typeof raw === "string" ? JSON.parse(raw) : (raw || {});
    return {
      threat_actors: p.threat_actors || [],
      ips:           p.ips           || [],
      hashes:        p.hashes        || [],
      cves:          p.cves          || [],
    };
  } catch { return { threat_actors: [], ips: [], hashes: [], cves: [] }; }
}

function parseTags(raw) {
  try {
    const p = typeof raw === "string" ? JSON.parse(raw) : (raw || {});
    return {
      indicator_types:    p.indicator_types    || [],
      malware_types:      p.malware_types      || [],
      threat_actor_types: p.threat_actor_types || [],
      target_sectors:     p.target_sectors     || [],
      platforms:          p.platforms          || [],
    };
  } catch {
    return { indicator_types: [], malware_types: [], threat_actor_types: [], target_sectors: [], platforms: [] };
  }
}

export default function FeedCard({ entry, apiKey, selected = false, onSelect }) {
  const [triage, setTriage] = useState({
    severity:   entry.severity   || "Unknown",
    ttps:       entry.ttps       || "",
    ai_summary: entry.ai_summary || "",
    tags:       entry.tags       || "{}",
    iocs:       entry.iocs       || "{}",
  });
  const [retriageState, setRetriagedState] = useState("idle");

  const tags    = parseTags(triage.tags);
  const iocData = parseIocs(triage.iocs);
  const ttps    = triage.ttps ? triage.ttps.split(",").filter(Boolean) : [];
  const sevClass = SEVERITY_CLASS[triage.severity] || SEVERITY_CLASS.Unknown;

  const stackMatch = Boolean(entry.stack_match);
  const stackMatchedItems = (() => {
    try { return JSON.parse(entry.stack_matched_items || "[]"); } catch { return []; }
  })();

  const displayTimestampRaw = entry.published || entry.ingested || "";
  const displayTimestamp = (() => {
    if (!displayTimestampRaw) return "";
    const parsed = new Date(displayTimestampRaw);
    if (Number.isNaN(parsed.getTime())) return "";
    return parsed.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZone: DISPLAY_TIMEZONE,
    });
  })();

  function handleRetriage() {
    if (retriageState !== "idle") return;
    setRetriagedState("loading");
    const liveToken = (typeof window !== "undefined" && sessionStorage.getItem("ti_app_token")) || apiKey || "";
    fetch(`${API}/api/entries/${entry.hash}/retriage`, {
      method:  "POST",
      headers: { Authorization: "Bearer " + liveToken },
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((result) => {
        setTriage({
          severity:   result.severity,
          ttps:       result.ttps,
          ai_summary: result.ai_summary,
          tags:       result.tags,
          iocs:       result.iocs,
        });
        setRetriagedState("done");
        setTimeout(() => setRetriagedState("idle"), 3000);
      })
      .catch(() => {
        setRetriagedState("error");
        setTimeout(() => setRetriagedState("idle"), 3000);
      });
  }

  return (
    <div className={`border rounded mb-2 bg-surface transition-colors ${
      stackMatch ? "border-green-600" : selected ? "border-accent" : "border-border"
    }`}>
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onSelect?.(entry.hash)}
          className="accent-accent"
        />
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-sm ${sevClass}`}>
          {triage.severity.toUpperCase()}
        </span>
        {entry.priority_score != null && (
          <span className="text-xs text-text-dim font-mono">{entry.priority_score.toFixed(2)}</span>
        )}
        {stackMatch && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-green-900 text-green-400 border border-green-600">
            ⚡ Your Stack
          </span>
        )}
        {entry.runzero_confidence === "confirmed" && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-red-900 text-red-400 border border-red-600">
            CONFIRMED
          </span>
        )}
        {entry.runzero_confidence === "possible" && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-yellow-900 text-yellow-400 border border-yellow-600">
            POSSIBLE
          </span>
        )}
        <span className="flex items-center gap-1 text-xs text-text-dim">
          {entry.source}
          <DuplicateSourcesBadge
            hash={entry.hash}
            duplicateCount={entry.duplicate_count || 0}
            apiKey={apiKey}
          />
        </span>
        <span className="flex-1" />
        <span className="text-[10px] text-text-dim">{displayTimestamp}</span>
        <button
          onClick={handleRetriage}
          disabled={retriageState !== "idle"}
          className={`text-[10px] border rounded px-2 py-0.5 transition-colors ${
            retriageState === "idle"    ? "border-border text-text-dim hover:border-accent hover:text-accent" :
            retriageState === "loading" ? "border-yellow-600 text-yellow-400 cursor-wait" :
            retriageState === "done"    ? "border-green-600 text-green-400" :
                                          "border-red-600 text-red-400"
          }`}
        >
          {retriageState === "idle"    ? "⟳" :
           retriageState === "loading" ? "…" :
           retriageState === "done"    ? "✓" : "✗"}
        </button>
      </div>

      <div className="px-3 py-2">
        <a
          href={safeHref(entry.link)}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-text hover:text-accent line-clamp-2"
        >
          {entry.title}
        </a>
        {triage.ai_summary && (
          <p className="text-xs text-text-dim mt-1">{triage.ai_summary}</p>
        )}
      </div>

      {(Object.values(tags).some((a) => a.length) || iocData.cves.length > 0 || iocData.threat_actors.length > 0 || ttps.length > 0) && (
        <div className="px-3 pb-2 flex flex-wrap gap-1 overflow-x-auto">
          {Object.entries(tags).map(([cat, vals]) =>
            vals.map((v) => (
              <span
                key={`${cat}-${v}`}
                className="text-[10px] rounded-sm px-1.5 py-0.5 border font-mono"
                style={{ borderColor: TAG_COLORS[cat], color: TAG_COLORS[cat] }}
              >
                {TAG_LABELS[cat]}: {v}
              </span>
            ))
          )}
          {iocData.threat_actors.map((ta) => (
            <span key={`ta-${ta}`} className="text-[10px] border rounded-sm px-1.5 py-0.5 font-mono" style={{ borderColor: "#fd79a8", color: "#fd79a8" }}>
              ACTOR: {ta}
            </span>
          ))}
          {iocData.cves.map((cve) => (
            <span key={cve} className="text-[10px] border rounded-sm px-1.5 py-0.5 font-mono" style={{ borderColor: "#fdcb6e", color: "#fdcb6e" }}>
              CVE: {cve}
            </span>
          ))}
          {ttps.map((t) => (
            <span key={t} className="text-[10px] border rounded-sm px-1.5 py-0.5 font-mono border-green-600 text-green-400">
              {t}
            </span>
          ))}
        </div>
      )}
      {stackMatchedItems.length > 0 && (
        <div className="px-3 pb-2 flex flex-wrap gap-1">
          <span className="text-[10px] text-green-500 font-bold mr-1">Matched:</span>
          {stackMatchedItems.map((item) => (
            <span key={item} className="text-[10px] border rounded-sm px-1.5 py-0.5 font-mono border-green-700 text-green-400 bg-green-950">
              {item}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
