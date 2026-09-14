import { useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import { useFilters } from "../../context/FilterContext";

const SEVERITY_COLORS = {
  Critical:      "#c0392b",
  High:          "#e17055",
  Medium:        "#f9ca24",
  Low:           "#00b894",
  Informational: "#0984e3",
  Unknown:       "#4a6a4a",
};
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"];

const TAG_GROUPS = [
  { key: "indicator_types",    label: "Type",     color: "#00cec9" },
  { key: "malware_types",      label: "Malware",  color: "#e84393" },
  { key: "threat_actor_types", label: "Actor",    color: "#e17055" },
  { key: "target_sectors",     label: "Target",   color: "#a29bfe" },
  { key: "platforms",          label: "Platform", color: "#74b9ff" },
];

const IOC_GROUPS = [
  { key: "threat_actors", label: "Threat Actors", color: "#fd79a8" },
  { key: "cves",          label: "CVEs",          color: "#fdcb6e" },
];

const DATE_WINDOWS = [
  { value: "24h", label: "24h" },
  { value: "48h", label: "48h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
  { value: "90d", label: "90d" },
  { value: "all", label: "All" },
];

const CHIP_COLORS = {
  Critical: "#c0392b", High: "#e17055", Medium: "#f9ca24",
  Low: "#00b894", Informational: "#0984e3", Unknown: "#4a6a4a",
  indicator_types: "#00cec9", malware_types: "#e84393",
  threat_actor_types: "#e17055", target_sectors: "#a29bfe", platforms: "#74b9ff",
  threat_actors: "#fd79a8", cves: "#fdcb6e",
  ttp: "#00ff88",
};

function FilterButton({ label, activeCount, children }) {
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button className="flex items-center gap-1 text-xs border border-border rounded-sm px-3 py-1 text-text-dim hover:text-text hover:border-accent transition-colors">
          {label}
          {activeCount > 0 && (
            <span className="bg-accent text-background rounded-full text-[10px] px-1.5 font-bold">
              {activeCount}
            </span>
          )}
          <span className="ml-1">▾</span>
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          className="z-50 bg-surface border border-border rounded-sm shadow-xl p-3 min-w-[200px] max-h-[360px] overflow-y-auto"
          sideOffset={4}
        >
          {children}
          <Popover.Arrow className="fill-border" />
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

function CheckRow({ label, color, checked, count, onToggle }) {
  return (
    <label className="flex items-center gap-2 py-0.5 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={onToggle} className="accent-accent" />
      {color && (
        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
      )}
      <span className="text-xs text-text flex-1">{label}</span>
      {count != null && (
        <span className="text-[10px] text-text-dim">{count}</span>
      )}
    </label>
  );
}

function Chip({ label, color, onRemove }) {
  return (
    <span
      className="inline-flex items-center gap-1 text-[10px] rounded-sm px-2 py-0.5 border font-mono"
      style={{ borderColor: color, color }}
    >
      {label}
      <button onClick={onRemove} className="ml-0.5 hover:opacity-60">×</button>
    </span>
  );
}

export default function TopFilterBar({ tagDistribution, iocDistribution, ttpDistribution }) {
  const {
    activeSeverities, activeTagFilters, activeIocFilters, activeTtps,
    dateWindow, setDateWindow,
    toggleSeverity, toggleTag, toggleIoc, toggleTtp, clearAll,
  } = useFilters();

  const hasAny =
    activeSeverities.length > 0 ||
    activeTagFilters.length > 0 ||
    activeIocFilters.length > 0 ||
    activeTtps.length > 0;

  const dist  = tagDistribution  || {};
  const iDist = iocDistribution  || {};
  // ttpDistribution is its own top-level prop, not nested under
  // tagDistribution -- the dashboard/stats API returns `ttps` as a
  // sibling of `tag_distribution`, not a member of it (see pages/index.js's
  // fetchDistributions(), which previously never captured it at all,
  // leaving this dropdown permanently empty).
  const ttpList = ttpDistribution || [];

  return (
    <div className="border-b border-border bg-surface px-4 py-2 space-y-2 shrink-0">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1 mr-2">
          <span className="text-[10px] text-text-dim font-bold">TIME</span>
          {DATE_WINDOWS.map((w) => (
            <button
              key={w.value}
              onClick={() => setDateWindow(w.value)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                dateWindow === w.value
                  ? "border-accent text-accent"
                  : "border-border text-text-dim hover:text-text"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>

        <FilterButton label="Severity" activeCount={activeSeverities.length}>
          {SEVERITIES.map((sev) => {
            const count = dist.severity?.find((r) => r.label === sev)?.count;
            return (
              <CheckRow
                key={sev}
                label={sev}
                color={SEVERITY_COLORS[sev]}
                checked={activeSeverities.includes(sev)}
                count={count}
                onToggle={() => toggleSeverity(sev)}
              />
            );
          })}
        </FilterButton>

        <FilterButton label="Tags" activeCount={activeTagFilters.length}>
          {TAG_GROUPS.map((group) => {
            const values = dist[group.key] || [];
            if (values.length === 0) return (
              <div key={group.key} className="mb-2">
                <div className="text-[10px] text-text-dim font-bold mb-1">{group.label}</div>
                <div className="text-[10px] text-text-dim italic">No data</div>
              </div>
            );
            return (
              <div key={group.key} className="mb-3">
                <div className="text-[10px] font-bold mb-1" style={{ color: group.color }}>
                  {group.label}
                </div>
                {values.map((item) => (
                  <CheckRow
                    key={item.value}
                    label={item.value}
                    color={group.color}
                    checked={activeTagFilters.some((f) => f.category === group.key && f.value === item.value)}
                    count={item.count}
                    onToggle={() => toggleTag(group.key, item.value)}
                  />
                ))}
              </div>
            );
          })}
        </FilterButton>

        <FilterButton label="IOCs" activeCount={activeIocFilters.length}>
          {IOC_GROUPS.map((group) => {
            const values = iDist[group.key] || [];
            if (values.length === 0) return (
              <div key={group.key} className="mb-2">
                <div className="text-[10px] text-text-dim font-bold mb-1">{group.label}</div>
                <div className="text-[10px] text-text-dim italic">No data</div>
              </div>
            );
            return (
              <div key={group.key} className="mb-3">
                <div className="text-[10px] font-bold mb-1" style={{ color: group.color }}>
                  {group.label}
                </div>
                {values.map((item) => (
                  <CheckRow
                    key={item.value}
                    label={item.value}
                    color={group.color}
                    checked={activeIocFilters.some((f) => f.category === group.key && f.value === item.value)}
                    count={item.count}
                    onToggle={() => toggleIoc(group.key, item.value)}
                  />
                ))}
              </div>
            );
          })}
        </FilterButton>

        <FilterButton label="TTPs" activeCount={activeTtps.length}>
          {ttpList.length === 0
            ? <div className="text-[10px] text-text-dim italic">No data</div>
            : ttpList.map((item) => (
              <CheckRow
                key={item.value}
                label={item.value}
                checked={activeTtps.includes(item.value)}
                count={item.count}
                onToggle={() => toggleTtp(item.value)}
              />
            ))
          }
        </FilterButton>

        {hasAny && (
          <button
            onClick={clearAll}
            className="ml-auto text-xs text-text-dim hover:text-text underline"
          >
            Clear all
          </button>
        )}
      </div>

      {hasAny && (
        <div className="flex flex-wrap gap-1">
          {activeSeverities.map((sev) => (
            <Chip key={`sev-${sev}`} label={sev} color={CHIP_COLORS[sev] || "#888"} onRemove={() => toggleSeverity(sev)} />
          ))}
          {activeTagFilters.map((f) => (
            <Chip key={`tag-${f.category}-${f.value}`} label={f.value} color={CHIP_COLORS[f.category] || "#888"} onRemove={() => toggleTag(f.category, f.value)} />
          ))}
          {activeIocFilters.map((f) => (
            <Chip key={`ioc-${f.category}-${f.value}`} label={f.value} color={CHIP_COLORS[f.category] || "#888"} onRemove={() => toggleIoc(f.category, f.value)} />
          ))}
          {activeTtps.map((t) => (
            <Chip key={`ttp-${t}`} label={t} color={CHIP_COLORS.ttp} onRemove={() => toggleTtp(t)} />
          ))}
        </div>
      )}
    </div>
  );
}
