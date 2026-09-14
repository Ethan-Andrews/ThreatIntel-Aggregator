import { useState, useEffect } from "react";

function stixPattern(ioc) {
  if (!ioc) return "";
  switch (ioc.type) {
    case "ipv4-addr":    return `[ipv4-addr:value = '${ioc.value}']`;
    case "domain-name":  return `[domain-name:value = '${ioc.value}']`;
    case "url":          return `[url:value = '${ioc.value}']`;
    case "file":         return `[file:hashes.'${ioc.subtype || "SHA-256"}' = '${ioc.value}']`;
    case "vulnerability":return `external_references: [{source_name: "cve", external_id: "${ioc.value}"}]`;
    case "threat-actor": return `threat-actor SDO (no indicator pattern)`;
    default:             return "";
  }
}

function fmtDate(str) {
  if (!str) return "—";
  return new Date(str).toLocaleString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short",
  });
}

function EntryRow({ entry, onSwitchToFeed, userRole, onRemove }) {
  return (
    <div className="py-2 border-b border-border hover:bg-background">
      <div className="flex items-start gap-1">
        <div
          className="flex-1 cursor-pointer"
          onClick={onSwitchToFeed}
        >
          <div className="text-xs text-text font-medium line-clamp-2">{entry.title || "(no title)"}</div>
          <div className="flex gap-2 mt-0.5 text-[10px] text-text-dim">
            <span>{entry.source}</span>
            <span>·</span>
            <span>{entry.ingested?.slice(0, 10)}</span>
            {entry.severity && entry.severity !== "Unknown" && (
              <>
                <span>·</span>
                <span className={
                  entry.severity === "Critical" ? "text-red-400" :
                  entry.severity === "High" ? "text-orange-400" :
                  entry.severity === "Medium" ? "text-yellow-400" : "text-text-dim"
                }>
                  {entry.severity}
                </span>
              </>
            )}
          </div>
        </div>
        {userRole === "admin" && (
          <button
            onClick={onRemove}
            className="ml-1 mt-0.5 text-text-dim hover:text-red-400 text-xs leading-none shrink-0"
            title="Remove article association"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  );
}

export default function IocDetailPanel({
  ioc,
  entries,
  onClose,
  onSwitchToFeed,
  userRole,
  onDeleteIoc,
  onRemoveEntry,
  onSetBenign,
  isDeleting,
}) {
  const open = !!ioc;
  const [showBenignInput, setShowBenignInput] = useState(false);
  const [benignReason, setBenignReason] = useState("");

  useEffect(() => {
    setShowBenignInput(false);
    setBenignReason("");
  }, [ioc?.id]);

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-40"
          onClick={onClose}
        />
      )}
      <div
        className={`fixed inset-y-0 right-0 w-96 bg-surface border-l border-border flex flex-col z-50 shadow-2xl transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
          <span className="text-sm font-bold text-text">IOC Details</span>
          <div className="flex items-center gap-2">
            {userRole === "admin" && ioc && (
              ioc.benign ? (
                <button
                  onClick={() => onSetBenign && onSetBenign(ioc.id, false, "")}
                  disabled={isDeleting}
                  className="text-[10px] px-2 py-0.5 rounded-sm border border-border text-text-dim hover:text-text disabled:opacity-40"
                  title="Remove benign flag"
                >
                  Unmark benign
                </button>
              ) : showBenignInput ? (
                <div className="flex items-center gap-1">
                  <input
                    value={benignReason}
                    onChange={e => setBenignReason(e.target.value)}
                    placeholder="Reason (optional)"
                    className="text-xs bg-background border border-border rounded-sm px-2 py-0.5 text-text placeholder-text-dim outline-hidden w-32"
                  />
                  <button
                    onClick={() => {
                      onSetBenign && onSetBenign(ioc.id, true, benignReason);
                      setShowBenignInput(false);
                      setBenignReason("");
                    }}
                    className="text-[10px] text-accent hover:text-text"
                  >
                    Confirm
                  </button>
                  <button
                    onClick={() => { setShowBenignInput(false); setBenignReason(""); }}
                    className="text-[10px] text-text-dim hover:text-text"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setShowBenignInput(true)}
                  disabled={isDeleting}
                  className="text-[10px] px-2 py-0.5 rounded-sm border border-border text-text-dim hover:text-text disabled:opacity-40"
                  title="Mark this IOC as benign (suppress from ledger)"
                >
                  Mark benign
                </button>
              )
            )}
            {userRole === "admin" && ioc && (
              <button
                onClick={() => onDeleteIoc && onDeleteIoc(ioc.id)}
                disabled={isDeleting}
                className="text-text-dim hover:text-red-400 text-sm leading-none disabled:opacity-40"
                title="Delete IOC from ledger"
              >
                🗑
              </button>
            )}
            <button onClick={onClose} className="text-text-dim hover:text-text text-lg leading-none">✕</button>
          </div>
        </div>

        {ioc && (
          <div className="flex-1 overflow-y-auto">
            {/* Indicator attributes */}
            <div className="px-4 py-3 border-b border-border">
              <div className="text-[10px] text-text-dim font-bold tracking-wider mb-2">INDICATOR</div>
              <table className="w-full text-xs">
                <tbody>
                  {[
                    ["Type",        ioc.type],
                    ["Value",       ioc.value],
                    ["Subtype",     ioc.subtype || "—"],
                    ["First seen",  fmtDate(ioc.first_seen)],
                    ["Last seen",   fmtDate(ioc.last_seen)],
                    ["Occurrences", ioc.occurrence_count],
                    ...(ioc.benign ? [
                      ["Benign",  "Yes"],
                      ...(ioc.benign_reason ? [["Reason", ioc.benign_reason]] : []),
                    ] : []),
                  ].map(([label, val]) => (
                    <tr key={label} className="border-b border-border last:border-0">
                      <td className="py-1.5 pr-3 text-text-dim w-28 align-top">{label}</td>
                      <td className="py-1.5 text-text font-mono break-all">{val}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* STIX pattern */}
            <div className="px-4 py-3 border-b border-border">
              <div className="text-[10px] text-text-dim font-bold tracking-wider mb-2">STIX 2.1 PATTERN</div>
              <code className="text-[10px] text-accent bg-background rounded-sm p-2 block break-all">
                {stixPattern(ioc)}
              </code>
            </div>

            {/* Correlated articles */}
            <div className="px-4 py-3">
              <div className="text-[10px] text-text-dim font-bold tracking-wider mb-2">
                CORRELATED ARTICLES ({entries.length})
              </div>
              {entries.length === 0 && (
                <div className="text-xs text-text-dim">No articles found.</div>
              )}
              {entries.map(e => (
                <EntryRow
                  key={e.hash}
                  entry={e}
                  onSwitchToFeed={onSwitchToFeed}
                  userRole={userRole}
                  onRemove={() => onRemoveEntry && onRemoveEntry(ioc.id, e.hash)}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
