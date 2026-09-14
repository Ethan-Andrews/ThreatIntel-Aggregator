import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function safeHref(url) {
  if (!url) return "#";
  try {
    return ["http:", "https:"].includes(new URL(url).protocol) ? url : "#";
  } catch {
    return "#";
  }
}

export default function DuplicateSourcesBadge({ hash, duplicateCount, apiKey }) {
  const [open, setOpen] = useState(false);
  const [members, setMembers] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  if (!duplicateCount || duplicateCount < 1) return null;

  async function toggle() {
    if (open) {
      setOpen(false);
      return;
    }
    if (members !== null) {
      setOpen(true);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/entries/${hash}/group`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      // Skip the first entry (canonical = current card)
      setMembers(data.slice(1));
      setOpen(true);
    } catch (e) {
      setError("Failed to load sources.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <span className="inline-block">
      <button
        onClick={toggle}
        className="ml-2 px-2 py-0.5 text-xs rounded-sm bg-indigo-700 text-indigo-100 hover:bg-indigo-600 transition-colors"
        title={`Also covered by ${duplicateCount} other source${duplicateCount > 1 ? "s" : ""}`}
      >
        {loading ? "…" : `+${duplicateCount} source${duplicateCount > 1 ? "s" : ""}`}
      </button>

      {open && members !== null && (
        <div className="mt-1 ml-2 text-xs text-zinc-300 space-y-0.5">
          <div className="text-zinc-500 font-medium">Also covered by:</div>
          {error && <div className="text-red-400">{error}</div>}
          {members.map((m) => (
            <div key={m.hash} className="flex items-center gap-1">
              <span className="text-zinc-400">{m.source}</span>
              <span className="text-zinc-600">—</span>
              <span className="text-zinc-300 truncate max-w-xs">{m.title}</span>
              <a
                href={safeHref(m.link)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-indigo-400 hover:text-indigo-300 ml-1"
              >
                ↗
              </a>
            </div>
          ))}
        </div>
      )}
    </span>
  );
}
