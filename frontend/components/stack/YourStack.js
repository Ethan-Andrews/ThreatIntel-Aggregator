import { useState, useEffect, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function authHeader(apiKey) {
  const liveToken = (typeof window !== "undefined" && sessionStorage.getItem("ti_app_token")) || apiKey || "";
  return { Authorization: "Bearer " + liveToken, "Content-Type": "application/json" };
}

const CATEGORY_COLORS = {
  "Endpoint":           "#f85149",
  "Cloud":              "#58a6ff",
  "SIEM":               "#e3b341",
  "Firewall / Network": "#fd7e14",
  "Identity":           "#bc8cff",
  "SaaS":               "#3fb950",
  "Other":              "#8b949e",
};

export default function YourStack({ apiKey, onRematchComplete }) {
  const [presets,      setPresets]      = useState([]);
  const [stack,        setStack]        = useState([]);
  const [openCats,     setOpenCats]     = useState({});
  const [search,       setSearch]       = useState("");
  const [customInputs, setCustomInputs] = useState({});
  const [dirty,        setDirty]        = useState(false);
  const [rematching,   setRematching]   = useState(false);
  const [toast,        setToast]        = useState(null);

  const showToast = useCallback((msg, variant = "success") => {
    setToast({ msg, variant });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const fetchPresets = useCallback(() => {
    fetch(`${API}/api/stack/categories`, { headers: authHeader(apiKey) })
      .then((r) => r.json())
      .then((d) => setPresets(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, [apiKey]);

  const fetchStack = useCallback(() => {
    fetch(`${API}/api/stack`, { headers: authHeader(apiKey) })
      .then((r) => r.json())
      .then((d) => setStack(Array.isArray(d) ? d : []))
      .catch(() => {});
  }, [apiKey]);

  useEffect(() => {
    fetchPresets();
    fetchStack();
  }, [fetchPresets, fetchStack]);

  const addedNames = new Set(
    stack.flatMap((g) => g.items.map((i) => i.name))
  );

  function toggleCategory(cat) {
    setOpenCats((prev) => ({ ...prev, [cat]: !prev[cat] }));
  }

  function addItem(category, name, keywords) {
    fetch(`${API}/api/stack`, {
      method:  "POST",
      headers: authHeader(apiKey),
      body:    JSON.stringify({ category, name, keywords }),
    })
      .then((r) => {
        if (r.status === 409) { showToast(`"${name}" already in stack`, "error"); throw new Error(); }
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(() => { fetchStack(); setDirty(true); })
      .catch(() => {});
  }

  function removeItem(id) {
    fetch(`${API}/api/stack/${id}`, { method: "DELETE", headers: authHeader(apiKey) })
      .then((r) => { if (!r.ok) throw new Error(); })
      .then(() => { fetchStack(); setDirty(true); })
      .catch(() => showToast("Failed to remove item", "error"));
  }

  function handleRematch() {
    setRematching(true);
    fetch(`${API}/api/stack/rematch`, { method: "POST", headers: authHeader(apiKey) })
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then((d) => {
        if (d.status === "already_running") {
          showToast("Rematch already in progress", "error");
        } else {
          setDirty(false);
          showToast("Rematch started — feed scores will update shortly");
          onRematchComplete?.();
        }
      })
      .catch(() => showToast("Failed to start rematch", "error"))
      .finally(() => setRematching(false));
  }

  const filteredPresets = presets.map((cat) => ({
    ...cat,
    vendors: (cat.vendors || []).filter((v) =>
      !search || v.name.toLowerCase().includes(search.toLowerCase())
    ),
  })).filter((cat) => !search || cat.vendors.length > 0);

  return (
    <div className="flex h-full overflow-hidden">
      {/* Toast */}
      {toast && (
        <div className={`fixed bottom-4 right-4 z-50 px-4 py-3 rounded border text-sm shadow-xl ${
          toast.variant === "error"
            ? "bg-surface border-red-600 text-red-400"
            : "bg-surface border-emerald-600 text-emerald-400"
        }`}>
          {toast.msg}
        </div>
      )}

      {/* LEFT: Category browser */}
      <div className="w-80 shrink-0 border-r border-border overflow-y-auto p-4">
        <h2 className="text-xs font-bold text-text-dim uppercase tracking-wider mb-3">Add to Stack</h2>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search vendors..."
          className="w-full bg-surface border border-border rounded-sm px-3 py-1.5 text-xs text-text placeholder-text-dim mb-3 outline-hidden focus:border-accent"
        />

        {filteredPresets.map((cat) => {
          const isOpen = openCats[cat.category] !== false; // default open
          const color  = CATEGORY_COLORS[cat.category] || "#8b949e";
          return (
            <div key={cat.category} className="mb-1">
              <button
                onClick={() => toggleCategory(cat.category)}
                className="flex items-center justify-between w-full px-3 py-2 bg-surface border border-border rounded-sm text-xs font-bold hover:text-text"
              >
                <span style={{ color }}>{cat.category}</span>
                <span className="text-[10px] text-text-dim">{isOpen ? "▾" : "▸"}</span>
              </button>

              {isOpen && (
                <div className="border border-border border-t-0 rounded-b px-2 pb-2 bg-background">
                  {cat.vendors.map((v) => {
                    const added = addedNames.has(v.name);
                    return (
                      <div key={v.name} className="flex items-center justify-between py-1 px-1 rounded-sm hover:bg-surface">
                        <span className={`text-xs ${added ? "text-emerald-400" : "text-text"}`}>{v.name}</span>
                        <button
                          disabled={added}
                          onClick={() => addItem(cat.category, v.name, v.keywords)}
                          className={`text-[10px] px-2 py-0.5 rounded border ${
                            added
                              ? "border-border text-text-dim cursor-default"
                              : "border-emerald-600 text-emerald-400 hover:bg-emerald-900"
                          }`}
                        >
                          {added ? "✓" : "+ Add"}
                        </button>
                      </div>
                    );
                  })}

                  {/* Custom entry */}
                  <div className="flex gap-1 mt-2 pt-2 border-t border-border">
                    <input
                      value={customInputs[cat.category] || ""}
                      onChange={(e) => setCustomInputs((p) => ({ ...p, [cat.category]: e.target.value }))}
                      placeholder="Add custom product..."
                      className="flex-1 bg-surface border border-border rounded-sm px-2 py-1 text-xs text-text placeholder-text-dim outline-hidden focus:border-accent"
                    />
                    <button
                      onClick={() => {
                        const name = (customInputs[cat.category] || "").trim();
                        if (!name) return;
                        addItem(cat.category, name, [name]);
                        setCustomInputs((p) => ({ ...p, [cat.category]: "" }));
                      }}
                      className="text-[10px] px-2 py-1 rounded-sm border border-emerald-600 text-emerald-400 hover:bg-emerald-900 whitespace-nowrap"
                    >
                      + Add
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* RIGHT: Current stack */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-bold text-text">
            Your Stack
            <span className="ml-2 text-[10px] font-bold px-1.5 py-0.5 rounded-sm bg-emerald-900 border border-emerald-600 text-emerald-400">
              {stack.reduce((n, g) => n + g.items.length, 0)} items
            </span>
          </span>
          <div className="flex items-center gap-2">
            {dirty && (
              <span className="text-[10px] text-yellow-400 border border-yellow-700 rounded-sm px-2 py-0.5">
                Stack changed — rematch to update scores
              </span>
            )}
            <button
              onClick={handleRematch}
              disabled={rematching}
              className="text-[10px] px-3 py-1 rounded-sm border border-accent text-accent hover:bg-surface disabled:opacity-50"
            >
              {rematching ? "…" : "↻ Rematch Feed"}
            </button>
          </div>
        </div>

        {stack.length === 0 && (
          <div className="text-text-dim text-xs text-center py-16">
            No items in your stack yet. Add vendors from the left panel.
          </div>
        )}

        {stack.map((group) => {
          const color = CATEGORY_COLORS[group.category] || "#8b949e";
          return (
            <div key={group.category} className="mb-5">
              <div
                className="text-[10px] font-bold uppercase tracking-wider mb-2"
                style={{ color }}
              >
                {group.category}
              </div>
              <div className="flex flex-wrap gap-2">
                {group.items.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-center gap-2 bg-surface border border-border rounded-full px-3 py-1 text-xs text-text"
                  >
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: color }} />
                    {item.name}
                    <button
                      onClick={() => removeItem(item.id)}
                      className="text-text-dim hover:text-red-400 leading-none ml-1"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
