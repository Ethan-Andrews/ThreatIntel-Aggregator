import { useCallback, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';

/**
 * Shared apply/dismiss + multi-select state for stage-7 tuning suggestions
 * (tune.py's proposed narrowed KQL, surfaced on an analytic row's
 * `tuning_suggestion` field). Used by both HuntsPanel.js and
 * DetectionsCatalogPanel.js -- they render the same underlying `analytics`
 * rows, just grouped differently, so one hook covers the single-row and
 * multi-select batch cases in both panels rather than duplicating this
 * logic per panel.
 *
 * onDone(results) is called after a successful apply/dismiss call (single
 * or batch) with the per-id results array, so the caller can refresh
 * whatever list/detail data it's showing without this hook needing to know
 * the shape of that data.
 */
export default function useTuningSuggestions(authFetch, onDone) {
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const toggleSelected = useCallback((id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const clearSelected = useCallback(() => setSelectedIds(new Set()), []);

  const post = useCallback((action, ids) => {
    if (!ids || ids.length === 0) return Promise.resolve([]);
    setBusy(true);
    setError(null);
    return authFetch(`${API}/api/detections/tuning-suggestions/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analytic_ids: ids }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || `Failed to ${action} tuning suggestion(s).`);
        }
        return r.json();
      })
      .then((data) => {
        const results = data.results || [];
        setSelectedIds((prev) => {
          const next = new Set(prev);
          ids.forEach((id) => next.delete(id));
          return next;
        });
        onDone?.(results);
        return results;
      })
      .catch((err) => {
        setError(err.message || `Failed to ${action} tuning suggestion(s).`);
        return [];
      })
      .finally(() => setBusy(false));
  }, [authFetch, onDone]);

  return {
    selectedIds,
    toggleSelected,
    clearSelected,
    busy,
    error,
    applyOne: (id) => post('apply', [id]),
    dismissOne: (id) => post('dismiss', [id]),
    applySelected: () => post('apply', Array.from(selectedIds)),
    dismissSelected: () => post('dismiss', Array.from(selectedIds)),
  };
}
