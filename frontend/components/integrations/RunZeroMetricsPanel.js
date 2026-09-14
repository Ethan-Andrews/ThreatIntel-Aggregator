'use client';
import { useState, useEffect, useCallback } from 'react';
import TimeRangeToggle from '../layout/TimeRangeToggle';

const API = process.env.NEXT_PUBLIC_API_URL || '';

// Workstream F, docs/superpowers/specs/2026-09-04-live-feedback-round-6-
// design.md -- built on exposure_items (TI-correlated, remediation-
// tracked matches), not raw RunZero CVE rows (runzero_vulns has zero
// history, full overwrite every sync). "Tracked exposures," not
// unqualified "vulnerabilities" -- this is the scope tradeoff the design
// doc's own honesty requirement calls for.

function LineChart({ intakeRows, remediatedRows, org }) {
  const filteredIntake = org === 'all' ? intakeRows : intakeRows.filter((r) => r.org === org);
  const filteredRemediated = org === 'all' ? remediatedRows : remediatedRows.filter((r) => r.org === org);

  const dates = Array.from(
    new Set([...filteredIntake.map((r) => r.date), ...filteredRemediated.map((r) => r.date)]),
  ).sort();

  if (dates.length === 0) {
    return <div className="text-xs text-text-dim italic">No tracked exposures in this window.</div>;
  }

  const intakeByDate = {};
  for (const r of filteredIntake) intakeByDate[r.date] = (intakeByDate[r.date] || 0) + r.count;
  const remediatedByDate = {};
  for (const r of filteredRemediated) remediatedByDate[r.date] = (remediatedByDate[r.date] || 0) + r.count;

  const max = Math.max(1, ...dates.map((d) => Math.max(intakeByDate[d] || 0, remediatedByDate[d] || 0)));

  return (
    <div className="flex items-end gap-1 h-24">
      {dates.map((d) => {
        const intake = intakeByDate[d] || 0;
        const remediated = remediatedByDate[d] || 0;
        return (
          <div
            key={d}
            title={`${new Date(d).toLocaleDateString()}: ${intake} new, ${remediated} remediated`}
            className="flex-1 flex flex-col justify-end gap-0.5 min-w-[4px]"
            style={{ height: 96 }}
          >
            <div className="w-full bg-amber-600" style={{ height: Math.round((intake / max) * 40) }} />
            <div className="w-full bg-green-700" style={{ height: Math.round((remediated / max) * 40) }} />
          </div>
        );
      })}
    </div>
  );
}

export default function RunZeroMetricsPanel({ apiKey }) {
  const [metrics, setMetrics] = useState({ intake_by_day: [], remediated_by_day: [], standing: [] });
  const [range, setRange] = useState({ window: '30d', from: null, to: null });
  const [orgFilter, setOrgFilter] = useState('all');
  const [loading, setLoading] = useState(true);

  const headers = { Authorization: `Bearer ${apiKey}` };

  const load = useCallback(() => {
    if (range.window === 'custom' && (!range.from || !range.to)) return;
    setLoading(true);
    const params = new URLSearchParams({ window: range.window });
    if (range.window === 'custom') {
      params.set('from', range.from);
      params.set('to', range.to);
    }
    fetch(`${API}/api/exposure/metrics?${params.toString()}`, { headers })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((d) => setMetrics({
        intake_by_day: d.intake_by_day || [],
        remediated_by_day: d.remediated_by_day || [],
        standing: d.standing || [],
      }))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [apiKey, range]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);

  const orgs = Array.from(new Set(metrics.standing.map((s) => s.org))).sort();
  const totals = metrics.standing.reduce(
    (acc, s) => {
      if (orgFilter !== 'all' && s.org !== orgFilter) return acc;
      acc.total_intake += s.total_intake;
      acc.still_standing += s.still_standing;
      acc.remediated += s.remediated;
      return acc;
    },
    { total_intake: 0, still_standing: 0, remediated: 0 },
  );

  return (
    <div className="p-4">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
        <div className="text-xs font-bold text-text-dim tracking-wider">
          ▸ TRACKED EXPOSURES
        </div>
        <TimeRangeToggle value={{ window: range.window }} onChange={setRange} />
      </div>
      <div className="text-[11px] text-text-dim mb-4">
        Tracks TI-correlated exposures under this app's own remediation workflow, not every raw
        CVE RunZero has ever seen on an asset. Counts below are scoped to items that first
        appeared within the selected window.
      </div>

      {orgs.length > 0 && (
        <div className="flex items-center gap-1 mb-3 flex-wrap">
          <label className="text-[11px] text-text-dim mr-1">Org:</label>
          <button
            onClick={() => setOrgFilter('all')}
            className={`text-xs px-2 py-1 rounded border ${orgFilter === 'all' ? 'bg-gray-700 border-gray-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'}`}
          >
            All orgs
          </button>
          {orgs.map((o) => (
            <button
              key={o}
              onClick={() => setOrgFilter(o)}
              className={`text-xs px-2 py-1 rounded border ${orgFilter === o ? 'bg-gray-700 border-gray-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white'}`}
            >
              {o || '(no org)'}
            </button>
          ))}
        </div>
      )}

      <div className="flex gap-6 text-xs text-gray-400 mb-4">
        <span>{totals.total_intake} tracked in window</span>
        <span className="text-amber-400">{totals.still_standing} still standing</span>
        <span className="text-green-400">{totals.remediated} remediated</span>
      </div>

      {loading ? (
        <div className="text-xs text-text-dim">Loading…</div>
      ) : (
        <LineChart intakeRows={metrics.intake_by_day} remediatedRows={metrics.remediated_by_day} org={orgFilter} />
      )}
      <div className="flex gap-4 mt-2 text-[10px] text-text-dim">
        <span><span className="inline-block w-2 h-2 bg-amber-600 mr-1" />New</span>
        <span><span className="inline-block w-2 h-2 bg-green-700 mr-1" />Remediated</span>
      </div>
    </div>
  );
}
