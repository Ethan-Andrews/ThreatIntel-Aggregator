'use client';
import { useState, useEffect, useCallback, useRef } from 'react';
import HuntsPanel from './HuntsPanel';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const POLL_INTERVAL_MS = 1500;

// Copied from TriagePanel.js's JobRow -- a bordered card with job id, status
// badge, and a percentage progress bar computed from completed/total. Not
// exported/shared from that file today, so the visual structure is
// duplicated here rather than introducing a new shared module for one caller.
function JobRow({ job }) {
  const pct = job.total > 0 ? Math.round((job.completed / job.total) * 100) : 0;
  return (
    <div className="border border-border rounded-sm p-2 mb-2">
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-text-dim font-mono">Job {job.job_id}</span>
        <span className={job.status === 'completed' ? 'text-green-400' : job.status === 'failed' ? 'text-red-400' : 'text-yellow-400'}>
          {job.status === 'running' ? 'Running' : job.status === 'completed' ? '✓ Completed' : '✗ Failed'}
        </span>
      </div>
      <div className="w-full bg-border rounded-sm h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-sm transition-all ${job.status === 'failed' ? 'bg-red-500' : 'bg-accent'}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-[10px] text-text-dim mt-1 text-right">
        {job.completed} / {job.total}
      </div>
    </div>
  );
}

const RESULT_STATUS_STYLES = {
  imported: 'bg-green-950 text-green-300 border-green-800',
  skipped: 'bg-surface text-text-dim border-border',
  error: 'bg-red-950 text-red-300 border-red-800',
};

function ResultStatusBadge({ status }) {
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border',
      RESULT_STATUS_STYLES[status] || RESULT_STATUS_STYLES.skipped,
    ].join(' ')}>
      {(status || 'unknown').toUpperCase()}
    </span>
  );
}

// static_gate_verdict/static_gate_durability are only ever populated for
// language === "kql" (local_import.py only runs static_gate.evaluate() on
// KQL content) -- every other recognized language, plus "unrecognized"/
// error rows, has both fields NULL by design, not because analysis failed.
// A blank cell there would read as "passed" (actively misleading), so a
// non-KQL row falls back to the row's own `detail` text instead, which the
// backend always populates with a specific reason for exactly this case.
function StaticGateCell({ result }) {
  if (result.language === 'kql' && result.static_gate_verdict) {
    const cls = result.static_gate_verdict === 'pass'
      ? 'bg-green-950 text-green-300 border-green-800'
      : result.static_gate_verdict === 'reject'
        ? 'bg-red-950 text-red-300 border-red-800'
        : 'bg-yellow-950 text-yellow-300 border-yellow-800';
    const pct = result.static_gate_durability != null
      ? ` (${Math.round(result.static_gate_durability * 100)}%)`
      : '';
    return (
      <span className={['inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-bold border', cls].join(' ')}>
        {result.static_gate_verdict.toUpperCase()}{pct}
      </span>
    );
  }
  return (
    <span className="text-[10px] text-text-dim italic">
      {result.detail || `static analysis not available for ${result.language || 'this file'}`}
    </span>
  );
}

// Surfaced at the top of a completed job's results, not buried in a
// per-row Detail column -- a failed or flagged file is easy to miss
// scrolling a long results table otherwise. `failed` (couldn't be
// imported at all) and `flagged` (imported, but static analysis marked
// it invalid/suspicious) are always shown as two separate counts: an
// "improper" KQL rule is NOT a failure, it's still a real catalog entry,
// and conflating the two would misrepresent what actually happened.
function ImportSummaryAlert({ job }) {
  const failedResults = (job.results || []).filter((r) => r.status === 'error');
  const flaggedResults = (job.results || []).filter(
    (r) => r.status === 'imported' && r.static_gate_verdict === 'reject',
  );
  if (failedResults.length === 0 && flaggedResults.length === 0) {
    return (
      <div className="border border-green-800 bg-green-950 text-green-300 rounded-sm px-3 py-2 text-xs mb-3">
        ✓ All {job.completed} file{job.completed === 1 ? '' : 's'} imported cleanly — nothing failed or was flagged.
      </div>
    );
  }
  return (
    <div className="space-y-2 mb-3">
      {failedResults.length > 0 && (
        <div className="border border-red-800 bg-red-950 text-red-300 rounded-sm px-3 py-2 text-xs">
          <div className="font-bold mb-1">
            ✗ {failedResults.length} file{failedResults.length === 1 ? '' : 's'} failed to import
          </div>
          <ul className="space-y-0.5 text-[11px] text-red-200">
            {failedResults.slice(0, 8).map((r, i) => (
              <li key={`${r.path}-${i}`}>
                <span className="font-mono">{r.path}</span>
                {r.detail ? <> — {r.detail}</> : null}
              </li>
            ))}
            {failedResults.length > 8 && (
              <li className="italic text-red-300/80">
                …and {failedResults.length - 8} more (see the table below).
              </li>
            )}
          </ul>
        </div>
      )}
      {flaggedResults.length > 0 && (
        <div className="border border-yellow-800 bg-yellow-950 text-yellow-300 rounded-sm px-3 py-2 text-xs">
          <div className="font-bold mb-1">
            ⚠ {flaggedResults.length} file{flaggedResults.length === 1 ? '' : 's'} imported but flagged invalid by static analysis
          </div>
          <div className="text-[11px] text-yellow-200 mb-1">
            These were still cataloged (browsable below and in Generated Hunts) so nothing silently
            disappears — review each one&rsquo;s reason before relying on it as a working detection.
          </div>
          <ul className="space-y-0.5 text-[11px] text-yellow-200">
            {flaggedResults.slice(0, 8).map((r, i) => (
              <li key={`${r.path}-${i}`}>
                <span className="font-mono">{r.path}</span>
                {r.detail ? <> — {r.detail}</> : null}
              </li>
            ))}
            {flaggedResults.length > 8 && (
              <li className="italic text-yellow-300/80">
                …and {flaggedResults.length - 8} more (see the table below).
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

function ResultsTable({ results }) {
  if (!results || results.length === 0) {
    return <div className="text-xs text-text-dim italic">No files were processed.</div>;
  }
  return (
    <div className="border border-border rounded-sm overflow-x-auto">
      <table className="w-full text-[11px]">
        <thead className="bg-surface text-text-dim">
          <tr>
            <th className="text-left px-2 py-1.5 font-bold">Path</th>
            <th className="text-left px-2 py-1.5 font-bold">Status</th>
            <th className="text-left px-2 py-1.5 font-bold">Language</th>
            <th className="text-left px-2 py-1.5 font-bold">Technique</th>
            <th className="text-left px-2 py-1.5 font-bold">Static gate</th>
            <th className="text-left px-2 py-1.5 font-bold">Detail</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r, i) => {
            const flagged = r.status === 'imported' && r.static_gate_verdict === 'reject';
            const rowCls = r.status === 'error'
              ? 'border-t border-border bg-red-950/30'
              : flagged
                ? 'border-t border-border bg-yellow-950/20'
                : 'border-t border-border';
            return (
            <tr key={`${r.path}-${i}`} className={rowCls}>
              <td className="px-2 py-1.5 text-text font-mono whitespace-nowrap">{r.path}</td>
              <td className="px-2 py-1.5"><ResultStatusBadge status={r.status} /></td>
              <td className="px-2 py-1.5 text-text-dim">{r.language || '—'}</td>
              <td className="px-2 py-1.5 text-text-dim font-mono">{r.technique_id || '—'}</td>
              <td className="px-2 py-1.5"><StaticGateCell result={r} /></td>
              <td className="px-2 py-1.5 text-text-dim max-w-xs truncate" title={r.detail || ''}>
                {r.detail || '—'}
              </td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Collapsible reference for the two metadata mechanisms an import folder
// can use: a same-folder sidecar JSON/YAML file (paired to its content
// file by an explicit `file` field, not by matching filename stems), and
// Microsoft's own native-exported Analytics Rule JSON (self-contained,
// no sidecar needed). Shown once, not per-tab-visit noise -- collapsed
// by default via <details>, matching this app's existing disclosure
// pattern (see Section's defaultOpen usage elsewhere) without needing a
// second stateful open/close mechanism just for this.
function ImportFormatReference() {
  return (
    <details className="mb-3 text-[11px] text-text-dim border border-border rounded-sm">
      <summary className="cursor-pointer px-3 py-2 font-bold text-text-dim hover:text-text select-none">
        ▸ Supported formats &amp; sidecar template
      </summary>
      <div className="px-3 pb-3 space-y-3">
        <div>
          <div className="font-bold text-text mb-1">Recognized file formats</div>
          <ul className="list-disc list-inside space-y-0.5">
            <li><span className="font-mono">.kql</span> or any extension containing plain KQL — fully validated (static gate, MITRE tagging)</li>
            <li><span className="font-mono">.yar</span> / <span className="font-mono">.yara</span> — YARA rules</li>
            <li><span className="font-mono">.rules</span> or similar — Suricata rules</li>
            <li><span className="font-mono">.yml</span> / <span className="font-mono">.yaml</span> — Sigma rules (detected by a real <span className="font-mono">logsource</span>/<span className="font-mono">detection</span> shape)</li>
            <li><span className="font-mono">.spl</span> or any extension containing Splunk SPL</li>
            <li><span className="font-mono">.json</span> — Microsoft&rsquo;s native exported Analytics Rule/Hunting Query JSON (self-contained, only <span className="font-mono">Scheduled</span>-kind rules carry an evaluable query)</li>
          </ul>
          <p className="mt-1">
            Every recognized non-KQL format is still cataloged with a language badge — static analysis
            (durability score, pass/reject) only runs for KQL. Anything that can&rsquo;t be confidently
            classified as any of the above is rejected for that file specifically, with a clear reason,
            rather than guessed at.
          </p>
        </div>
        <div>
          <div className="font-bold text-text mb-1">Optional sidecar (title/description/technique)</div>
          <p className="mb-1">
            Pair a plain rule file with a same-folder <span className="font-mono">.json</span> or{' '}
            <span className="font-mono">.yaml</span> file that names it explicitly via <span className="font-mono">file</span>:
          </p>
          <pre className="bg-background border border-border rounded-sm p-2 overflow-x-auto text-text font-mono text-[10px]">
{`{
  "file": "my_rule.kql",
  "title": "Suspicious PowerShell EncodedCommand",
  "description": "Flags base64-encoded PowerShell payloads",
  "technique_id": "T1059.001"
}`}
          </pre>
          <p className="mt-1">
            All four fields are optional except <span className="font-mono">file</span> — a rule with no
            sidecar imports fine using its filename as the title and no declared technique. Unexpected
            extra fields cause the whole sidecar to be ignored (the rule file it would have described
            still imports on its own, just without that metadata) rather than silently accepted.
          </p>
        </div>
      </div>
    </details>
  );
}

function ImportTrigger({ authFetch, onImportSettled }) {
  const [status, setStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState(null);

  const [subPath, setSubPath] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  const [job, setJob] = useState(null);
  const [recentJobs, setRecentJobs] = useState([]);

  const pollTimeout = useRef(null);

  const fetchStatus = useCallback(() => {
    setStatusLoading(true);
    setStatusError(null);
    authFetch(`${API}/api/detections/local-import/status`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setStatus)
      .catch(() => setStatusError('Failed to load import status.'))
      .finally(() => setStatusLoading(false));
  }, [authFetch]);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);

  const fetchRecentJobs = useCallback(() => {
    authFetch(`${API}/api/detections/local-import/jobs`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((d) => setRecentJobs(d.jobs || []))
      .catch(() => {});
  }, [authFetch]);

  useEffect(() => { fetchRecentJobs(); }, [fetchRecentJobs]);

  // Poll every 1.5s while the job is running; stop (no further timeout
  // scheduled) once it reaches a terminal status, matching how
  // SettingsPanel.js polls retriage/reextract jobs.
  const pollJob = useCallback((jobId) => {
    authFetch(`${API}/api/detections/local-import/jobs/${jobId}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setJob(data);
        if (data.status === 'running') {
          pollTimeout.current = setTimeout(() => pollJob(jobId), POLL_INTERVAL_MS);
        } else {
          fetchRecentJobs();
          // Newly-imported files become hunts in the LOCAL DETECTIONS list
          // rendered below this component (see LocalDetectionsPanel) -- that
          // list is a separate HuntsPanel instance that only fetches once on
          // mount, so without this it stays stuck showing whatever existed
          // before this import ran until the admin navigates away and back.
          if (onImportSettled) onImportSettled();
        }
      })
      .catch(() => {
        // Transient failure reading job status -- stop polling silently;
        // the last known state stays on screen and the user can re-import.
      });
  }, [authFetch, fetchRecentJobs, onImportSettled]);

  useEffect(() => () => {
    if (pollTimeout.current) clearTimeout(pollTimeout.current);
  }, []);

  function handleImport(e) {
    e.preventDefault();
    if (submitting || (job && job.status === 'running')) return;
    setSubmitting(true);
    setSubmitError(null);
    authFetch(`${API}/api/detections/local-import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sub_path: subPath.trim() }),
    })
      .then(async (r) => {
        if (!r.ok) {
          const body = await r.json().catch(() => ({}));
          throw new Error(body.detail || 'Import failed to start.');
        }
        return r.json();
      })
      .then((data) => {
        setJob({ job_id: data.job_id, status: 'running', total: 0, completed: 0, failed: 0, results: [] });
        pollJob(data.job_id);
      })
      .catch((err) => setSubmitError(err.message || 'Import failed to start.'))
      .finally(() => setSubmitting(false));
  }

  const recentOthers = recentJobs.filter((j) => !job || j.job_id !== job.job_id).slice(0, 5);
  const jobRunning = job && job.status === 'running';

  return (
    <div className="border border-border rounded-sm bg-surface p-4 mb-6">
      <div className="text-xs font-bold text-text-dim tracking-wider mb-2">▸ IMPORT FROM LOCAL FOLDER</div>
      <div className="text-[11px] text-text-dim mb-3">
        Point this app at a folder of your own detection rule files (KQL, YARA, Suricata, Sigma,
        Splunk SPL, or Microsoft&rsquo;s native exported Analytics Rule JSON) to catalog, MITRE-tag,
        and statically validate them — no Sentinel connection or AI provider required.
      </div>

      <ImportFormatReference />

      {statusLoading && <div className="text-xs text-text-dim">Checking configuration…</div>}

      {!statusLoading && statusError && (
        <div className="text-xs text-red-400">{statusError}</div>
      )}

      {!statusLoading && !statusError && status && status.configured === false && (
        <div>
          <div className="text-xs font-bold text-yellow-400 mb-1">Not configured</div>
          <div className="text-[11px] text-text-dim mb-1">{status.detail}</div>
          <div className="text-[10px] text-text-dim">
            An admin needs to set the <code className="font-mono text-text">LOCAL_IMPORT_DIR</code> environment
            variable on the backend to a directory containing your detection rule files, then restart the API.
          </div>
        </div>
      )}

      {!statusLoading && !statusError && status && status.configured && (
        <>
          <div className="text-[10px] text-text-dim mb-3">
            Configured root: <span className="font-mono text-text">{status.root}</span>
          </div>
          <form onSubmit={handleImport} className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1 text-[10px] text-text-dim">
              Sub-path (optional)
              <input
                type="text"
                value={subPath}
                onChange={(e) => setSubPath(e.target.value)}
                placeholder="e.g. team-a/kql"
                className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text w-56"
              />
            </label>
            <button
              type="submit"
              disabled={submitting || jobRunning}
              className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {submitting ? 'Starting…' : jobRunning ? 'Import running…' : 'Import'}
            </button>
          </form>
          <div className="text-[10px] text-text-dim mt-1">
            Scoped under the configured root above, not a free-form filesystem path — leave blank to import
            everything under the root.
          </div>
          {submitError && <div className="text-xs text-red-400 mt-2">{submitError}</div>}
        </>
      )}

      {job && (
        <div className="mt-4">
          <JobRow job={job} />
          {job.status !== 'running' && (
            <div className="mt-3">
              <div className="text-[10px] font-bold text-text-dim tracking-wider mb-2">
                ▸ RESULTS ({(job.results || []).length})
              </div>
              <ImportSummaryAlert job={job} />
              <ResultsTable results={job.results} />
            </div>
          )}
        </div>
      )}

      {recentOthers.length > 0 && (
        <div className="mt-4">
          <div className="text-[10px] font-bold text-text-dim tracking-wider mb-2">▸ RECENT IMPORTS</div>
          {recentOthers.map((j) => <JobRow key={j.job_id} job={j} />)}
        </div>
      )}
    </div>
  );
}

const LOCAL_DETECTIONS_DESCRIPTION = (
  <>
    Hunts created from files imported via Local Detections Import above, one hunt per imported file —
    click a hunt to see its detection. These follow the same review workflow (static gate, MITRE tagging,
    Sentinel deploy) as AI-generated hunts, minus Sentinel-dependent checks (backtest, disposition) since
    there&rsquo;s no live Sentinel workspace behind a local import.
  </>
);

export default function LocalDetectionsPanel({ authFetch, userRole }) {
  const isAdmin = userRole === 'admin';
  // Bumped whenever an import job reaches a terminal state, and passed to
  // HuntsPanel as `key` -- HuntsPanel only fetches once on mount (see its
  // own load() useCallback), so without forcing a remount here, newly-
  // imported hunts wouldn't show up below until the admin left this tab
  // and came back.
  const [refreshNonce, setRefreshNonce] = useState(0);

  return (
    <div className="p-4 overflow-y-auto">
      {isAdmin && (
        <ImportTrigger authFetch={authFetch} onImportSettled={() => setRefreshNonce((n) => n + 1)} />
      )}

      <HuntsPanel
        key={refreshNonce}
        authFetch={authFetch}
        userRole={userRole}
        originFilter="local_import"
        title="LOCAL DETECTIONS"
        description={LOCAL_DETECTIONS_DESCRIPTION}
      />
    </div>
  );
}
