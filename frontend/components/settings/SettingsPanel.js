import { useState, useEffect, useCallback } from "react";
import * as AlertDialog from "@radix-ui/react-alert-dialog";
import CadencePicker from "./CadencePicker";
import SeverityCards from "./SeverityCards";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function currentToken(fallback) {
  if (typeof window === "undefined") return fallback || "";
  return sessionStorage.getItem("ti_app_token") || fallback || "";
}

function authHeader() {
  return {
    Authorization: "Bearer " + sessionStorage.getItem("ti_app_token"),
    "Content-Type": "application/json",
  };
}

function Section({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-sm mb-4">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 w-full px-4 py-3 text-left text-xs font-bold text-text-dim tracking-wider hover:text-text"
      >
        <span>{open ? "▾" : "▸"}</span>
        {title}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

export default function SettingsPanel({ apiKey, sources, userRole }) {
  const [archiveStats, setArchiveStats]   = useState(null);
  const [dashStats,    setDashStats]      = useState(null);
  const [feedHealth,   setFeedHealth]     = useState(null);
  const [archiveDays,  setArchiveDays]    = useState(90);
  const [purgeInput,   setPurgeInput]     = useState("");
  const [actionState,  setActionState]    = useState({});
  const [triageJob,     setTriageJob]     = useState(null);
  const [reextractJob,  setReextractJob]  = useState(null);
  const [users,       setUsers]       = useState([]);
  const [roleLoading, setRoleLoading] = useState({});
  const [orchestratorSettings, setOrchestratorSettings] = useState(null);
  const [orchestratorToggling, setOrchestratorToggling] = useState(false);
  const [orchestratorError, setOrchestratorError] = useState(false);
  const [scheduleForm, setScheduleForm] = useState(null);
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [scheduleError, setScheduleError] = useState(false);
  const [huntSyncSettings, setHuntSyncSettings] = useState(null);
  const [huntSyncSaving, setHuntSyncSaving] = useState(false);
  const [huntSyncError, setHuntSyncError] = useState(false);
  const [huntScheduleSaving, setHuntScheduleSaving] = useState(false);
  const [huntScheduleError, setHuntScheduleError] = useState(false);
  const [sentinelTargets, setSentinelTargets] = useState(null);
  const [autoDeployTargetSaving, setAutoDeployTargetSaving] = useState(false);
  const [autoDeployTargetError, setAutoDeployTargetError] = useState(false);
  const [retryingFeeds, setRetryingFeeds] = useState({});
  const [retryErrors, setRetryErrors] = useState({});
  const [localImportStatus, setLocalImportStatus] = useState(null);
  const [localImportError, setLocalImportError] = useState(false);

  const fetchStats = useCallback(() => {
    const token = currentToken(apiKey);
    if (!token) return;
    fetch(`${API}/api/archive/stats`,    { headers: { Authorization: "Bearer " + token } })
      .then((r) => r.json()).then(setArchiveStats).catch(() => {});
    fetch(`${API}/api/dashboard/stats`,  { headers: { Authorization: "Bearer " + token } })
      .then((r) => r.json()).then(setDashStats).catch(() => {});
    fetch(`${API}/api/feeds/health`,     { headers: { Authorization: "Bearer " + token } })
      .then((r) => r.json()).then((d) => setFeedHealth(d.feeds || [])).catch(() => {});
  }, [apiKey]);

  useEffect(() => { fetchStats(); }, [fetchStats]);

  // Read-only status check -- GET .../local-import/status is require_auth
  // (not require_admin), so every signed-in role can see whether an admin
  // has configured LOCAL_IMPORT_DIR. The actual import trigger lives only
  // in Detections -> Local Detections (LocalDetectionsPanel.js), per the
  // "don't duplicate the full import UI here" direction.
  const fetchLocalImportStatus = useCallback(() => {
    const token = currentToken(apiKey);
    if (!token) return;
    fetch(`${API}/api/detections/local-import/status`, { headers: { Authorization: "Bearer " + token } })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setLocalImportStatus)
      .catch(() => setLocalImportError(true));
  }, [apiKey]);

  useEffect(() => { fetchLocalImportStatus(); }, [fetchLocalImportStatus]);

  const fetchUsers = useCallback(() => {
    if (userRole !== "admin") return;
    fetch(`${API}/api/users`, { headers: authHeader() })
      .then((r) => r.json())
      .then((d) => setUsers(d.users || []))
      .catch(() => {});
  }, [userRole]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const fetchOrchestratorSettings = useCallback(() => {
    if (userRole !== "admin") return;
    fetch(`${API}/api/settings/orchestrator`, { headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setOrchestratorSettings)
      .catch(() => setOrchestratorError(true));
  }, [userRole]);

  useEffect(() => { fetchOrchestratorSettings(); }, [fetchOrchestratorSettings]);

  const INTERVAL_PRESETS = [30, 60, 120, 240, 1440];
  const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]; // 0=Sunday, matches Postgres's date_part('dow', ...)

  function minutesToTimeInput(min) {
    const h = Math.floor(min / 60).toString().padStart(2, "0");
    const m = (min % 60).toString().padStart(2, "0");
    return `${h}:${m}`;
  }
  function timeInputToMinutes(t) {
    const [h, m] = t.split(":").map(Number);
    return h * 60 + m;
  }

  // Seed the (locally-edited) schedule form from the loaded settings once,
  // the first time they arrive. A later successful save already reflects
  // what the form held at submit time, so this deliberately doesn't
  // re-seed on every orchestratorSettings change -- only the initial load.
  useEffect(() => {
    if (!orchestratorSettings || scheduleForm) return;
    const interval = orchestratorSettings.interval_minutes ?? 30;
    setScheduleForm({
      intervalPreset: INTERVAL_PRESETS.includes(interval) ? interval : "custom",
      customMinutes: INTERVAL_PRESETS.includes(interval) ? "" : String(interval),
      windowEnabled: orchestratorSettings.window_start_minute != null,
      windowStart: minutesToTimeInput(orchestratorSettings.window_start_minute ?? 9 * 60),
      windowEnd: minutesToTimeInput(orchestratorSettings.window_end_minute ?? 17 * 60),
      days: orchestratorSettings.days_of_week && orchestratorSettings.days_of_week.length > 0
        ? orchestratorSettings.days_of_week
        : [0, 1, 2, 3, 4, 5, 6],
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orchestratorSettings]);

  function toggleScheduleDay(day) {
    setScheduleForm((prev) => ({
      ...prev,
      days: prev.days.includes(day)
        ? prev.days.filter((d) => d !== day)
        : [...prev.days, day].sort((a, b) => a - b),
    }));
  }

  function handleSaveSchedule() {
    if (!scheduleForm) return;
    const interval = scheduleForm.intervalPreset === "custom"
      ? parseInt(scheduleForm.customMinutes, 10)
      : scheduleForm.intervalPreset;
    if (!interval || interval <= 0) {
      setScheduleError(true);
      return;
    }
    setScheduleSaving(true);
    setScheduleError(false);
    fetch(`${API}/api/settings/orchestrator/schedule`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({
        interval_minutes: interval,
        window_start_minute: scheduleForm.windowEnabled ? timeInputToMinutes(scheduleForm.windowStart) : null,
        window_end_minute: scheduleForm.windowEnabled ? timeInputToMinutes(scheduleForm.windowEnd) : null,
        // A full 7-day selection means "no restriction" -- send null rather
        // than an explicit all-days array, matching the backend's own
        // "empty/null means every day" convention.
        days_of_week: scheduleForm.days.length === 7 ? null : scheduleForm.days,
      }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setOrchestratorSettings)
      .catch(() => setScheduleError(true))
      .finally(() => setScheduleSaving(false));
  }

  const fetchHuntSyncSettings = useCallback(() => {
    if (userRole !== "admin") return;
    fetch(`${API}/api/settings/hunt-sync`, { headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setHuntSyncError(true));
  }, [userRole]);

  useEffect(() => { fetchHuntSyncSettings(); }, [fetchHuntSyncSettings]);

  // Same picker data HuntsPanel.js's per-hunt DeployTargetPicker already
  // fetches -- only needed once the auto-deploy-target control is
  // actually visible (mode === "auto"), not on every Settings page load.
  useEffect(() => {
    if (userRole !== "admin" || huntSyncSettings?.mode !== "auto") return;
    fetch(`${API}/api/detections/hunts/sentinel-targets`, { headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setSentinelTargets)
      .catch(() => setSentinelTargets({ enabled: false, hunts: [], error: "Failed to load Sentinel hunts." }));
  }, [userRole, huntSyncSettings?.mode]);

  function handleSetHuntSyncMode(mode) {
    if (!huntSyncSettings) return;
    setHuntSyncSaving(true);
    setHuntSyncError(false);
    fetch(`${API}/api/settings/hunt-sync`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({ mode, require_alignment: huntSyncSettings.require_alignment }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setHuntSyncError(true))
      .finally(() => setHuntSyncSaving(false));
  }

  function handleToggleRequireAlignment() {
    if (!huntSyncSettings) return;
    setHuntSyncSaving(true);
    setHuntSyncError(false);
    fetch(`${API}/api/settings/hunt-sync`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({
        mode: huntSyncSettings.mode,
        require_alignment: !huntSyncSettings.require_alignment,
      }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setHuntSyncError(true))
      .finally(() => setHuntSyncSaving(false));
  }

  function handleSaveHuntSeverities(severities) {
    if (!huntSyncSettings) return;
    setHuntScheduleSaving(true);
    setHuntScheduleError(false);
    fetch(`${API}/api/settings/hunt-sync/schedule`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({
        severities,
        interval_minutes: huntSyncSettings.interval_minutes ?? 30,
        window_start_minute: huntSyncSettings.window_start_minute ?? null,
        window_end_minute: huntSyncSettings.window_end_minute ?? null,
        days_of_week: huntSyncSettings.days_of_week ?? null,
      }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setHuntScheduleError(true))
      .finally(() => setHuntScheduleSaving(false));
  }

  function handleSaveHuntSchedule(payload) {
    if (!payload) {
      setHuntScheduleError(true);
      return;
    }
    setHuntScheduleSaving(true);
    setHuntScheduleError(false);
    fetch(`${API}/api/settings/hunt-sync/schedule`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({ ...payload, severities: huntSyncSettings?.severities ?? null }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setHuntScheduleError(true))
      .finally(() => setHuntScheduleSaving(false));
  }

  function handleSaveAutoDeployTarget(targetSentinelHuntId) {
    setAutoDeployTargetSaving(true);
    setAutoDeployTargetError(false);
    fetch(`${API}/api/settings/hunt-sync/auto-deploy-target`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({ target_sentinel_hunt_id: targetSentinelHuntId || null }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setHuntSyncSettings)
      .catch(() => setAutoDeployTargetError(true))
      .finally(() => setAutoDeployTargetSaving(false));
  }

  function handleToggleOrchestrator() {
    if (!orchestratorSettings) return;
    const nextEnabled = !orchestratorSettings.enabled;
    setOrchestratorToggling(true);
    setOrchestratorError(false);
    fetch(`${API}/api/settings/orchestrator`, {
      method: "PATCH",
      headers: authHeader(),
      body: JSON.stringify({ enabled: nextEnabled }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setOrchestratorSettings)
      .catch(() => setOrchestratorError(true))
      .finally(() => setOrchestratorToggling(false));
  }

  // Poll active triage job
  useEffect(() => {
    if (!triageJob || triageJob.status === "completed" || triageJob.status === "failed") return;
    const token = currentToken(apiKey);
    if (!token) return;
    const iv = setInterval(() => {
      fetch(`${API}/api/retriage/jobs/${triageJob.job_id}`, { headers: { Authorization: "Bearer " + token } })
        .then((r) => r.json())
        .then((j) => {
          setTriageJob(j);
          if (j.status === "completed" || j.status === "failed") {
            fetchStats();
          }
        })
        .catch(() => {});
    }, 2000);
    return () => clearInterval(iv);
  }, [triageJob, apiKey, fetchStats]);

  // Poll active reextract job
  useEffect(() => {
    if (!reextractJob || reextractJob.status === "completed" || reextractJob.status === "failed") return;
    const token = currentToken(apiKey);
    if (!token) return;
    const iv = setInterval(() => {
      fetch(`${API}/api/retriage/jobs/${reextractJob.job_id}`, {
        headers: { Authorization: "Bearer " + token },
      })
        .then((r) => r.json())
        .then((j) => {
          setReextractJob(j);
          if (j.status === "completed" || j.status === "failed") {
            fetchStats();
          }
        })
        .catch(() => {});
    }, 2000);
    return () => clearInterval(iv);
  }, [reextractJob, apiKey, fetchStats]);

  function setAction(key, state) {
    setActionState((prev) => ({ ...prev, [key]: state }));
  }

  function handleRetriaigeFailed() {
    fetch(`${API}/api/retriage/failed`, { method: "POST", headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((j) => { if (j.job_id) setTriageJob({ job_id: j.job_id, status: "running", total: j.count, completed: 0, failed: 0 }); })
      .catch(() => {});
  }

  function handleReextractIocs() {
    fetch(`${API}/api/iocs/reextract`, { method: "POST", headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((j) => {
        if (j.job_id) {
          setReextractJob({ job_id: j.job_id, status: "running", total: 0, completed: 0, failed: 0 });
        }
      })
      .catch(() => {});
  }

  function handleArchive() {
    setAction("archive", "running");
    fetch(`${API}/api/archive/run`, {
      method: "POST",
      headers: authHeader(),
      body: JSON.stringify({ days: archiveDays }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => { setAction("archive", "done"); fetchStats(); })
      .catch(() => setAction("archive", "error"));
  }

  function handlePurge() {
    setAction("purge", "running");
    fetch(`${API}/api/archive/purge`, { method: "POST", headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => { setAction("purge", "done"); setPurgeInput(""); fetchStats(); })
      .catch(() => setAction("purge", "error"));
  }

  function handleRetryFeed(feedName) {
    setRetryingFeeds((prev) => ({ ...prev, [feedName]: true }));
    setRetryErrors((prev) => ({ ...prev, [feedName]: null }));
    fetch(`${API}/api/feeds/${encodeURIComponent(feedName)}/retry`, {
      method: "POST",
      headers: authHeader(),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((result) => {
        if (!result.success) {
          setRetryErrors((prev) => ({ ...prev, [feedName]: result.error || "Retry failed" }));
        }
        fetchStats();
      })
      .catch(() => setRetryErrors((prev) => ({ ...prev, [feedName]: "Retry request failed" })))
      .finally(() => setRetryingFeeds((prev) => ({ ...prev, [feedName]: false })));
  }

  function handleDedup() {
    setAction("dedup", "running");
    fetch(`${API}/api/archive/dedup`, { method: "POST", headers: authHeader() })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(() => setAction("dedup", "done"))
      .catch(() => setAction("dedup", "error"));
  }

  return (
    <div className="p-4">
      <div className="flex gap-6 items-start">
        <div className="flex-1 min-w-0">

      <Section title="AI TRIAGE">
        <div className="space-y-3">
          <div className="flex items-center gap-4">
            <div className="text-xs text-text-dim">
              Total entries: <span className="text-text font-mono">{dashStats?.total ?? "—"}</span>
            </div>
            <div className="text-xs text-text-dim">
              Triaged: <span className="text-accent font-mono">{dashStats?.triaged ?? "—"}</span>
            </div>
            <div className="text-xs text-text-dim">
              Failed / Unknown: <span className="text-yellow-400 font-mono">{dashStats?.needs_retriage ?? "—"}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRetriaigeFailed}
              disabled={!dashStats?.needs_retriage || triageJob?.status === "running"}
              className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {triageJob?.status === "running" ? `Triaging… ${triageJob.completed}/${triageJob.total}` : `Retriage ${dashStats?.needs_retriage ?? 0} failed entries`}
            </button>
            {triageJob?.status === "completed" && (
              <span className="text-xs text-accent">✓ Done — {triageJob.completed} processed, {triageJob.failed} failed</span>
            )}
            {triageJob?.status === "failed" && (
              <span className="text-xs text-red-400">✗ Job failed</span>
            )}
          </div>
          <p className="text-[10px] text-text-dim">
            Re-runs AI triage on all entries marked Unknown with no TTP mappings (previously failed due to API issues).
          </p>

          {userRole === "admin" && (
            <div className="mt-3 border-t border-border pt-3 space-y-2">
              <div className="flex items-center gap-3">
                <button
                  onClick={handleReextractIocs}
                  disabled={reextractJob?.status === "running"}
                  className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {reextractJob?.status === "running"
                    ? `Re-extracting… ${reextractJob.completed}/${reextractJob.total}`
                    : "Re-extract IOCs"}
                </button>
                {reextractJob?.status === "completed" && (
                  <span className="text-xs text-accent">
                    ✓ Complete — {reextractJob.completed} entries processed
                  </span>
                )}
                {reextractJob?.status === "failed" && (
                  <span className="text-xs text-red-400">✗ Re-extraction failed</span>
                )}
              </div>
              <p className="text-[10px] text-text-dim">
                Re-runs ioc-finder on all triaged entries to fill in missing domains, URLs, and hashes. No AI calls.
              </p>
            </div>
          )}
        </div>
      </Section>

      <Section title="DATA MANAGEMENT">
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <span className="text-text-dim w-40">Archive entries older than</span>
            <input
              type="number" min={1} max={3650} value={archiveDays}
              onChange={(e) => setArchiveDays(Number(e.target.value))}
              className="w-20 bg-background border border-border rounded-sm px-2 py-1 text-xs text-text focus:outline-hidden focus:border-accent"
            />
            <span className="text-text-dim">days</span>
            <AlertDialog.Root>
              <AlertDialog.Trigger asChild>
                <button className="text-xs border border-border rounded-sm px-3 py-1 hover:border-accent hover:text-accent transition-colors">
                  Archive
                </button>
              </AlertDialog.Trigger>
              <AlertDialog.Portal>
                <AlertDialog.Overlay className="fixed inset-0 bg-black/50 z-50" />
                <AlertDialog.Content className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-surface border border-border rounded-sm p-6 z-50 max-w-sm w-full">
                  <AlertDialog.Title className="text-sm font-bold text-text mb-2">Archive entries?</AlertDialog.Title>
                  <AlertDialog.Description className="text-xs text-text-dim mb-4">
                    This will archive entries older than {archiveDays} days. They will no longer appear in the feed.
                  </AlertDialog.Description>
                  <div className="flex gap-2 justify-end">
                    <AlertDialog.Cancel className="text-xs border border-border rounded-sm px-3 py-1 hover:text-text text-text-dim">Cancel</AlertDialog.Cancel>
                    <AlertDialog.Action onClick={handleArchive} className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors">
                      {actionState.archive === "running" ? "Archiving…" : "Confirm"}
                    </AlertDialog.Action>
                  </div>
                </AlertDialog.Content>
              </AlertDialog.Portal>
            </AlertDialog.Root>
          </div>

          {archiveStats && (
            <div className="text-[10px] text-text-dim">
              Archived: {archiveStats.archived_count ?? 0} entries · Last run: {archiveStats.last_run ?? "never"}
            </div>
          )}

          <div className="flex items-center gap-3">
            <span className="text-text-dim w-40">Purge archived entries</span>
            <input
              type="text" placeholder="Type PURGE to confirm"
              value={purgeInput} onChange={(e) => setPurgeInput(e.target.value)}
              className="bg-background border border-border rounded-sm px-2 py-1 text-xs text-text focus:outline-hidden focus:border-accent"
            />
            <button
              disabled={purgeInput !== "PURGE"}
              onClick={handlePurge}
              className="text-xs border border-red-700 text-red-500 rounded-sm px-3 py-1 hover:bg-red-900 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              {actionState.purge === "running" ? "Purging…" : "Purge"}
            </button>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-text-dim w-40">Deduplicate CVEs</span>
            <button
              onClick={handleDedup}
              disabled={actionState.dedup === "running"}
              className="text-xs border border-border rounded-sm px-3 py-1 hover:border-accent hover:text-accent transition-colors disabled:opacity-50"
            >
              {actionState.dedup === "running" ? "Running…" : actionState.dedup === "done" ? "✓ Done" : "Run Dedup"}
            </button>
          </div>
        </div>
      </Section>

      <Section title="FEED HEALTH" defaultOpen={false}>
        {!feedHealth ? (
          <div className="text-xs text-text-dim">Loading…</div>
        ) : feedHealth.length === 0 ? (
          <div className="text-xs text-text-dim">No feed data yet.</div>
        ) : (
          <div className="space-y-1">
            {feedHealth.map((f) => {
              const dotClass = !f.last_polled
                ? 'bg-gray-500'
                : f.consecutive_failures > 0
                  ? 'bg-red-500'
                  : 'bg-green-500';
              const statusText = !f.last_polled
                ? '— never polled'
                : f.consecutive_failures > 0
                  ? `✗ FAILING ×${f.consecutive_failures}`
                  : `✓ ${new Date(f.last_polled).toLocaleString()}`;
              const statusClass = !f.last_polled
                ? 'text-gray-500'
                : f.consecutive_failures > 0
                  ? 'text-red-400'
                  : 'text-green-400';
              const isFailing = f.consecutive_failures > 0;
              const isRetrying = !!retryingFeeds[f.name];
              const retryError = retryErrors[f.name];
              return (
                <div key={f.name} className="py-0.5">
                  <div className="flex items-center gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${dotClass}`} />
                    <span className="text-text w-44 truncate" title={f.name}>{f.name}</span>
                    <span className="text-gray-500 shrink-0">[T{f.tier}]</span>
                    <span className={`flex-1 ${statusClass}`}>{statusText}</span>
                    <span className="text-gray-400 shrink-0">{f.items_last_7d}/7d</span>
                    <span className="text-gray-500 shrink-0">{f.total_active} active</span>
                    {userRole === "admin" && isFailing && (
                      <button
                        onClick={() => handleRetryFeed(f.name)}
                        disabled={isRetrying}
                        className="text-[10px] border border-accent text-accent rounded px-2 py-0.5 hover:bg-accent hover:text-background transition-colors disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
                      >
                        {isRetrying ? "Retrying…" : "Retry"}
                      </button>
                    )}
                  </div>
                  {isFailing && f.last_error && (
                    <div className="text-[10px] text-red-400/80 pl-4 truncate" title={f.last_error}>
                      {f.last_error}
                    </div>
                  )}
                  {retryError && (
                    <div className="text-[10px] text-red-400 pl-4">
                      Retry failed: {retryError}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Section>

      <Section title="LOCAL DETECTIONS IMPORT" defaultOpen={false}>
        {localImportError && !localImportStatus && (
          <div className="text-xs text-red-400">Failed to load local import status.</div>
        )}
        {!localImportError && !localImportStatus && (
          <div className="text-xs text-text-dim">Loading…</div>
        )}
        {localImportStatus && localImportStatus.configured === false && (
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs">
              <span className="w-2 h-2 rounded-full shrink-0 bg-red-500" />
              <span className="text-red-400">Not configured</span>
            </div>
            <p className="text-[10px] text-text-dim">{localImportStatus.detail}</p>
            <p className="text-[10px] text-text-dim leading-relaxed">
              An admin needs to set the <code className="font-mono">LOCAL_IMPORT_DIR</code> environment
              variable on the backend to a directory containing detection rule files (KQL, YARA, Suricata,
              Sigma, Splunk SPL, or a native exported Analytics Rule JSON), then restart the API.
            </p>
          </div>
        )}
        {localImportStatus && localImportStatus.configured && (
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs">
              <span className="w-2 h-2 rounded-full shrink-0 bg-green-500" />
              <span className="text-green-400">Configured</span>
            </div>
            <div className="text-[10px] text-text-dim">
              Root: <span className="text-text font-mono">{localImportStatus.root}</span>
            </div>
          </div>
        )}
        <p className="text-[10px] text-text-dim mt-2">
          Run an import from the Detections → Local Detections tab.
        </p>
      </Section>

      {userRole === "admin" && (
        <Section title="USERS">
          {users.length === 0 ? (
            <div className="text-xs text-text-dim">No users found.</div>
          ) : (
            <div className="space-y-2">
              {users.map((u) => (
                <div key={u.entra_oid} className="flex items-center justify-between text-xs">
                  <div>
                    <span className="text-text font-medium">{u.display_name}</span>
                    <span className="text-text-dim ml-2">{u.email}</span>
                  </div>
                  <select
                    value={u.role}
                    disabled={!!roleLoading[u.entra_oid]}
                    onChange={(e) => {
                      const newRole = e.target.value;
                      setRoleLoading((prev) => ({ ...prev, [u.entra_oid]: true }));
                      fetch(`${API}/api/users/${u.entra_oid}/role`, {
                        method:  "PATCH",
                        headers: authHeader(),
                        body:    JSON.stringify({ role: newRole }),
                      })
                        .then((r) => {
                          if (!r.ok) throw new Error("Failed");
                          return r.json();
                        })
                        .then(() => {
                          setUsers((prev) =>
                            prev.map((user) =>
                              user.entra_oid === u.entra_oid ? { ...user, role: newRole } : user
                            )
                          );
                        })
                        .catch(() => {})
                        .finally(() =>
                          setRoleLoading((prev) => ({ ...prev, [u.entra_oid]: false }))
                        );
                    }}
                    className="text-xs bg-surface border border-border rounded-sm px-1 py-0.5"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {userRole === "admin" && (
        <Section title="API SETTINGS">
          <div className="space-y-3">
            <div className="text-xs font-bold text-text-dim tracking-wider">
              DETECTIONS.AI ORCHESTRATOR
            </div>
            <div className="text-xs text-text-dim">
              Coming soon — detections.ai has a public API in development,
              and this integration will support it once it's available. It
              isn't part of this public release yet. The controls
              below are previewed here but won't do anything without a
              configured deployment. See the README's Local Detections Import
              section for a fully-supported way to get detections cataloged
              today.
            </div>

            {orchestratorError && !orchestratorSettings && (
              <div className="text-xs text-red-400">Failed to load orchestrator settings.</div>
            )}

            {orchestratorSettings && (
              <>
                <div className="flex items-center gap-3">
                  <span className="text-text-dim w-40">Job processing</span>
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      orchestratorSettings.enabled ? "bg-green-500" : "bg-red-500"
                    }`}
                  />
                  <span className={orchestratorSettings.enabled ? "text-green-400" : "text-red-400"}>
                    {orchestratorSettings.enabled ? "Enabled" : "Disabled"}
                  </span>
                  <button
                    onClick={handleToggleOrchestrator}
                    disabled={orchestratorToggling}
                    className={`text-xs border rounded px-3 py-1 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                      orchestratorSettings.enabled
                        ? "border-red-700 text-red-500 hover:bg-red-900"
                        : "border-accent text-accent hover:bg-accent hover:text-background"
                    }`}
                  >
                    {orchestratorToggling
                      ? "Saving…"
                      : orchestratorSettings.enabled
                        ? "Disable"
                        : "Enable"}
                  </button>
                </div>

                {orchestratorSettings.updated_by && (
                  <div className="text-[10px] text-text-dim">
                    Last changed by {orchestratorSettings.updated_by}
                    {orchestratorSettings.updated_at
                      ? ` · ${new Date(orchestratorSettings.updated_at).toLocaleString()}`
                      : ""}
                  </div>
                )}

                {orchestratorError && (
                  <div className="text-xs text-red-400">Failed to save — try again.</div>
                )}

                <p className="text-[10px] text-text-dim leading-relaxed">
                  When disabled, job-tiagg-orchestrator's next scheduled run exits
                  immediately without claiming any candidates or calling
                  detections.ai/Sentinel — no new detection projects get
                  created. This does <span className="text-text-dim underline">not</span> change
                  the job's underlying Azure schedule trigger (fixed via
                  infra/apps.bicep); the container still starts on its normal
                  cadence and exits quickly while disabled.
                </p>

                {scheduleForm && (
                  <div className="mt-4 border-t border-border pt-3 space-y-3">
                    <div className="text-xs font-bold text-text-dim tracking-wider">
                      RUN SCHEDULE
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      <label className="text-text-dim w-40 shrink-0">Run every</label>
                      <select
                        value={scheduleForm.intervalPreset}
                        onChange={(e) => {
                          const v = e.target.value === "custom" ? "custom" : Number(e.target.value);
                          setScheduleForm((prev) => ({ ...prev, intervalPreset: v }));
                        }}
                        className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
                      >
                        <option value={30}>30 Min</option>
                        <option value={60}>1 Hour</option>
                        <option value={120}>2 Hours</option>
                        <option value={240}>4 Hours</option>
                        <option value={1440}>1 Day</option>
                        <option value="custom">Custom…</option>
                      </select>
                      {scheduleForm.intervalPreset === "custom" && (
                        <input
                          type="number"
                          min="1"
                          max="10080"
                          value={scheduleForm.customMinutes}
                          onChange={(e) => setScheduleForm((prev) => ({ ...prev, customMinutes: e.target.value }))}
                          placeholder="minutes"
                          className="text-xs bg-background border border-border rounded px-2 py-1 text-text w-24"
                        />
                      )}
                    </div>
                    <p className="text-[10px] text-text-dim leading-relaxed">
                      Azure's own job schedule (infra/apps.bicep's <code>orchestratorSchedule</code>,
                      currently deployed as every 30 minutes — confirm this hasn't changed before
                      trusting it) is the real floor: this setting can only skip fires to lengthen
                      the effective interval, it can never make the job run more often than its
                      underlying Azure cron.
                    </p>

                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        id="schedule-window-enabled"
                        checked={scheduleForm.windowEnabled}
                        onChange={(e) => setScheduleForm((prev) => ({ ...prev, windowEnabled: e.target.checked }))}
                      />
                      <label htmlFor="schedule-window-enabled" className="text-text-dim">
                        Restrict to a daily time window (UTC)
                      </label>
                    </div>
                    {scheduleForm.windowEnabled && (
                      <div className="flex items-center gap-2 pl-6">
                        <input
                          type="time"
                          value={scheduleForm.windowStart}
                          onChange={(e) => setScheduleForm((prev) => ({ ...prev, windowStart: e.target.value }))}
                          className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
                        />
                        <span className="text-text-dim">to</span>
                        <input
                          type="time"
                          value={scheduleForm.windowEnd}
                          onChange={(e) => setScheduleForm((prev) => ({ ...prev, windowEnd: e.target.value }))}
                          className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
                        />
                      </div>
                    )}

                    <div className="flex items-center gap-1.5 flex-wrap">
                      <label className="text-text-dim w-40 shrink-0">Days</label>
                      {DAY_LABELS.map((label, day) => (
                        <button
                          key={day}
                          type="button"
                          onClick={() => toggleScheduleDay(day)}
                          className={`text-[10px] px-2 py-1 rounded border transition-colors ${
                            scheduleForm.days.includes(day)
                              ? "border-accent text-accent"
                              : "border-border text-text-dim hover:text-text"
                          }`}
                        >
                          {label}
                        </button>
                      ))}
                    </div>

                    <div className="flex items-center gap-3">
                      <button
                        onClick={handleSaveSchedule}
                        disabled={scheduleSaving}
                        className="text-xs border border-accent text-accent rounded-sm px-3 py-1 hover:bg-accent hover:text-background transition-colors disabled:opacity-40"
                      >
                        {scheduleSaving ? "Saving…" : "Save schedule"}
                      </button>
                      {scheduleError && (
                        <span className="text-xs text-red-400">Failed to save — check the values and try again.</span>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </Section>
      )}

      {userRole === "admin" && (
        <Section title="HUNT SENTINEL SYNC">
          <div className="space-y-3">
            {huntSyncError && !huntSyncSettings && (
              <div className="text-xs text-red-400">Failed to load hunt sync settings.</div>
            )}

            {huntSyncSettings && (
              <>
                <div className="flex items-center gap-2">
                  <span className="text-text-dim w-40">Mode</span>
                  {["off", "manual", "auto"].map((mode) => (
                    <button
                      key={mode}
                      onClick={() => handleSetHuntSyncMode(mode)}
                      disabled={huntSyncSaving}
                      className={`text-xs border rounded px-3 py-1 transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                        huntSyncSettings.mode === mode
                          ? "border-accent text-accent bg-accent/10"
                          : "border-border text-text-dim hover:text-text"
                      }`}
                    >
                      {mode === "off" ? "Off" : mode === "manual" ? "Manual approval" : "Auto-deploy"}
                    </button>
                  ))}
                </div>

                {huntSyncSettings.mode === "auto" && (
                  <>
                    <label className="flex items-center gap-2 text-xs text-text-dim cursor-pointer">
                      <input
                        type="checkbox"
                        checked={huntSyncSettings.require_alignment}
                        onChange={handleToggleRequireAlignment}
                        disabled={huntSyncSaving}
                      />
                      Require MITRE alignment (stricter — fewer hunts auto-deploy)
                    </label>

                    <div className="mt-4 border-t border-border pt-3 space-y-3">
                      <div className="text-xs font-bold text-text-dim tracking-wider">
                        SEVERITY GATE
                      </div>
                      <p className="text-[10px] text-text-dim leading-relaxed">
                        Only hunts whose source article severity matches a selected card
                        auto-deploy. All four selected (the default) means no restriction.
                      </p>
                      <SeverityCards
                        selected={huntSyncSettings.severities}
                        onChange={handleSaveHuntSeverities}
                      />
                      {huntScheduleSaving && (
                        <span className="text-[10px] text-text-dim">Saving…</span>
                      )}
                    </div>

                    <div className="mt-4 border-t border-border pt-3 space-y-3">
                      <div className="text-xs font-bold text-text-dim tracking-wider">
                        SYNC SCHEDULE
                      </div>
                      <CadencePicker
                        settings={huntSyncSettings}
                        onSave={handleSaveHuntSchedule}
                        saving={huntScheduleSaving}
                        error={huntScheduleError}
                        helpText="Layered on top of job-tiagg-orchestrator's own run cadence -- a hunt's auto-deploy can only happen when the orchestrator itself is already running, so this can lengthen the effective interval further but never sync faster than the orchestrator's own schedule allows."
                      />
                    </div>

                    <div className="mt-4 border-t border-border pt-3 space-y-3">
                      <div className="text-xs font-bold text-text-dim tracking-wider">
                        AUTO-DEPLOY TARGET
                      </div>
                      <p className="text-[10px] text-text-dim leading-relaxed">
                        Where auto-deploy links new detections by default, for any hunt that
                        hasn&rsquo;t been pointed at a specific Sentinel Hunt of its own (see
                        Generated Hunts &rsquo; own deploy-target picker, which always takes
                        priority over this). If the chosen hunt fills up (~975 queries), a
                        new &ldquo;In The News: Hunts vN&rdquo; hunt is created automatically
                        and this setting updates to point at it.
                      </p>
                      <label className="flex items-center gap-1.5 text-[10px] text-text-dim">
                        Default target
                        <select
                          value={huntSyncSettings.auto_deploy_target_sentinel_hunt_id || ""}
                          onChange={(e) => handleSaveAutoDeployTarget(e.target.value || null)}
                          disabled={autoDeployTargetSaving}
                          className="bg-background border border-border rounded-sm px-1.5 py-0.5 text-[10px] text-text disabled:opacity-40"
                        >
                          <option value="">Create new hunt each time</option>
                          {(sentinelTargets?.hunts || []).map((t) => (
                            <option key={t.id} value={t.id}>{t.display_name || t.id}</option>
                          ))}
                        </select>
                      </label>
                      {autoDeployTargetSaving && (
                        <span className="text-[10px] text-text-dim">Saving…</span>
                      )}
                      {autoDeployTargetError && (
                        <div className="text-[10px] text-red-400">Failed to save — try again.</div>
                      )}
                      {sentinelTargets?.error && (
                        <div className="text-[10px] text-red-400">{sentinelTargets.error}</div>
                      )}
                    </div>
                  </>
                )}

                {huntSyncSettings.updated_by && (
                  <div className="text-[10px] text-text-dim">
                    Last changed by {huntSyncSettings.updated_by}
                    {huntSyncSettings.updated_at
                      ? ` · ${new Date(huntSyncSettings.updated_at).toLocaleString()}`
                      : ""}
                  </div>
                )}

                {huntSyncError && (
                  <div className="text-xs text-red-400">Failed to save — try again.</div>
                )}

                <p className="text-[10px] text-text-dim leading-relaxed">
                  Controls whether generated hunts get pushed into a real Microsoft
                  Sentinel workspace. <span className="text-text-dim underline">Off</span> (default)
                  never touches Sentinel. <span className="text-text-dim underline">Manual approval</span> lets
                  you review a hunt in the Hunts tab and click Deploy yourself — only
                  detections that already passed the static gate and backtest are
                  pushed. <span className="text-text-dim underline">Auto-deploy</span> pushes
                  eligible detections automatically, with no human in the loop, as
                  soon as they're generated. All modes still require
                  SENTINEL_HUNTING_SYNC_ENABLED and a working Sentinel RBAC grant to
                  actually reach Azure.
                </p>
              </>
            )}
          </div>
        </Section>
      )}

        </div>{/* end left column */}

        <div className="w-80 shrink-0">
          <Section title="SOURCES & TRUST SCORES">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-text-dim border-b border-border">
                  <th className="text-left pb-2 font-normal">Source</th>
                  <th className="text-left pb-2 font-normal">Tier</th>
                  <th className="text-right pb-2 font-normal">Trust Score (0–100)</th>
                </tr>
              </thead>
              <tbody>
                {(sources || []).map((src) => (
                  <SourceRow key={src.name} source={src} />
                ))}
              </tbody>
            </table>
          </Section>
        </div>{/* end right column */}

      </div>{/* end flex row */}
    </div>
  );
}

function SourceRow({ source }) {
  const [val, setVal] = useState(source.score ?? 50);
  const [saved, setSaved] = useState(false);

  function commit() {
    fetch(
      `${API}/api/sources/${encodeURIComponent(source.name)}/score`,
      { method: "PATCH", headers: authHeader(), body: JSON.stringify({ score: val }) }
    )
      .then((r) => r.json())
      .then(() => { setSaved(true); setTimeout(() => setSaved(false), 2000); })
      .catch(() => {});
  }

  return (
    <tr className="border-b border-border last:border-0">
      <td className="py-1.5 text-text">{source.name}</td>
      <td className="py-1.5 text-text-dim">{source.tier ?? 3}</td>
      <td className="py-1.5 text-right">
        <input
          type="number" min={0} max={100} value={val}
          onChange={(e) => setVal(Number(e.target.value))}
          onBlur={commit}
          className="w-16 bg-background border border-border rounded-sm px-1 py-0.5 text-xs text-text text-right focus:outline-hidden focus:border-accent"
        />
        {saved && <span className="ml-1 text-[10px] text-accent">✓</span>}
      </td>
    </tr>
  );
}

