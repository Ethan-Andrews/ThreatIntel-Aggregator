import { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/router";
import { signOut } from "next-auth/react";
import { FilterProvider, useFilters } from "../context/FilterContext";
import TopBar        from "../components/layout/TopBar";
import TabBar        from "../components/layout/TabBar";
import Sidebar       from "../components/layout/Sidebar";
import TopFilterBar  from "../components/layout/TopFilterBar";
import FeedList      from "../components/feed/FeedList";
import DashboardWidgets from "../components/dashboard/DashboardWidgets";
import MitreMatrix   from "../components/mitre/MitreMatrix";
import SettingsPanel from "../components/settings/SettingsPanel";
import TriagePanel   from "../components/triage/TriagePanel";
import YourStack     from "../components/stack/YourStack";
import IocTable      from "../components/iocs/IocTable";
import IntegrationsPanel from "../components/integrations/IntegrationsPanel";
import RunZeroPanel      from "../components/integrations/RunZeroPanel";
import DetectionsPanel from "../components/detections/DetectionsPanel";
import { authFetch as authFetchWithRetry } from "../lib/authFetch";
import { clearAuthState, decodeJwtPayload, getToken, isTokenExpired, logout, shouldRedirectNow } from "../lib/authSession";
import { getAuthMode } from "../lib/authMode";

const API       = process.env.NEXT_PUBLIC_API_URL || "";
const PAGE_SIZE = 100;

function Toast({ message, variant, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 5000);
    return () => clearTimeout(t);
  }, [onDismiss]);
  return (
    <div
      className={`fixed bottom-4 right-4 z-50 px-4 py-3 rounded border text-sm max-w-xs shadow-xl ${
        variant === "error"
          ? "bg-surface border-red-600 text-red-400"
          : "bg-surface border-accent text-accent"
      }`}
    >
      {message}
      <button onClick={onDismiss} className="ml-3 text-text-dim hover:text-text">✕</button>
    </div>
  );
}

function Shell({ apiKey, onLogout, userRole }) {
  const router   = useRouter();
  const filters  = useFilters();
  const {
    activeSources, activeSeverities, activeTagFilters, activeIocFilters,
    activeTtps, search, showDuplicates, dateWindow,
  } = filters;

  const [activeTab,       setActiveTab]       = useState("feed");
  // Set by IntegrationsPanel's "Go to Sentinel Hunts"/"Go to Sentinel
  // Analytic Rules"/"Go to Defender Custom Detections" buttons so
  // DetectionsPanel mounts on the right sub-tab -- cleared on any direct
  // TabBar click so a stale target doesn't stick around on later visits.
  const [detectionsSubTab, setDetectionsSubTab] = useState(null);
  const [entries,         setEntries]         = useState([]);
  const [total,           setTotal]           = useState(0);
  const [loadedCount,     setLoadedCount]     = useState(0);
  const [hiddenDupes,     setHiddenDupes]     = useState(0);
  const [loading,         setLoading]         = useState(false);
  const [loadingMore,     setLoadingMore]     = useState(false);
  const [lastPoll,        setLastPoll]        = useState(null);
  const [sources,         setSources]         = useState([]);
  const [tagDistribution, setTagDistribution] = useState(null);
  const [iocDistribution, setIocDistribution] = useState(null);
  const [ttpDistribution, setTtpDistribution] = useState([]);
  const [triagePanelOpen, setTriagePanelOpen] = useState(false);
  const [activeJobs,      setActiveJobs]      = useState([]);
  const [toasts,          setToasts]          = useState([]);
  const [sortBy,          setSortBy]          = useState("ingested");
  const [sortDir,         setSortDir]         = useState("desc");
  const jobIntervalsRef = useRef({});

  async function refreshViaApi() {
    // Local auth mode has no NextAuth cookie to silently re-exchange — send
    // the user straight back to /login to re-enter the API key instead.
    const mode = await getAuthMode().catch(() => "entra");
    if (mode === "local") {
      throw new Error("local mode has no refresh flow");
    }

    const r = await fetch("/api/auth/refresh", { method: "POST" });
    if (!r.ok) {
      throw new Error(`refresh failed ${r.status}`);
    }
    const data = await r.json();
    const [, payloadB64] = data.access_token.split(".");
    const payload = decodeJwtPayload(payloadB64);
    return { accessToken: data.access_token, role: payload.role || "viewer" };
  }

  const authFetch = useCallback((url, opts = {}) => {
    return authFetchWithRetry(url, {
      ...opts,
      refreshImpl: refreshViaApi,
    }).catch((err) => {
      if (err.message === "AUTH_REAUTH_REQUIRED" && shouldRedirectNow()) {
        clearAuthState("SESSION_MISSING");
        router.replace("/login");
      }
      throw err;
    });
  }, [router]);

  // "trust" sort is client-side only (requires source score map); map everything else to API params.
  const SERVER_SORT_MAP = { ingested: "ingested", published: "published", priority: "priority", source: "source" };

  const getFilterParams = useCallback((offset) => {
    const p = new URLSearchParams({ limit: PAGE_SIZE, offset });
    activeSources.forEach((s)    => p.append("source",       s));
    activeSeverities.forEach((s) => p.append("severity",     s));
    activeTtps.forEach((t)       => p.append("ttp",          t));
    activeTagFilters.forEach((f) => { p.append("tag_category", f.category); p.append("tag_value", f.value); });
    activeIocFilters.forEach((f) => { p.append("ioc_category", f.category); p.append("ioc_value", f.value); });
    if (search)         p.set("search",             search);
    if (showDuplicates) p.set("include_duplicates", "true");
    if (dateWindow)     p.set("date_window",        dateWindow);
    const serverKey = SERVER_SORT_MAP[sortBy];
    p.set("sort_by",  serverKey || "ingested");
    p.set("sort_dir", sortDir);
    return p;
  }, [activeSources, activeSeverities, activeTtps, activeTagFilters, activeIocFilters, search, showDuplicates, dateWindow, sortBy, sortDir]);

  const fetchSources = useCallback(() => {
    authFetch(`${API}/api/sources`)
      .then((r) => r.json())
      .then((d) => setSources(d.sources || []))
      .catch(() => {});
  }, [authFetch]);

  const fetchDistributions = useCallback(() => {
    authFetch(`${API}/api/dashboard/stats`)
      .then((r) => r.json())
      .then((d) => {
        setTagDistribution(d.tag_distribution || null);
        setIocDistribution(d.ioc_distribution || null);
        // `ttps` is a top-level field on the stats response (not nested
        // under tag_distribution) -- mapped to the {value, count} shape
        // TopFilterBar's other filter lists already use, since the API
        // returns {technique, count}.
        setTtpDistribution((d.ttps || []).map((t) => ({ value: t.technique, count: t.count })));
      })
      .catch(() => {});
  }, [authFetch]);

  useEffect(() => {
    fetchSources();
    fetchDistributions();
    const interval = setInterval(fetchDistributions, 60000);
    return () => clearInterval(interval);
  }, [fetchSources, fetchDistributions]);

  const fetchEntries = useCallback(() => {
    setLoading(true);
    authFetch(`${API}/api/entries?${getFilterParams(0)}`)
      .then((r) => r.json())
      .then((d) => {
        const rows = d.entries || [];
        setEntries(rows);
        setTotal(d.total || 0);
        setHiddenDupes(d.hidden_dupes || 0);
        setLoadedCount(rows.length);
        setLastPoll(new Date().toLocaleTimeString());
      })
      .finally(() => setLoading(false));
  }, [authFetch, getFilterParams]);

  useEffect(() => {
    fetchEntries();
    const interval = setInterval(fetchEntries, 60000);
    return () => clearInterval(interval);
  }, [fetchEntries]);

  const loadMore = useCallback(() => {
    if (loadingMore || loadedCount >= total) return;
    setLoadingMore(true);
    authFetch(`${API}/api/entries?${getFilterParams(loadedCount)}`)
      .then((r) => r.json())
      .then((d) => {
        const rows = d.entries || [];
        setEntries((prev) => [...prev, ...rows]);
        setLoadedCount((prev) => prev + rows.length);
        setTotal(d.total || 0);
      })
      .finally(() => setLoadingMore(false));
  }, [authFetch, getFilterParams, loadedCount, total, loadingMore]);

  function addToast(message, variant = "success") {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, variant }]);
  }

  function dismissToast(id) {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }

  function startJobPolling(job_id) {
    setActiveJobs((prev) => [
      ...prev.filter((j) => j.job_id !== job_id),
      { job_id, status: "running", total: 0, completed: 0, failed: 0 },
    ]);

    const intervalId = setInterval(() => {
      authFetch(`${API}/api/retriage/jobs/${job_id}`)
        .then((r) => r.json())
        .then((job) => {
          setActiveJobs((prev) =>
            prev.map((j) => (j.job_id === job_id ? job : j))
          );
          if (job.status === "completed") {
            clearInterval(jobIntervalsRef.current[job_id]);
            delete jobIntervalsRef.current[job_id];
            addToast(`Retriage complete — ${job.completed} entries processed`);
            fetchEntries();
          } else if (job.status === "failed") {
            clearInterval(jobIntervalsRef.current[job_id]);
            delete jobIntervalsRef.current[job_id];
            addToast(`Retriage job failed after ${job.completed} / ${job.total} entries`, "error");
          }
        })
        .catch(() => {});
    }, 2000);

    jobIntervalsRef.current[job_id] = intervalId;
  }

  useEffect(() => {
    const intervals = jobIntervalsRef.current;
    return () => Object.values(intervals).forEach(clearInterval);
  }, []);

  function handleRetriagedSelected(hashes) {
    authFetch(`${API}/api/retriage/selected`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ hashes }),
    })
      .then((r) => r.json())
      .then((d) => { if (d.job_id) startJobPolling(d.job_id); })
      .catch(() => addToast("Failed to start retriage job", "error"));
  }

  const activeJobCount = activeJobs.filter((j) => j.status === "running").length;
  const showSidebar    = activeTab === "feed" || activeTab === "dashboard";

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-background text-text">
      <TopBar lastPoll={lastPoll} onLogout={onLogout} />
      <TabBar
        activeTab={activeTab}
        onTabChange={(tab) => { setDetectionsSubTab(null); setActiveTab(tab); }}
      />

      <div className="flex flex-1 overflow-hidden">
        {showSidebar && (
          <Sidebar sources={sources} />
        )}

        <div className="flex flex-col flex-1 overflow-hidden">
          {showSidebar && (
            <TopFilterBar
              tagDistribution={tagDistribution}
              iocDistribution={iocDistribution}
              ttpDistribution={ttpDistribution}
            />
          )}

          <div className="flex-1 overflow-y-auto">
            {activeTab === "feed" && (
              <FeedList
                entries={entries}
                total={total}
                loadedCount={loadedCount}
                loading={loading}
                loadingMore={loadingMore}
                hiddenDupes={hiddenDupes}
                sources={sources}
                onLoadMore={loadMore}
                onRetriagedSelected={handleRetriagedSelected}
                apiKey={apiKey}
                onOpenTriagePanel={() => setTriagePanelOpen(true)}
                activeJobCount={activeJobCount}
                sortBy={sortBy}
                sortDir={sortDir}
                onPrimarySortChange={(key, dir) => { setSortBy(key); setSortDir(dir); }}
              />
            )}
            {activeTab === "dashboard" && (
              <DashboardWidgets
                apiKey={apiKey}
                onSwitchToFeed={() => setActiveTab("feed")}
              />
            )}
            {activeTab === "mitre" && (
              <MitreMatrix
                apiKey={apiKey}
                onSwitchToFeed={() => setActiveTab("feed")}
              />
            )}
            {activeTab === "settings" && (
              <SettingsPanel apiKey={apiKey} sources={sources} userRole={userRole} />
            )}
            {activeTab === "your-stack" && (
              <YourStack apiKey={apiKey} onRematchComplete={fetchEntries} />
            )}
            {activeTab === "iocs" && (
              <IocTable
                authFetch={authFetch}
                onSwitchToFeed={() => setActiveTab("feed")}
                userRole={userRole}
              />
            )}
            {activeTab === "integrations" && (
              <IntegrationsPanel
                apiKey={apiKey}
                userRole={userRole}
                onSwitchToRunZero={() => setActiveTab("runzero")}
                onSwitchToDetections={(subTab) => {
                  setDetectionsSubTab(subTab);
                  setActiveTab("detections");
                }}
              />
            )}
            {activeTab === "runzero" && (
              <RunZeroPanel apiKey={apiKey} userRole={userRole} />
            )}
            {activeTab === "detections" && (
              <DetectionsPanel
                authFetch={authFetch}
                userRole={userRole}
                initialSubTab={detectionsSubTab}
              />
            )}
          </div>
        </div>
      </div>

      <TriagePanel
        open={triagePanelOpen}
        onClose={() => setTriagePanelOpen(false)}
        onJobStarted={startJobPolling}
        activeJobs={activeJobs}
      />

      {toasts.map((t) => (
        <Toast key={t.id} message={t.message} variant={t.variant} onDismiss={() => dismissToast(t.id)} />
      ))}
    </div>
  );
}

export default function Home() {
  const [apiKey, setApiKey] = useState(null);
  const [userRole, setUserRole] = useState("viewer");
  const router = useRouter();

  useEffect(() => {
    const stored = getToken();
    if (!stored || isTokenExpired(stored)) {
      router.replace("/login");
      return;
    }
    setApiKey(stored);
    setUserRole(sessionStorage.getItem("ti_user_role") || "viewer");
  }, [router]);

  useEffect(() => {
    const checkExpiry = () => {
      const token = getToken();
      if (!token || isTokenExpired(token)) {
        clearAuthState("TOKEN_EXPIRED");
        router.replace("/login");
      }
    };
    const interval = setInterval(checkExpiry, 60_000);
    checkExpiry();
    return () => clearInterval(interval);
  }, [router]);

  function handleLogout() {
    logout({ signOutImpl: signOut, redirectImpl: (path) => router.replace(path) });
  }

  if (!apiKey) return null;

  return (
    <FilterProvider>
      <Shell apiKey={apiKey} onLogout={handleLogout} userRole={userRole} />
    </FilterProvider>
  );
}