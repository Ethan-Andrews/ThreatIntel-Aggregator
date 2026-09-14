import { useState, useEffect } from "react";
import * as Dialog from "@radix-ui/react-dialog";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function authHeader() {
  return { Authorization: "Bearer " + sessionStorage.getItem("ti_app_token") };
}

function JobRow({ job }) {
  const pct = job.total > 0 ? Math.round((job.completed / job.total) * 100) : 0;
  return (
    <div className="border border-border rounded-sm p-2 mb-2">
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-text-dim font-mono">Job {job.job_id}</span>
        <span className={job.status === "completed" ? "text-green-400" : job.status === "failed" ? "text-red-400" : "text-yellow-400"}>
          {job.status === "running" ? "Running" : job.status === "completed" ? "✓ Completed" : "✗ Failed"}
        </span>
      </div>
      <div className="w-full bg-border rounded-sm h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-sm transition-all ${job.status === "failed" ? "bg-red-500" : "bg-accent"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-[10px] text-text-dim mt-1 text-right">
        {job.completed} / {job.total}
      </div>
    </div>
  );
}

export default function TriagePanel({ open, onClose, onJobStarted, activeJobs }) {
  const [count,       setCount]      = useState(50);
  const [recentJobs,  setRecentJobs] = useState([]);
  const [submitting,  setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    fetch(`${API}/api/retriage/jobs`, { headers: authHeader() })
      .then((r) => r.json())
      .then((d) => setRecentJobs(d.jobs || []))
      .catch(() => {});
  }, [open]);

  function handleRun() {
    if (submitting) return;
    setSubmitting(true);
    fetch(`${API}/api/retriage/batch`, {
      method:  "POST",
      headers: { ...authHeader(), "Content-Type": "application/json" },
      body:    JSON.stringify({ count }),
    })
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((d) => {
        onJobStarted(d.job_id);
        setSubmitting(false);
      })
      .catch(() => setSubmitting(false));
  }

  const runningJobs = activeJobs.filter((j) => j.status === "running");
  const recentFive  = recentJobs.filter((j) => j.status !== "running").slice(0, 5);

  return (
    <Dialog.Root open={open} onOpenChange={(v) => !v && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-40" />
        <Dialog.Content className="fixed right-0 top-0 h-full w-[360px] bg-surface border-l border-border z-50 flex flex-col p-4 overflow-y-auto">
          <div className="flex items-center justify-between mb-4">
            <Dialog.Title className="text-sm font-bold text-text tracking-wider">
              ⟳ Retriage Panel
            </Dialog.Title>
            <Dialog.Close className="text-text-dim hover:text-text">✕</Dialog.Close>
          </div>

          <div className="mb-4">
            <div className="text-xs font-bold text-text-dim mb-2 tracking-wider">BATCH RETRIAGE</div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-text-dim">Count:</span>
              <input
                type="number"
                min={1}
                max={500}
                value={count}
                onChange={(e) => setCount(Math.max(1, Math.min(500, Number(e.target.value))))}
                className="w-20 bg-background border border-border rounded-sm px-2 py-1 text-xs text-text focus:outline-hidden focus:border-accent"
              />
              <button
                onClick={handleRun}
                disabled={submitting}
                className="flex-1 text-xs border border-border rounded-sm px-3 py-1 hover:border-accent hover:text-accent transition-colors disabled:opacity-50"
              >
                {submitting ? "Starting…" : "Run Retriage"}
              </button>
            </div>
          </div>

          {runningJobs.length > 0 && (
            <div className="mb-4">
              <div className="text-[10px] font-bold text-text-dim mb-2 tracking-wider">▸ ACTIVE JOBS</div>
              {runningJobs.map((j) => <JobRow key={j.job_id} job={j} />)}
            </div>
          )}

          {recentFive.length > 0 && (
            <div>
              <div className="text-[10px] font-bold text-text-dim mb-2 tracking-wider">▸ RECENT (LAST 5)</div>
              {recentFive.map((j) => <JobRow key={j.job_id} job={j} />)}
            </div>
          )}

          {runningJobs.length === 0 && recentFive.length === 0 && (
            <div className="text-xs text-text-dim italic">No retriage jobs yet.</div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
