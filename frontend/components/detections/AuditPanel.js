'use client';
import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import TimeRangeToggle from '../layout/TimeRangeToggle';

const API = process.env.NEXT_PUBLIC_API_URL || '';
const PAGE_SIZE = 50;

// Bubble size/color scale -- a category with 1 occurrence reads as a small,
// muted node; the largest category in the current set reads as a large,
// saturated one. Pure CSS custom properties (no per-category class list to
// maintain) so this scales to however many distinct categories the real
// data produces.
function bubbleScale(count, maxCount) {
  const ratio = maxCount > 0 ? count / maxCount : 0;
  const size = 56 + Math.round(ratio * 64); // 56px .. 120px
  return { size, ratio };
}

function categoryTone(category) {
  if (category.startsWith('Static gate:')) return 'gate';
  if (/forbidden|unauthorized|rbac/i.test(category)) return 'auth';
  return 'other';
}

const TONE_STYLES = {
  gate:  { ring: 'ring-red-500/50',    glow: 'shadow-[0_0_24px_-4px_rgba(239,68,68,0.55)]',    grad: 'from-red-500/30 via-rose-500/15 to-transparent' },
  auth:  { ring: 'ring-amber-500/50',  glow: 'shadow-[0_0_24px_-4px_rgba(245,158,11,0.55)]',   grad: 'from-amber-500/30 via-orange-500/15 to-transparent' },
  other: { ring: 'ring-fuchsia-500/50', glow: 'shadow-[0_0_24px_-4px_rgba(217,70,239,0.55)]',  grad: 'from-fuchsia-500/30 via-purple-500/15 to-transparent' },
};

function FailureBubble({ category, count, maxCount, index, active, onSelect }) {
  const { size, ratio } = bubbleScale(count, maxCount);
  const tone = TONE_STYLES[categoryTone(category)];
  const label = category.startsWith('Static gate: ') ? category.slice('Static gate: '.length) : category;
  const sublabel = category.startsWith('Static gate: ') ? 'static gate' : null;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.4 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.4 }}
      transition={{ type: 'spring', stiffness: 260, damping: 20, delay: index * 0.04 }}
      whileHover={{ scale: 1.08 }}
      title={`Filter by ${category}`}
      className="flex flex-col items-center gap-2 cursor-pointer"
      onClick={() => onSelect(category)}
    >
      <div
        style={{ width: size, height: size }}
        className={[
          'relative rounded-full flex items-center justify-center',
          'bg-gradient-to-br', tone.grad,
          'bg-surface ring-2', active ? 'ring-4' : tone.ring, tone.glow,
          'backdrop-blur-sm transition-shadow',
        ].join(' ')}
      >
        <span
          className="font-bold text-text tabular-nums"
          style={{ fontSize: 14 + Math.round(ratio * 10) }}
        >
          {count}
        </span>
      </div>
      <div className="text-center max-w-[7.5rem]">
        <div className="text-[10px] font-bold text-text leading-tight">{label}</div>
        {sublabel && <div className="text-[9px] text-text-dim">{sublabel}</div>}
      </div>
    </motion.div>
  );
}

const LEGEND_ENTRIES = [
  { tone: 'gate',  label: 'Static gate rejection' },
  { tone: 'auth',  label: 'Auth / RBAC error' },
  { tone: 'other', label: 'Other error' },
];

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-3 mb-4 text-[10px] text-text-dim">
      {LEGEND_ENTRIES.map(({ tone, label }) => (
        <div key={tone} className="flex items-center gap-1.5">
          <span className={`inline-block w-2.5 h-2.5 rounded-full ring-1 ${TONE_STYLES[tone].ring} bg-surface`} />
          {label}
        </div>
      ))}
    </div>
  );
}

function FailureBubbles({ categories, activeCategory, onSelect }) {
  if (!categories || categories.length === 0) return null;
  const maxCount = Math.max(...categories.map((c) => c.count));

  return (
    <div className="relative mb-5 rounded-lg border border-border bg-surface p-4">
      <div className="text-[10px] font-bold text-text-dim tracking-wider mb-2">
        FAILURE BREAKDOWN
      </div>
      <Legend />
      <div className="relative flex flex-wrap gap-5">
        <AnimatePresence>
          {categories.map((c, i) => (
            <FailureBubble
              key={c.category}
              category={c.category}
              count={c.count}
              maxCount={maxCount}
              index={i}
              active={c.category === activeCategory}
              onSelect={onSelect}
            />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

function TrendChart({ trend, window: activeWindow, onWindowChange }) {
  const maxCount = Math.max(1, ...trend.map((t) => t.failing + t.passing));

  return (
    <div className="mb-5 rounded-lg border border-border bg-surface p-4">
      <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
        <div className="text-[10px] font-bold text-text-dim tracking-wider">
          RESULTS BY LAST-CHECKED DATE
        </div>
        <TimeRangeToggle value={{ window: activeWindow }} onChange={onWindowChange} />
      </div>
      <div className="text-[10px] text-text-dim italic mb-3">
        This shows when items were last checked and what that check said — not a real
        pass/fail history. A detection's result is fixed at generation time and never
        re-checked, so a bar here reflects generation volume, not day-by-day drift.
      </div>
      {trend.length === 0 ? (
        <div className="text-xs text-text-dim italic">No checked items in this window.</div>
      ) : (
        <div className="flex items-end gap-1 h-24">
          {trend.map((t) => {
            const total = t.failing + t.passing;
            const height = Math.max(2, Math.round((total / maxCount) * 96));
            const failingHeight = total > 0 ? Math.round((t.failing / total) * height) : 0;
            return (
              <div
                key={t.date}
                title={`${new Date(t.date).toLocaleDateString()}: ${t.failing} failing, ${t.passing} passing`}
                className="flex-1 flex flex-col justify-end min-w-[4px]"
                style={{ height: 96 }}
              >
                <div className="w-full bg-green-800" style={{ height: height - failingHeight }} />
                <div className="w-full bg-red-700" style={{ height: failingHeight }} />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const SOURCE_LABEL = {
  detection:      'AI Detection',
  hunt_sync:      'Hunt Sync',
  sentinel_query: 'Sentinel Query',
  analytics_rule: 'Analytics Rule',
};

function OutcomeBadge({ isFailing }) {
  return (
    <span className={[
      'inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border shrink-0',
      isFailing
        ? 'bg-red-950 text-red-300 border-red-800'
        : 'bg-green-950 text-green-300 border-green-800',
    ].join(' ')}>
      {isFailing ? 'FAILING' : 'PASSING'}
    </span>
  );
}

function SourceBadge({ source }) {
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border bg-surface text-text-dim border-border shrink-0">
      {SOURCE_LABEL[source] || source}
    </span>
  );
}

const ANNOTATION_LABEL = {
  acknowledged: 'ACKNOWLEDGED',
  not_applicable: 'NOT APPLICABLE',
  fixed: 'FIXED',
};

function AnnotationBadge({ status }) {
  if (!status) return null;
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border shrink-0 bg-blue-950 text-blue-300 border-blue-800">
      {ANNOTATION_LABEL[status] || status.toUpperCase()}
    </span>
  );
}

function AuditRow({ item, onAnnotate, onClearAnnotation }) {
  const [editing, setEditing] = useState(false);
  const [status, setStatus] = useState(item.annotation_status || 'acknowledged');
  const [notes, setNotes] = useState(item.annotation_notes || '');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await onAnnotate(item.source, item.source_id, status, notes);
      setEditing(false);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="border border-border rounded bg-surface p-3">
      <div className="flex items-center gap-2 flex-wrap mb-1">
        <OutcomeBadge isFailing={item.is_failing} />
        <SourceBadge source={item.source} />
        <AnnotationBadge status={item.annotation_status} />
        <span className="text-[10px] text-text-dim">{item.check_type}</span>
        {item.checked_at && (
          <span className="text-[10px] text-text-dim ml-auto shrink-0">
            {new Date(item.checked_at).toLocaleString()}
          </span>
        )}
      </div>
      <div className="text-xs font-bold text-text mb-1">{item.title}</div>
      <div className={`text-[11px] ${item.is_failing ? 'text-red-400' : 'text-text-dim'}`}>
        {item.detail}
      </div>
      {item.annotation_status && item.annotation_notes && (
        <div className="text-[11px] text-blue-300 mt-1 italic">"{item.annotation_notes}"</div>
      )}

      {!editing ? (
        <div className="flex gap-2 mt-2">
          <button
            onClick={() => setEditing(true)}
            className="text-[10px] border border-border rounded px-2 py-1 text-text-dim hover:text-text hover:bg-background transition-colors"
          >
            {item.annotation_status ? 'Edit annotation' : 'Annotate'}
          </button>
          {item.annotation_status && (
            <button
              onClick={() => onClearAnnotation(item.source, item.source_id)}
              className="text-[10px] border border-border rounded px-2 py-1 text-text-dim hover:text-text hover:bg-background transition-colors"
            >
              Clear annotation
            </button>
          )}
        </div>
      ) : (
        <div className="mt-2 flex flex-col gap-2 border-t border-border pt-2">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
          >
            <option value="acknowledged">Acknowledged</option>
            <option value="not_applicable">Not Applicable</option>
            <option value="fixed">Fixed</option>
          </select>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Closing notes…"
            className="text-xs bg-background border border-border rounded px-2 py-1 text-text w-full"
            rows={2}
          />
          <div className="flex gap-2">
            <button
              onClick={save}
              disabled={saving}
              className="text-[10px] border border-accent rounded px-2 py-1 text-accent hover:bg-background transition-colors disabled:opacity-50"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            <button
              onClick={() => setEditing(false)}
              className="text-[10px] border border-border rounded px-2 py-1 text-text-dim hover:text-text hover:bg-background transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Pager({ offset, total, onPrev, onNext }) {
  if (total === 0) return null;
  return (
    <div className="flex items-center justify-between mt-4 text-xs text-text-dim">
      <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
      <div className="flex gap-2">
        <button
          onClick={onPrev}
          disabled={offset === 0}
          className="border border-border rounded px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
        >
          Prev
        </button>
        <button
          onClick={onNext}
          disabled={offset + PAGE_SIZE >= total}
          className="border border-border rounded px-3 py-1 hover:bg-surface transition-colors disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

export default function AuditPanel({ authFetch, userRole }) {
  const [summary, setSummary] = useState(null);
  const [breakdown, setBreakdown] = useState([]);
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [outcomeFilter, setOutcomeFilter] = useState('failing');
  const [categoryFilter, setCategoryFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState('unannotated');
  const [trend, setTrend] = useState([]);
  const [trendRange, setTrendRange] = useState({ window: '30d', from: null, to: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const isAdmin = userRole === 'admin';

  const loadSummary = useCallback(() => {
    if (!isAdmin) return;
    authFetch(`${API}/api/audit/summary`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then(setSummary)
      .catch(() => {});
  }, [authFetch, isAdmin]);

  const loadBreakdown = useCallback(() => {
    if (!isAdmin) return;
    authFetch(`${API}/api/audit/failure-breakdown`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => setBreakdown(data.categories || []))
      .catch(() => {});
  }, [authFetch, isAdmin]);

  const load = useCallback(() => {
    if (!isAdmin) return;
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) });
    // A category only ever exists among failing rows (see audit_log.py's
    // _categorize()) -- force outcome=failing whenever a category filter
    // is active, regardless of the dropdown's own state, so the two
    // filters can never silently contradict each other.
    if (categoryFilter) {
      params.set('outcome', 'failing');
      params.set('category', categoryFilter);
    } else if (outcomeFilter !== 'all') {
      params.set('outcome', outcomeFilter);
    }
    if (statusFilter !== 'unannotated') {
      params.set('status', statusFilter);
    }

    authFetch(`${API}/api/audit/failures?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => setError('Failed to load audit entries.'))
      .finally(() => setLoading(false));
  }, [authFetch, offset, outcomeFilter, categoryFilter, statusFilter]);

  const annotate = useCallback(async (source, sourceId, status, notes) => {
    const res = await authFetch(`${API}/api/audit/${source}/${sourceId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes }),
    });
    if (!res.ok) throw new Error('Failed to save annotation');
    load();
    loadSummary();
  }, [authFetch, load, loadSummary]);

  const clearAnnotation = useCallback(async (source, sourceId) => {
    const res = await authFetch(`${API}/api/audit/${source}/${sourceId}`, { method: 'DELETE' });
    if (!res.ok) return;
    load();
    loadSummary();
  }, [authFetch, load, loadSummary]);

  const selectCategory = useCallback((category) => {
    setCategoryFilter((prev) => (prev === category ? null : category));
    setOffset(0);
  }, []);

  const clearCategory = useCallback(() => {
    setCategoryFilter(null);
    setOffset(0);
  }, []);

  const loadTrend = useCallback(() => {
    if (!isAdmin) return;
    if (trendRange.window === 'custom' && (!trendRange.from || !trendRange.to)) return;
    const params = new URLSearchParams({ window: trendRange.window });
    if (trendRange.window === 'custom') {
      params.set('from', trendRange.from);
      params.set('to', trendRange.to);
    }
    authFetch(`${API}/api/audit/trend?${params.toString()}`)
      .then((r) => { if (!r.ok) throw new Error(); return r.json(); })
      .then((data) => setTrend(data.trend || []))
      .catch(() => {});
  }, [authFetch, isAdmin, trendRange]);

  const handleTrendWindowChange = useCallback((range) => {
    setTrendRange(range);
  }, []);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => { loadBreakdown(); }, [loadBreakdown]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadTrend(); }, [loadTrend]);

  if (!isAdmin) {
    return (
      <div className="p-4 text-xs text-text-dim italic">
        The audit log is only available to admins.
      </div>
    );
  }

  return (
    <div className="p-4 overflow-y-auto">
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="text-xs font-bold text-text-dim tracking-wider">
          ▸ PIPELINE AUDIT LOG ({total})
        </div>
        {summary && (
          <div className="flex gap-2 text-[11px]">
            <span className="px-1.5 py-0.5 rounded border bg-red-950 text-red-300 border-red-800 font-bold">
              {summary.failing} failing
            </span>
            <span className="px-1.5 py-0.5 rounded border bg-green-950 text-green-300 border-green-800 font-bold">
              {summary.passing} passing
            </span>
          </div>
        )}
      </div>
      <div className="text-[11px] text-text-dim mb-4">
        Every static-gate/control-probe check this app has actually run, across AI-generated
        detections, Sentinel hunt syncs, and Sentinel-native hunt queries — one place to see
        what's currently failing instead of checking each tab separately.
      </div>

      <TrendChart trend={trend} window={trendRange.window} onWindowChange={handleTrendWindowChange} />

      <FailureBubbles categories={breakdown} activeCategory={categoryFilter} onSelect={selectCategory} />

      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <label className="text-[11px] text-text-dim">Show:</label>
        <select
          value={outcomeFilter}
          onChange={(e) => { setOutcomeFilter(e.target.value); setOffset(0); }}
          disabled={!!categoryFilter}
          className="text-xs bg-background border border-border rounded px-2 py-1 text-text disabled:opacity-50"
        >
          <option value="failing">Failing only</option>
          <option value="passing">Passing only</option>
          <option value="all">All checked items</option>
        </select>
        <label className="text-[11px] text-text-dim">Status:</label>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}
          className="text-xs bg-background border border-border rounded px-2 py-1 text-text"
        >
          <option value="unannotated">Unannotated</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="not_applicable">Not Applicable</option>
          <option value="fixed">Fixed</option>
          <option value="all">All (any status)</option>
        </select>
        {categoryFilter && (
          <span className="inline-flex items-center gap-1 text-[11px] rounded-sm px-2 py-0.5 border border-accent text-accent font-mono">
            {categoryFilter}
            <button onClick={clearCategory} className="ml-0.5 hover:opacity-60" aria-label="Clear category filter">×</button>
          </span>
        )}
      </div>

      {error && <div className="text-xs text-red-400 mb-3">{error}</div>}
      {loading && <div className="text-xs text-text-dim">Loading…</div>}

      {!loading && items.length === 0 && (
        <div className="text-xs text-text-dim italic">
          {categoryFilter
            ? 'Nothing currently failing matches this category.'
            : outcomeFilter === 'failing'
            ? 'Nothing is currently failing.'
            : 'No items match this filter.'}
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="flex flex-col gap-2">
          {items.map((item) => (
            <AuditRow
              key={`${item.source}-${item.source_id}`}
              item={item}
              onAnnotate={annotate}
              onClearAnnotation={clearAnnotation}
            />
          ))}
        </div>
      )}

      <Pager
        offset={offset}
        total={total}
        onPrev={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        onNext={() => setOffset(offset + PAGE_SIZE)}
      />
    </div>
  );
}
