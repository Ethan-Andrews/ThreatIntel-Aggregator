'use client';
import { useState } from 'react';
import RunZeroMatchesPanel from './RunZeroMatchesPanel';
import ExposurePanel from './ExposurePanel';
import RunZeroMetricsPanel from './RunZeroMetricsPanel';

// Three sub-tabs under the RunZero tab: "Matches" is exactly what used to be
// the whole Integrations tab (RunZero-matched threat intel against this
// org's asset inventory), "Exposure" is the org-level exposure rollup
// (ExposurePanel.js, previously its own top-level nav item), and "Metrics"
// (Workstream F) is the intake/remediation trend over tracked exposures --
// all three are RunZero-sourced views, so folding them in here instead of
// leaving separate nav entries keeps every RunZero-derived view under one
// tab.
const SUB_TABS = [
  { value: 'matches',  label: 'MATCHES'  },
  { value: 'exposure', label: 'EXPOSURE' },
  { value: 'metrics',  label: 'METRICS'  },
];

export default function RunZeroPanel({ apiKey, userRole }) {
  const [subTab, setSubTab] = useState('matches');

  return (
    <div className="flex flex-col h-full">
      <nav className="flex items-center gap-1 px-4 border-b border-border bg-surface shrink-0">
        {SUB_TABS.map((tab) => (
          <button
            key={tab.value}
            onClick={() => setSubTab(tab.value)}
            className={[
              'px-3 py-1.5 text-[11px] font-bold tracking-wider border-b-2 -mb-px transition-colors',
              subTab === tab.value
                ? 'border-accent text-accent'
                : 'border-transparent text-text-dim hover:text-text',
            ].join(' ')}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="flex-1 overflow-y-auto">
        {subTab === 'matches' && <RunZeroMatchesPanel apiKey={apiKey} userRole={userRole} />}
        {subTab === 'exposure' && <ExposurePanel apiKey={apiKey} />}
        {subTab === 'metrics' && <RunZeroMetricsPanel apiKey={apiKey} />}
      </div>
    </div>
  );
}
