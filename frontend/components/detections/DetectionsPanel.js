'use client';
import { useState } from 'react';
import AlignmentReviewPanel from './AlignmentReviewPanel';
import DetectionsCatalogPanel from './DetectionsCatalogPanel';
import DispositionAlertsPanel from './DispositionAlertsPanel';
import HuntsPanel from './HuntsPanel';
import SentinelHuntsPanel from './SentinelHuntsPanel';
import SentinelAnalyticsRulesPanel from './SentinelAnalyticsRulesPanel';
import AuditPanel from './AuditPanel';
import LocalDetectionsPanel from './LocalDetectionsPanel';

// Tab labels are deliberately explicit about origin -- "GENERATED" (this
// app's own AI pipeline output) vs "SENTINEL" (read-only sync of what
// already exists in the real workspace) -- since a bare "Hunts" next to
// "Sentinel Hunts" reads as two views of the same thing rather than two
// different data sources with no overlap. See each panel's own subtitle
// text for the fuller explanation.
const SUB_TABS = [
  { value: 'catalog',    label: 'ALL DETECTIONS'    },
  { value: 'defender',   label: 'DEFENDER CUSTOM DETECTIONS' },
  { value: 'alignment',  label: 'ALIGNMENT REVIEWS' },
  { value: 'disposition', label: 'DISPOSITION ALERTS' },
  { value: 'hunts',      label: 'GENERATED HUNTS'   },
  { value: 'sentinel-hunts', label: 'SENTINEL HUNTS' },
  { value: 'sentinel-analytics-rules', label: 'SENTINEL ANALYTICS RULES' },
  { value: 'local',      label: 'LOCAL DETECTIONS'  },
  { value: 'audit',      label: 'AUDIT LOG', adminOnly: true },
];

export default function DetectionsPanel({ authFetch, userRole, initialSubTab }) {
  // initialSubTab: set by IntegrationsPanel's "Go to Sentinel Hunts"/"Go to
  // Sentinel Analytic Rules"/"Go to Defender Custom Detections" buttons --
  // only read once at mount since pages/index.js only ever renders this
  // component fresh (it's unmounted whenever activeTab !== "detections"),
  // so re-deriving from the prop on every mount is enough to land on the
  // right sub-tab without needing a fully controlled subTab.
  const [subTab, setSubTab] = useState(initialSubTab || 'catalog');
  const isAdmin = userRole === 'admin';
  const visibleTabs = SUB_TABS.filter((tab) => !tab.adminOnly || isAdmin);

  return (
    <div className="flex flex-col h-full">
      <nav className="flex items-center gap-1 px-4 border-b border-border bg-surface shrink-0">
        {visibleTabs.map((tab) => (
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
        {subTab === 'catalog' && <DetectionsCatalogPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'defender' && (
          <DetectionsCatalogPanel authFetch={authFetch} userRole={userRole} lockedDetectionType="mde" />
        )}
        {subTab === 'alignment' && <AlignmentReviewPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'disposition' && <DispositionAlertsPanel authFetch={authFetch} />}
        {subTab === 'hunts' && <HuntsPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'sentinel-hunts' && <SentinelHuntsPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'sentinel-analytics-rules' && <SentinelAnalyticsRulesPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'local' && <LocalDetectionsPanel authFetch={authFetch} userRole={userRole} />}
        {subTab === 'audit' && isAdmin && <AuditPanel authFetch={authFetch} userRole={userRole} />}
      </div>
    </div>
  );
}
