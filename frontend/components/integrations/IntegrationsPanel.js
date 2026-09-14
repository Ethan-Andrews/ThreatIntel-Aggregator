'use client';
import { useState, useEffect, useCallback } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || '';

// Connector-status overview -- what used to be this whole tab (the RunZero
// matches list/search/filters) now lives under its own RunZero tab
// (RunZeroPanel.js), reached via this card's "Go to Integration" button.
// Sentinel and Defender ride the identical Sentinel/Log Analytics ARM
// connection (see connections_status.py's module docstring) -- shown as
// two cards for organization since they're conceptually different
// consumers (Analytics Rules + Hunting queries vs. Defender custom
// detections), even though "configured"/"enabled" always match between
// them.

function StatusDot({ ok, configured }) {
  const cls = !configured ? 'bg-gray-500' : ok ? 'bg-green-500' : 'bg-red-500';
  return <span className={`w-2 h-2 rounded-full ${cls} shrink-0`} />;
}

function ConnectorCard({ title, configured, ok, statusLabel, subtitle, children }) {
  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 p-4">
      <div className="flex items-center gap-2 mb-1">
        <StatusDot ok={ok} configured={configured} />
        <span className="text-white font-semibold text-sm">{title}</span>
        <span className="text-gray-400 text-xs ml-auto">{statusLabel}</span>
      </div>
      {subtitle && <div className="text-gray-400 text-xs mb-3">{subtitle}</div>}
      <div className="flex flex-wrap gap-2 mt-2">{children}</div>
    </div>
  );
}

function GoToButton({ onClick, children }) {
  return (
    <button
      onClick={onClick}
      className="text-xs px-2 py-1 rounded-sm bg-blue-900 text-blue-300 border border-blue-700 hover:bg-blue-800"
    >
      {children}
    </button>
  );
}

function formatSync(ts) {
  return ts ? `synced ${new Date(ts).toLocaleString()}` : 'never synced';
}

export default function IntegrationsPanel({ apiKey, onSwitchToRunZero, onSwitchToDetections }) {
  const [connections, setConnections] = useState(null);
  const [loading, setLoading] = useState(true);
  const headers = { Authorization: `Bearer ${apiKey}` };

  const fetchConnections = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/integrations/connections`, { headers });
      if (res.ok) setConnections(await res.json());
    } catch {} finally {
      setLoading(false);
    }
  }, [apiKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetchConnections();
    const interval = setInterval(fetchConnections, 30000);
    return () => clearInterval(interval);
  }, [fetchConnections]);

  if (loading) return <div className="p-4 text-gray-400 text-sm">Loading…</div>;

  const sentinel = connections?.sentinel || {};
  const defender = connections?.defender || {};
  const runzero  = connections?.runzero || {};
  const runzeroOk = runzero.status === 'ok';

  return (
    <div className="p-4 space-y-3">
      <ConnectorCard
        title="Sentinel"
        configured={sentinel.configured}
        ok={sentinel.configured && sentinel.enabled}
        statusLabel={!sentinel.configured ? 'Not configured' : sentinel.enabled ? 'Enabled' : 'Disabled'}
        subtitle={
          sentinel.configured
            ? `${sentinel.hunt_query_count ?? 0} hunt queries (${formatSync(sentinel.hunts_last_sync)}) · `
              + `${sentinel.analytics_rule_count ?? 0} analytics rules (${formatSync(sentinel.analytics_rules_last_sync)})`
            : 'Set AZURE_SUBSCRIPTION_ID / AZURE_RESOURCE_GROUP / SENTINEL_WORKSPACE_NAME to enable.'
        }
      >
        <GoToButton onClick={() => onSwitchToDetections?.('sentinel-hunts')}>
          Go to Sentinel Hunts →
        </GoToButton>
        <GoToButton onClick={() => onSwitchToDetections?.('sentinel-analytics-rules')}>
          Go to Sentinel Analytic Rules →
        </GoToButton>
      </ConnectorCard>

      <ConnectorCard
        title="Defender"
        configured={defender.configured}
        ok={defender.configured && defender.enabled}
        statusLabel={!defender.configured ? 'Not configured' : defender.enabled ? 'Enabled' : 'Disabled'}
        subtitle={
          defender.configured
            ? `${defender.custom_detection_count ?? 0} custom detections (via the Sentinel connection above)`
            : 'Shares Sentinel\'s connection -- configure Sentinel to enable.'
        }
      >
        <GoToButton onClick={() => onSwitchToDetections?.('defender')}>
          Go to Defender Custom Detections →
        </GoToButton>
      </ConnectorCard>

      <ConnectorCard
        title="RunZero"
        configured={runzero.configured}
        ok={runzeroOk}
        statusLabel={!runzero.configured ? 'Not configured' : runzero.status === 'never_synced' ? 'Never synced' : runzero.status === 'ok' ? 'Synced' : 'Error'}
        subtitle={
          runzero.configured
            ? `${runzero.asset_count ?? 0} assets · ${runzero.org_count ?? 0} orgs · ${formatSync(runzero.last_sync)}`
            : 'Set RUNZERO_API_TOKEN to enable the RunZero integration.'
        }
      >
        <GoToButton onClick={() => onSwitchToRunZero?.()}>
          Go to Integration →
        </GoToButton>
      </ConnectorCard>
    </div>
  );
}
