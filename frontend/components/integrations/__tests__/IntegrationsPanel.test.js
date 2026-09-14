import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import IntegrationsPanel from '../IntegrationsPanel';

const CONNECTIONS = {
  sentinel: {
    configured: true, enabled: true,
    hunts_last_sync: '2026-09-01T00:00:00Z', analytics_rules_last_sync: '2026-09-01T00:00:00Z',
    hunt_query_count: 12, analytics_rule_count: 4,
  },
  defender: { configured: true, enabled: true, custom_detection_count: 3 },
  runzero: {
    configured: true, status: 'ok', last_sync: '2026-09-01T00:00:00Z',
    asset_count: 10, org_count: 2, vuln_count: 5,
    confirmed_matches: 1, possible_matches: 1,
  },
};

function mockFetchOnce(data) {
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, json: async () => data }));
}

describe('IntegrationsPanel', () => {
  test('renders Sentinel, Defender, and RunZero connector cards with status', async () => {
    mockFetchOnce(CONNECTIONS);
    render(<IntegrationsPanel apiKey="key" />);

    await waitFor(() => screen.getByText('Sentinel'));
    expect(screen.getByText('Defender')).toBeInTheDocument();
    expect(screen.getByText('RunZero')).toBeInTheDocument();
    expect(screen.getAllByText('Enabled')).toHaveLength(2);
    expect(screen.getByText('Synced')).toBeInTheDocument();
  });

  test('shows Not configured when a connector has no config', async () => {
    mockFetchOnce({
      ...CONNECTIONS,
      sentinel: { configured: false, enabled: false },
      defender: { configured: false, enabled: false },
    });
    render(<IntegrationsPanel apiKey="key" />);

    await waitFor(() => screen.getByText('Sentinel'));
    expect(screen.getAllByText('Not configured')).toHaveLength(2);
  });

  test('Go to Sentinel Hunts button calls onSwitchToDetections with sentinel-hunts', async () => {
    mockFetchOnce(CONNECTIONS);
    const onSwitchToDetections = jest.fn();
    render(<IntegrationsPanel apiKey="key" onSwitchToDetections={onSwitchToDetections} />);

    await waitFor(() => screen.getByText('Go to Sentinel Hunts →'));
    fireEvent.click(screen.getByText('Go to Sentinel Hunts →'));
    expect(onSwitchToDetections).toHaveBeenCalledWith('sentinel-hunts');
  });

  test('Go to Sentinel Analytic Rules button calls onSwitchToDetections with sentinel-analytics-rules', async () => {
    mockFetchOnce(CONNECTIONS);
    const onSwitchToDetections = jest.fn();
    render(<IntegrationsPanel apiKey="key" onSwitchToDetections={onSwitchToDetections} />);

    await waitFor(() => screen.getByText('Go to Sentinel Analytic Rules →'));
    fireEvent.click(screen.getByText('Go to Sentinel Analytic Rules →'));
    expect(onSwitchToDetections).toHaveBeenCalledWith('sentinel-analytics-rules');
  });

  test('Go to Defender Custom Detections button calls onSwitchToDetections with defender', async () => {
    mockFetchOnce(CONNECTIONS);
    const onSwitchToDetections = jest.fn();
    render(<IntegrationsPanel apiKey="key" onSwitchToDetections={onSwitchToDetections} />);

    await waitFor(() => screen.getByText('Go to Defender Custom Detections →'));
    fireEvent.click(screen.getByText('Go to Defender Custom Detections →'));
    expect(onSwitchToDetections).toHaveBeenCalledWith('defender');
  });

  test('Go to Integration button on the RunZero card calls onSwitchToRunZero', async () => {
    mockFetchOnce(CONNECTIONS);
    const onSwitchToRunZero = jest.fn();
    render(<IntegrationsPanel apiKey="key" onSwitchToRunZero={onSwitchToRunZero} />);

    await waitFor(() => screen.getByText('Go to Integration →'));
    fireEvent.click(screen.getByText('Go to Integration →'));
    expect(onSwitchToRunZero).toHaveBeenCalled();
  });
});
