import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import SettingsPanel from '../SettingsPanel';

function huntSyncSection() {
  // Both the orchestrator's own "RUN SCHEDULE" and this component's "SYNC
  // SCHEDULE" render an identically-labeled interval picker -- scope
  // queries to the HUNT SENTINEL SYNC section specifically.
  const heading = screen.getByText('HUNT SENTINEL SYNC');
  return within(heading.closest('div.border'));
}

const BASE_HUNT_SYNC_SETTINGS = {
  mode: 'auto',
  require_alignment: true,
  severities: null,
  interval_minutes: 30,
  window_start_minute: null,
  window_end_minute: null,
  days_of_week: null,
  last_run_at: null,
  updated_by: null,
  updated_at: null,
};

function mockFetchRouter(routes) {
  return jest.fn((url, opts) => {
    for (const [pattern, handler] of routes) {
      if (typeof pattern === 'string' ? url.includes(pattern) : pattern.test(url)) {
        return Promise.resolve(handler(url, opts));
      }
    }
    return Promise.resolve({ ok: true, json: async () => ({}) });
  });
}

function jsonResponse(data, ok = true) {
  return { ok, json: async () => data };
}

beforeEach(() => {
  window.sessionStorage.setItem('ti_app_token', 'test-token');
});

afterEach(() => {
  window.sessionStorage.clear();
  jest.restoreAllMocks();
});

describe('SettingsPanel Hunt Sentinel Sync severity + cadence (Workstream E)', () => {
  test('severity gate and sync schedule only render in auto mode', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, mode: 'manual' })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('HUNT SENTINEL SYNC');

    expect(screen.queryByText('SEVERITY GATE')).not.toBeInTheDocument();
    expect(screen.queryByText('SYNC SCHEDULE')).not.toBeInTheDocument();
  });

  test('all four severities selected by default (severities: null means no restriction)', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('SEVERITY GATE');

    for (const label of ['Critical', 'High', 'Medium', 'Low']) {
      const btn = screen.getByText(label);
      expect(btn.className).not.toMatch(/text-text-dim/);
    }
  });

  test('deselecting a severity PATCHes the schedule endpoint with the remaining set', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/hunt-sync/schedule', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, severities: ['critical', 'high', 'medium'] })],
      ['/api/settings/hunt-sync', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('SEVERITY GATE');

    fireEvent.click(screen.getByText('Low'));

    await waitFor(() => {
      const call = global.fetch.mock.calls.find(
        ([url, opts]) => url.includes('/api/settings/hunt-sync/schedule') && opts?.method === 'PATCH',
      );
      expect(call).toBeTruthy();
      const body = JSON.parse(call[1].body);
      expect(sorted(body.severities)).toEqual(['critical', 'high', 'medium']);
    });
  });

  test('seeds the sync schedule interval picker from loaded settings', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, interval_minutes: 240 })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('SYNC SCHEDULE');
    expect(huntSyncSection().getByDisplayValue('4 Hours')).toBeInTheDocument();
  });

  test('saving the schedule PATCHes with the form values and preserves existing severities', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/hunt-sync/schedule', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, severities: ['critical'], interval_minutes: 60 })],
      ['/api/settings/hunt-sync', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, severities: ['critical'] })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('SYNC SCHEDULE');

    fireEvent.change(huntSyncSection().getByDisplayValue('30 Min'), { target: { value: '60' } });
    fireEvent.click(huntSyncSection().getByText('Save schedule'));

    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(
        ([url, opts]) => url.includes('/api/settings/hunt-sync/schedule') && opts?.method === 'PATCH',
      );
      expect(calls.length).toBeGreaterThan(0);
      const body = JSON.parse(calls[calls.length - 1][1].body);
      expect(body.interval_minutes).toBe(60);
      expect(body.severities).toEqual(['critical']);
    });
  });
});

function sorted(arr) {
  return [...arr].sort();
}
