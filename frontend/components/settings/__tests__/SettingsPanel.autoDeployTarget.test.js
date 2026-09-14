import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import SettingsPanel from '../SettingsPanel';

function huntSyncSection() {
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
  auto_deploy_target_sentinel_hunt_id: null,
  updated_by: null,
  updated_at: null,
};

const SENTINEL_TARGETS = {
  enabled: true,
  hunts: [
    { id: 'guid-v2', display_name: 'In The News: Hunts v2' },
    { id: 'guid-other', display_name: "Some Analyst's Own Hunt" },
  ],
  error: null,
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

describe('SettingsPanel Hunt Sentinel Sync auto-deploy target', () => {
  test('does not render outside auto mode', async () => {
    global.fetch = mockFetchRouter([
      ['/api/detections/hunts/sentinel-targets', () => jsonResponse(SENTINEL_TARGETS)],
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse({ ...BASE_HUNT_SYNC_SETTINGS, mode: 'manual' })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('HUNT SENTINEL SYNC');

    expect(screen.queryByText('AUTO-DEPLOY TARGET')).not.toBeInTheDocument();
  });

  test('defaults to "Create new hunt each time" when unset', async () => {
    global.fetch = mockFetchRouter([
      ['/api/detections/hunts/sentinel-targets', () => jsonResponse(SENTINEL_TARGETS)],
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('AUTO-DEPLOY TARGET');

    expect(huntSyncSection().getByDisplayValue('Create new hunt each time')).toBeInTheDocument();
  });

  test('lists fetched Sentinel hunts and seeds the current selection', async () => {
    global.fetch = mockFetchRouter([
      ['/api/detections/hunts/sentinel-targets', () => jsonResponse(SENTINEL_TARGETS)],
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse({
        ...BASE_HUNT_SYNC_SETTINGS, auto_deploy_target_sentinel_hunt_id: 'guid-v2',
      })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('AUTO-DEPLOY TARGET');

    expect(huntSyncSection().getByDisplayValue('In The News: Hunts v2')).toBeInTheDocument();
    expect(huntSyncSection().getByText("Some Analyst's Own Hunt")).toBeInTheDocument();
  });

  test('selecting an existing hunt PATCHes auto-deploy-target with its id', async () => {
    global.fetch = mockFetchRouter([
      ['/api/detections/hunts/sentinel-targets', () => jsonResponse(SENTINEL_TARGETS)],
      ['/api/settings/hunt-sync/auto-deploy-target', () => jsonResponse({
        ...BASE_HUNT_SYNC_SETTINGS, auto_deploy_target_sentinel_hunt_id: 'guid-v2',
      })],
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('AUTO-DEPLOY TARGET');

    fireEvent.change(huntSyncSection().getByDisplayValue('Create new hunt each time'), {
      target: { value: 'guid-v2' },
    });

    await waitFor(() => {
      const call = global.fetch.mock.calls.find(
        ([url, opts]) => url.includes('/api/settings/hunt-sync/auto-deploy-target') && opts?.method === 'PATCH',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({ target_sentinel_hunt_id: 'guid-v2' });
    });
  });

  test('selecting "Create new hunt each time" PATCHes with a null target', async () => {
    global.fetch = mockFetchRouter([
      ['/api/detections/hunts/sentinel-targets', () => jsonResponse(SENTINEL_TARGETS)],
      ['/api/settings/hunt-sync/auto-deploy-target', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync/schedule', () => jsonResponse(BASE_HUNT_SYNC_SETTINGS)],
      ['/api/settings/hunt-sync', () => jsonResponse({
        ...BASE_HUNT_SYNC_SETTINGS, auto_deploy_target_sentinel_hunt_id: 'guid-v2',
      })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('AUTO-DEPLOY TARGET');

    fireEvent.change(huntSyncSection().getByDisplayValue('In The News: Hunts v2'), {
      target: { value: '' },
    });

    await waitFor(() => {
      const call = global.fetch.mock.calls.find(
        ([url, opts]) => url.includes('/api/settings/hunt-sync/auto-deploy-target') && opts?.method === 'PATCH',
      );
      expect(call).toBeTruthy();
      expect(JSON.parse(call[1].body)).toEqual({ target_sentinel_hunt_id: null });
    });
  });
});
