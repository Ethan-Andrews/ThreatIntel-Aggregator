import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import SettingsPanel from '../SettingsPanel';

const BASE_ORCHESTRATOR_SETTINGS = {
  enabled: true,
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

describe('SettingsPanel orchestrator run schedule', () => {
  test('seeds the interval picker from the loaded settings', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/orchestrator/schedule', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
      ['/api/settings/orchestrator', () => jsonResponse({ ...BASE_ORCHESTRATOR_SETTINGS, interval_minutes: 120 })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);

    await screen.findByText('RUN SCHEDULE');
    expect(screen.getByDisplayValue('2 Hours')).toBeInTheDocument();
  });

  test('choosing Custom reveals a minutes input, and saving PATCHes the schedule endpoint', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/orchestrator/schedule', () => jsonResponse({ ...BASE_ORCHESTRATOR_SETTINGS, interval_minutes: 90 })],
      ['/api/settings/orchestrator', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('RUN SCHEDULE');

    fireEvent.change(screen.getByDisplayValue('30 Min'), { target: { value: 'custom' } });
    const minutesInput = await screen.findByPlaceholderText('minutes');
    fireEvent.change(minutesInput, { target: { value: '90' } });

    fireEvent.click(screen.getByText('Save schedule'));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/settings/orchestrator/schedule'),
        expect.objectContaining({ method: 'PATCH' })
      );
    });
    const [, opts] = global.fetch.mock.calls.find(([url]) => url.includes('/schedule'));
    const body = JSON.parse(opts.body);
    expect(body.interval_minutes).toBe(90);
    expect(body.window_start_minute).toBeNull();
    expect(body.days_of_week).toBeNull(); // full week selected by default -> null
  });

  test('toggling off one day excludes it from the saved days_of_week', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/orchestrator/schedule', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
      ['/api/settings/orchestrator', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('RUN SCHEDULE');

    fireEvent.click(screen.getByText('Sun'));
    fireEvent.click(screen.getByText('Save schedule'));

    await waitFor(() => {
      const call = global.fetch.mock.calls.find(([url]) => url.includes('/schedule'));
      expect(call).toBeTruthy();
    });
    const [, opts] = global.fetch.mock.calls.find(([url]) => url.includes('/schedule'));
    const body = JSON.parse(opts.body);
    expect(body.days_of_week).toEqual([1, 2, 3, 4, 5, 6]);
  });

  test('enabling the daily window sends the time-of-day bounds in minutes', async () => {
    global.fetch = mockFetchRouter([
      ['/api/settings/orchestrator/schedule', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
      ['/api/settings/orchestrator', () => jsonResponse(BASE_ORCHESTRATOR_SETTINGS)],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    await screen.findByText('RUN SCHEDULE');

    fireEvent.click(screen.getByLabelText(/restrict to a daily time window/i));
    fireEvent.click(screen.getByText('Save schedule'));

    await waitFor(() => {
      const call = global.fetch.mock.calls.find(([url]) => url.includes('/schedule'));
      expect(call).toBeTruthy();
    });
    const [, opts] = global.fetch.mock.calls.find(([url]) => url.includes('/schedule'));
    const body = JSON.parse(opts.body);
    expect(body.window_start_minute).toBe(9 * 60);
    expect(body.window_end_minute).toBe(17 * 60);
  });
});
