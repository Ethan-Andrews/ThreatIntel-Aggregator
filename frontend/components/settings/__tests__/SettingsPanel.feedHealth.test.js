import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import SettingsPanel from '../SettingsPanel';

const FAILING_FEED = {
  name: 'CISA',
  tier: 1,
  last_polled: '2026-08-31T10:00:00Z',
  consecutive_failures: 3,
  items_last_7d: 0,
  total_active: 12,
  last_error: 'HTTPSConnectionPool: Read timed out',
};

const HEALTHY_FEED = {
  name: 'NVD CVE',
  tier: 1,
  last_polled: '2026-09-01T00:00:00Z',
  consecutive_failures: 0,
  items_last_7d: 4,
  total_active: 20,
  last_error: null,
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

describe('SettingsPanel Feed Health', () => {
  test('surfaces the last error for a failing feed', async () => {
    global.fetch = mockFetchRouter([
      ['/api/feeds/health', () => jsonResponse({ feeds: [FAILING_FEED, HEALTHY_FEED] })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    fireEvent.click(await screen.findByText('FEED HEALTH'));

    await waitFor(() => {
      expect(screen.getByText('HTTPSConnectionPool: Read timed out')).toBeInTheDocument();
    });
    // A healthy feed must not show a stale/leftover error.
    expect(screen.queryByText(/timed out/i, { selector: `[title="NVD CVE"]` })).toBeNull();
  });

  test('admin can retry a failing feed and the error clears on success', async () => {
    let retried = false;
    global.fetch = mockFetchRouter([
      [/\/api\/feeds\/CISA\/retry$/, () => {
        retried = true;
        return jsonResponse({ success: true, error: '', items_fetched: 3, new_entries: 2 });
      }],
      ['/api/feeds/health', () =>
        jsonResponse({
          feeds: [retried ? { ...FAILING_FEED, consecutive_failures: 0, last_error: null } : FAILING_FEED, HEALTHY_FEED],
        }),
      ],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="admin" />);
    fireEvent.click(await screen.findByText('FEED HEALTH'));

    const retryButton = await screen.findByText('Retry');
    fireEvent.click(retryButton);

    await waitFor(() => expect(retried).toBe(true));
    await waitFor(() => {
      expect(screen.queryByText('HTTPSConnectionPool: Read timed out')).toBeNull();
    });
  });

  test('a non-admin viewer sees the error but no retry button', async () => {
    global.fetch = mockFetchRouter([
      ['/api/feeds/health', () => jsonResponse({ feeds: [FAILING_FEED, HEALTHY_FEED] })],
    ]);

    render(<SettingsPanel apiKey="test-token" sources={[]} userRole="viewer" />);
    fireEvent.click(await screen.findByText('FEED HEALTH'));

    await waitFor(() => {
      expect(screen.getByText('HTTPSConnectionPool: Read timed out')).toBeInTheDocument();
    });
    expect(screen.queryByText('Retry')).toBeNull();
  });
});
