import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import RunZeroMatchesPanel from '../RunZeroMatchesPanel';

const STATUS = {
  configured: true, status: 'ok', last_sync: '2026-09-02T00:00:00Z',
  asset_count: 10, org_count: 2, vuln_count: 5,
  confirmed_matches: 1, possible_matches: 1,
};

const MATCH = {
  hash: 'h1', title: 'Critical RCE in Widgetsoft VPN', severity: 'Critical', source: 'S',
  published: '2026-08-01T00:00:00Z', link: '', confidence: 'confirmed',
  match_types: ['cve'], affected_asset_count: 1, affected_orgs: ['Acme'],
  ai_summary: '', match_details: [],
};

function mockFetchRouter(routes) {
  return jest.fn((url) => {
    for (const [pattern, handler] of routes) {
      if (typeof pattern === 'string' ? url.includes(pattern) : pattern.test(url)) {
        return Promise.resolve(handler(url));
      }
    }
    return Promise.resolve({ ok: true, json: async () => ({}) });
  });
}

function jsonResponse(data) {
  return { ok: true, json: async () => data };
}

function baseRoutes(matches = [MATCH]) {
  return [
    ['/api/integrations/runzero/status', () => jsonResponse(STATUS)],
    ['/api/integrations/runzero/matches', () => jsonResponse({ total: matches.length, matches })],
  ];
}

describe('RunZeroMatchesPanel', () => {
  test('search placeholder communicates it searches threat intel name too, not just asset/org', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    expect(screen.getByPlaceholderText(/threat intel name, asset name, or org/i)).toBeInTheDocument();
  });

  test('toggling a severity button re-fetches with a severity query param', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));

    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      expect(calls[calls.length - 1][0]).toContain('severity=Critical');
    });
  });

  test('toggling a severity button off removes it from the query', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      expect(calls[calls.length - 1][0]).toContain('severity=Critical');
    });

    fireEvent.click(screen.getByRole('button', { name: 'Critical' }));
    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      expect(calls[calls.length - 1][0]).not.toContain('severity=');
    });
  });

  test('setting a date range re-fetches with date_from/date_to query params', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-08-01' } });
    fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-08-31' } });

    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      const lastUrl = calls[calls.length - 1][0];
      expect(lastUrl).toContain('date_from=2026-08-01');
      expect(lastUrl).toContain('date_to=2026-08-31');
    });
  });

  test('a Clear button appears once a date range is set and clears both fields', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    expect(screen.queryByText('Clear')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-08-01' } });

    fireEvent.click(await screen.findByText('Clear'));
    expect(screen.getByLabelText('From')).toHaveValue('');
  });

  test('toggling KEV only re-fetches with kev_only=true, and off removes it', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<RunZeroMatchesPanel apiKey="key" userRole="viewer" />);
    await waitFor(() => screen.getByText('Critical RCE in Widgetsoft VPN'));

    fireEvent.click(screen.getByText(/KEV only/i));
    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      expect(calls[calls.length - 1][0]).toContain('kev_only=true');
    });

    fireEvent.click(screen.getByText(/KEV only/i));
    await waitFor(() => {
      const calls = global.fetch.mock.calls.filter(([url]) => url.includes('/runzero/matches'));
      expect(calls[calls.length - 1][0]).not.toContain('kev_only');
    });
  });
});
