import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import ExposurePanel from '../ExposurePanel';

const ORG_SUMMARY = {
  org: 'Acme Corp', total: 3, active: 1, acknowledged: 1, remediated: 1,
};

const ORG_CORRELATION = {
  org: 'Acme Corp', confirmed: 2, possible: 1, critical: 1, high: 1, medium: 1, low: 0,
};

const ACTIVE_ITEM = {
  id: 1, asset_id: 'host-1', hostname: 'web-01.acme.local', site: 'DMZ', os: 'Ubuntu',
  entry_hash: 'cve-1', title: 'Critical RCE (CVE-1)', severity: 'Critical',
  confidence: 'confirmed', match_type: 'cpe', link: 'https://nvd.nist.gov/vuln/detail/CVE-1',
  ai_summary: 'A critical remote code execution flaw.', status: 'active', notes: '',
  assigned_to: null, first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-09-01T00:00:00Z',
  remediated_at: null,
};

const ACK_ITEM = {
  ...ACTIVE_ITEM, id: 2, asset_id: 'host-2', hostname: 'web-02.acme.local',
  status: 'acknowledged', assigned_to: 'Jamie Smith',
};

const REMEDIATED_ITEM = {
  ...ACTIVE_ITEM, id: 3, asset_id: 'host-3', hostname: 'db-01.acme.local',
  entry_hash: 'cve-2', title: 'High severity SQLi (CVE-2)', severity: 'High',
  status: 'remediated', remediated_at: '2026-09-01T00:00:00Z',
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

function baseRoutes(overrides = []) {
  return [
    ...overrides,
    ['/api/exposure/summary', () => jsonResponse({ orgs: [ORG_SUMMARY] })],
    ['/api/integrations/runzero/exposure', () => jsonResponse({ orgs: [ORG_CORRELATION] })],
    ['/api/users/names', () => jsonResponse({ names: ['Jamie Smith', 'Taylor Lee'] })],
    [/\/api\/exposure\/items\?org=/, (url) => {
      const items = url.includes('status=remediated') ? [REMEDIATED_ITEM] : [ACTIVE_ITEM, ACK_ITEM];
      return jsonResponse({ total: items.length, items });
    }],
    [/\/api\/exposure\/items\/\d+\/audit/, () => jsonResponse({ log: [] })],
  ];
}

afterEach(() => jest.restoreAllMocks());

describe('ExposurePanel', () => {
  test('renders both the remediation progress and the correlation severity breakdown', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<ExposurePanel apiKey="test-token" />);

    expect(await screen.findByText('Acme Corp')).toBeInTheDocument();
    expect(screen.getByText(/1\/3 remediated/)).toBeInTheDocument();
    expect(screen.getByText('2 CONFIRMED')).toBeInTheDocument();
    expect(screen.getByText('1 POSSIBLE')).toBeInTheDocument();
  });

  test('shows an empty state when there are no exposure items', async () => {
    global.fetch = mockFetchRouter([
      ['/api/exposure/summary', () => jsonResponse({ orgs: [] })],
      ['/api/integrations/runzero/exposure', () => jsonResponse({ orgs: [] })],
      ['/api/users/names', () => jsonResponse({ names: [] })],
    ]);
    render(<ExposurePanel apiKey="test-token" />);
    expect(await screen.findByText(/No exposure items yet/i)).toBeInTheDocument();
  });

  test('shows an error state when the summary fetch fails', async () => {
    global.fetch = mockFetchRouter([
      ['/api/exposure/summary', () => jsonResponse({}, false)],
      ['/api/integrations/runzero/exposure', () => jsonResponse({ orgs: [] })],
      ['/api/users/names', () => jsonResponse({ names: [] })],
    ]);
    render(<ExposurePanel apiKey="test-token" />);
    expect(await screen.findByText(/Failed to load exposure data/i)).toBeInTheDocument();
  });

  test('expanding an org card groups items by vulnerability, not by asset', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<ExposurePanel apiKey="test-token" />);
    fireEvent.click(await screen.findByText('Acme Corp'));

    // One card for CVE-1, even though it has 2 affected assets underneath.
    expect(await screen.findByText('Critical RCE (CVE-1)')).toBeInTheDocument();
    expect(screen.getByText('2 assets')).toBeInTheDocument();
    expect(screen.getByText('web-01.acme.local')).toBeInTheDocument();
    expect(screen.getByText('web-02.acme.local')).toBeInTheDocument();
  });

  test('Acknowledge PATCHes every non-remediated asset in the group and refreshes the summary', async () => {
    const patched = [];
    global.fetch = mockFetchRouter(baseRoutes([
      [/\/api\/exposure\/items\/\d+$/, (url, opts) => {
        patched.push(JSON.parse(opts.body));
        return jsonResponse({ ...ACTIVE_ITEM, id: Number(url.match(/items\/(\d+)/)[1]), status: 'acknowledged' });
      }],
    ]));
    render(<ExposurePanel apiKey="test-token" />);
    fireEvent.click(await screen.findByText('Acme Corp'));
    await screen.findByText('Critical RCE (CVE-1)');

    fireEvent.click(screen.getByText('Acknowledge'));

    await waitFor(() => {
      // Only the still-active asset (id 1) gets PATCHed -- id 2 is already acknowledged.
      expect(patched).toEqual([{ status: 'acknowledged' }]);
    });
    // onSummaryRefresh re-fetches /api/exposure/summary -- called at least twice total (initial + refresh).
    const summaryCalls = global.fetch.mock.calls.filter(([url]) => url.includes('/api/exposure/summary'));
    expect(summaryCalls.length).toBeGreaterThanOrEqual(2);
  });

  test('assigning a group PATCHes assigned_to for every non-remediated asset', async () => {
    const patched = [];
    global.fetch = mockFetchRouter(baseRoutes([
      [/\/api\/exposure\/items\/\d+$/, (url, opts) => {
        patched.push(JSON.parse(opts.body));
        return jsonResponse({ ...ACTIVE_ITEM, id: Number(url.match(/items\/(\d+)/)[1]) });
      }],
    ]));
    render(<ExposurePanel apiKey="test-token" />);
    fireEvent.click(await screen.findByText('Acme Corp'));
    await screen.findByText('Critical RCE (CVE-1)');

    fireEvent.change(screen.getByDisplayValue('Unassigned'), { target: { value: 'Taylor Lee' } });

    await waitFor(() => {
      expect(patched).toEqual([{ assigned_to: 'Taylor Lee' }]);
    });
  });

  test('Show activity fetches and merges the audit log across the group\'s assets', async () => {
    global.fetch = mockFetchRouter(baseRoutes([
      [/\/api\/exposure\/items\/1\/audit/, () => jsonResponse({
        log: [{ created_at: '2026-09-01T10:00:00Z', actor: 'Jamie Smith', action: 'note_added', detail: 'Investigating.' }],
      })],
    ]));
    render(<ExposurePanel apiKey="test-token" />);
    fireEvent.click(await screen.findByText('Acme Corp'));
    await screen.findByText('Critical RCE (CVE-1)');

    fireEvent.click(screen.getByText('Show activity'));

    expect(await screen.findByText('Investigating.')).toBeInTheDocument();
    expect(screen.getByText('Hide activity')).toBeInTheDocument();
  });

  test('the Remediated tab fetches and shows only remediated items', async () => {
    global.fetch = mockFetchRouter(baseRoutes());
    render(<ExposurePanel apiKey="test-token" />);
    fireEvent.click(await screen.findByText('Acme Corp'));
    await screen.findByText('Critical RCE (CVE-1)');

    fireEvent.click(screen.getByText(/Remediated \(1\)/i));

    expect(await screen.findByText('High severity SQLi (CVE-2)')).toBeInTheDocument();
    expect(screen.queryByText('Critical RCE (CVE-1)')).not.toBeInTheDocument();
    // A remediated group has no group-level Acknowledge/Assign/Note controls.
    expect(screen.queryByText('Acknowledge')).not.toBeInTheDocument();
  });
});
