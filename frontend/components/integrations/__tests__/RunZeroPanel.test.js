import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import RunZeroPanel from '../RunZeroPanel';

function jsonResponse(data) {
  return Promise.resolve({ ok: true, json: async () => data });
}

beforeEach(() => {
  global.fetch = jest.fn((url) => {
    if (url.includes('/api/integrations/runzero/status')) {
      return jsonResponse({ configured: true, status: 'ok', last_sync: null, asset_count: 0, org_count: 0, vuln_count: 0, confirmed_matches: 0, possible_matches: 0 });
    }
    if (url.includes('/api/integrations/runzero/matches')) {
      return jsonResponse({ total: 0, matches: [] });
    }
    if (url.includes('/api/integrations/runzero/exposure')) {
      return jsonResponse({ orgs: [] });
    }
    if (url.includes('/api/exposure/metrics')) {
      return jsonResponse({ intake_by_day: [], remediated_by_day: [], standing: [] });
    }
    return jsonResponse({});
  });
});

describe('RunZeroPanel', () => {
  test('defaults to the Matches sub-tab and can switch to Exposure', async () => {
    render(<RunZeroPanel apiKey="key" userRole="admin" />);

    await waitFor(() => screen.getByText('MATCHES'));
    expect(screen.getByText('EXPOSURE')).toBeInTheDocument();

    fireEvent.click(screen.getByText('EXPOSURE'));
    await waitFor(() => expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/integrations/runzero/exposure'),
      expect.anything(),
    ));
  });

  test('can switch to the Metrics sub-tab', async () => {
    render(<RunZeroPanel apiKey="key" userRole="admin" />);
    await waitFor(() => screen.getByText('MATCHES'));
    expect(screen.getByText('METRICS')).toBeInTheDocument();

    fireEvent.click(screen.getByText('METRICS'));
    await waitFor(() => expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/exposure/metrics'),
      expect.anything(),
    ));
  });
});
