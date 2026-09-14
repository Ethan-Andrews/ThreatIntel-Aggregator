import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import RunZeroMetricsPanel from '../RunZeroMetricsPanel';

function jsonResponse(data) {
  return Promise.resolve({ ok: true, json: async () => data });
}

const METRICS = {
  intake_by_day: [
    { org: 'OrgA', date: '2026-01-01T00:00:00Z', count: 3 },
    { org: 'OrgB', date: '2026-01-02T00:00:00Z', count: 1 },
  ],
  remediated_by_day: [
    { org: 'OrgA', date: '2026-01-03T00:00:00Z', count: 2 },
  ],
  standing: [
    { org: 'OrgA', total_intake: 3, still_standing: 1, remediated: 2 },
    { org: 'OrgB', total_intake: 1, still_standing: 1, remediated: 0 },
  ],
};

describe('RunZeroMetricsPanel', () => {
  test('renders the scope-honesty copy and accumulative totals', async () => {
    global.fetch = jest.fn(() => jsonResponse(METRICS));
    render(<RunZeroMetricsPanel apiKey="key" />);

    expect(await screen.findByText(/tracked exposures/i)).toBeInTheDocument();
    await screen.findByText('OrgA');
    expect(screen.getByText('4 tracked in window')).toBeInTheDocument();
    expect(screen.getByText('2 still standing')).toBeInTheDocument();
    expect(screen.getByText('2 remediated')).toBeInTheDocument();
  });

  test('org filter scopes the accumulative totals', async () => {
    global.fetch = jest.fn(() => jsonResponse(METRICS));
    render(<RunZeroMetricsPanel apiKey="key" />);
    await screen.findByText('OrgA');

    fireEvent.click(screen.getByText('OrgA'));
    expect(screen.getByText('3 tracked in window')).toBeInTheDocument();
    expect(screen.getByText('1 still standing')).toBeInTheDocument();
  });

  test('does not crash on an unexpected/empty API response shape', async () => {
    global.fetch = jest.fn(() => jsonResponse({}));
    render(<RunZeroMetricsPanel apiKey="key" />);
    expect(await screen.findByText(/No tracked exposures in this window/i)).toBeInTheDocument();
  });

  test('changing the time-range toggle re-fetches with the new window', async () => {
    global.fetch = jest.fn(() => jsonResponse(METRICS));
    render(<RunZeroMetricsPanel apiKey="key" />);
    await screen.findByText('OrgA');

    fireEvent.click(screen.getByText('7D'));
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('window=7d'),
        expect.anything(),
      );
    });
  });
});
