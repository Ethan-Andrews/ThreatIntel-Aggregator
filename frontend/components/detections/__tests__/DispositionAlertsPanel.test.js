import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DispositionAlertsPanel from '../DispositionAlertsPanel';

function mockAuthFetch(data) {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: async () => data,
  });
}

const BASE_ALERT = {
  id: 1,
  analytic_id: 5,
  technique_id: 'T1053.005',
  technique_name: 'Scheduled Task/Job: Scheduled Task',
  name: 'Suspicious Scheduled Task Creation',
  description: 'Flags schtasks.exe creating a new scheduled task.',
  kql_body: "DeviceProcessEvents | where FileName == 'schtasks.exe'",
  checked_at: '2026-08-30T00:00:00Z',
  hits: 12,
  window_hours: 24,
  control_probe_disposition: 'ok',
  backtest_disposition: 'clean',
  outcome: 'now_firing',
  detail: {},
};

describe('DispositionAlertsPanel', () => {
  test('shows the detection name so an analyst can triage without a separate lookup', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ALERT], total: 1 });
    render(<DispositionAlertsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
    });
    expect(screen.getByText(/T1053\.005/)).toBeInTheDocument();
  });

  test('falls back to a clear label when the alert predates the name migration', async () => {
    const authFetch = mockAuthFetch({
      items: [{ ...BASE_ALERT, name: null, description: null, kql_body: null }],
      total: 1,
    });
    render(<DispositionAlertsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText(/Unnamed/i)).toBeInTheDocument();
    });
  });

  test('shows a human-readable detection type badge, including Hunt', async () => {
    const authFetch = mockAuthFetch({ items: [{ ...BASE_ALERT, detection_type: 'hunt' }], total: 1 });
    render(<DispositionAlertsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getAllByText('Hunt').length).toBeGreaterThan(0);
    });
  });

  test('selecting a detection type requests that type from the API', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ALERT], total: 1 });
    render(<DispositionAlertsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    fireEvent.change(screen.getByDisplayValue('All types'), { target: { value: 'sentinel' } });

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('detection_type=sentinel'));
    });
  });
});
