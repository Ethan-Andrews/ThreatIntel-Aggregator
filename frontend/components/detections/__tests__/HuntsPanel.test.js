import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import HuntsPanel from '../HuntsPanel';

function mockAuthFetch(listData, detailData) {
  return jest.fn((url) => {
    if (/\/api\/detections\/hunts\/\d+/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => detailData });
    }
    return Promise.resolve({ ok: true, json: async () => listData });
  });
}

const BASE_HUNT = {
  id: 1,
  title: 'BTR Reforged',
  description: 'APT campaign writeup',
  source_title: 'BTR Reforged: A New Campaign',
  source_link: 'https://example.com/article',
  source_name: 'Some Feed',
  source_severity: 'High',
  sentinel_hunt_id: null,
  sentinel_synced_at: null,
  created_at: '2026-08-31T00:00:00Z',
  detection_count: 2,
  techniques: [
    { technique_id: 'T1053.005', technique_name: 'Scheduled Task' },
    { technique_id: 'T1059.001', technique_name: 'PowerShell' },
  ],
  review_state_counts: { approved: 1, pending: 1 },
  eligible_count: 1,
};

const BASE_DETAIL = {
  ...BASE_HUNT,
  detections: [
    {
      id: 10, strategy_id: 1, technique_id: 'T1053.005', technique_name: 'Scheduled Task',
      objective: 'Detect scheduled task creation', artifact_id: 'art-1',
      name: 'Suspicious Scheduled Task Creation',
      description: 'Flags schtasks.exe creating a new scheduled task.',
      kql_body: "DeviceProcessEvents | where FileName == 'schtasks.exe'",
      static_gate_verdict: 'pass', static_gate_durability: 0.9,
      backtest_disposition: 'clean', review_state: 'approved',
      created_at: '2026-08-31T00:00:00Z',
    },
    {
      id: 11, strategy_id: 2, technique_id: 'T1059.001', technique_name: 'PowerShell',
      objective: 'Detect suspicious PowerShell', artifact_id: 'art-2',
      name: 'Encoded PowerShell Command',
      description: 'Flags base64-encoded PowerShell execution.',
      kql_body: "DeviceProcessEvents | where ProcessCommandLine has '-enc'",
      static_gate_verdict: 'pass', static_gate_durability: 0.8,
      backtest_disposition: null, review_state: 'pending',
      created_at: '2026-08-31T00:00:00Z',
    },
  ],
};

describe('HuntsPanel', () => {
  test('lists hunts by title with rollup info, not individual detections', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('BTR Reforged')).toBeInTheDocument();
    });
    expect(screen.getByText(/2 detections/i)).toBeInTheDocument();
    expect(screen.getByText(/T1053\.005/)).toBeInTheDocument();
    expect(screen.getByText(/T1059\.001/)).toBeInTheDocument();
    // The detail-only content must not be present yet.
    expect(screen.queryByText('Suspicious Scheduled Task Creation')).not.toBeInTheDocument();
  });

  test('shows an empty state when there are no hunts', async () => {
    const authFetch = mockAuthFetch({ items: [], total: 0 }, null);
    render(<HuntsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText(/No hunts/i)).toBeInTheDocument();
    });
  });

  test('clicking a hunt drills into its detail view with full child detections', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.click(screen.getByText('BTR Reforged'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/detections/hunts/1'));
    });
    expect(await screen.findByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
    expect(screen.getByText('Encoded PowerShell Command')).toBeInTheDocument();
    expect(screen.getByText(BASE_DETAIL.detections[0].kql_body)).toBeInTheDocument();
  });

  test('detail view has a way back to the hunts list', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    fireEvent.click(screen.getByText(/Back to hunts/i));

    await waitFor(() => {
      expect(screen.queryByText('Suspicious Scheduled Task Creation')).not.toBeInTheDocument();
    });
    expect(screen.getByText('BTR Reforged')).toBeInTheDocument();
  });

  test('filters by technique id', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.change(screen.getByPlaceholderText(/Technique ID/i), { target: { value: 'T1053' } });
    fireEvent.click(screen.getByText('Filter'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('technique_id=T1053'));
    });
  });

  test('filters by hunt name', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.change(screen.getByPlaceholderText(/Hunt name/i), { target: { value: 'Reforged' } });
    fireEvent.click(screen.getByText('Filter'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('search=Reforged'));
    });
  });

  test('shows a ready-to-deploy badge when a hunt has eligible detections', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);

    await waitFor(() => screen.getByText('BTR Reforged'));

    expect(screen.getByText(/1 ready to deploy/i)).toBeInTheDocument();
  });

  test('toggling "Ready to deploy only" refetches with ready_only=true', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.click(screen.getByLabelText(/Ready to deploy only/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('ready_only=true'));
    });
  });

  test('does not show a Deploy button to a non-admin viewer', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    expect(screen.queryByText(/Deploy to Sentinel/i)).not.toBeInTheDocument();
  });

  test('an admin can deploy a hunt to Sentinel, and the badge updates on success', async () => {
    const syncedDetail = { ...BASE_DETAIL, sentinel_hunt_id: 'hunt-abc', sentinel_synced_at: '2026-08-31T01:00:00Z' };
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => syncedDetail });
      }
      if (/\/api\/detections\/hunts\/\d+/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => BASE_DETAIL });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');
    expect(screen.getByText(/NOT SYNCED/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText(/^Deploy to Sentinel$/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/detections/hunts/1/deploy'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/SYNCED TO SENTINEL/i)).toBeInTheDocument();
  });

  test('shows the server-provided error message when deploy fails', async () => {
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST') {
        return Promise.resolve({
          ok: false,
          json: async () => ({ detail: 'Hunt Sentinel sync is off -- enable manual or auto mode in Settings first.' }),
        });
      }
      if (/\/api\/detections\/hunts\/\d+/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => BASE_DETAIL });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    fireEvent.click(screen.getByText(/^Deploy to Sentinel$/i));

    expect(await screen.findByText(/enable manual or auto mode/i)).toBeInTheDocument();
  });

  test('an admin sees the deploy-target picker populated with existing Sentinel Hunts', async () => {
    const authFetch = jest.fn((url) => {
      if (url.includes('/sentinel-targets')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            enabled: true,
            hunts: [{ id: 'guid-1', display_name: 'In the News V2' }],
            error: null,
          }),
        });
      }
      if (/\/api\/detections\/hunts\/\d+/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => BASE_DETAIL });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    expect(await screen.findByText('Create new Sentinel Hunt')).toBeInTheDocument();
    expect(screen.getByText('In the News V2')).toBeInTheDocument();
  });

  test('a non-admin viewer never sees the deploy-target picker', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    expect(screen.queryByText('Deploy target')).not.toBeInTheDocument();
    expect(authFetch).not.toHaveBeenCalledWith(expect.stringContaining('/sentinel-targets'));
  });

  test('picking an existing Sentinel Hunt as the deploy target persists it via PATCH', async () => {
    const updatedDetail = { ...BASE_DETAIL, target_sentinel_hunt_id: 'guid-1' };
    const authFetch = jest.fn((url, options) => {
      if (url.includes('/sentinel-targets')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            enabled: true,
            hunts: [{ id: 'guid-1', display_name: 'In the News V2' }],
            error: null,
          }),
        });
      }
      if (options && options.method === 'PATCH') {
        return Promise.resolve({ ok: true, json: async () => updatedDetail });
      }
      if (/\/api\/detections\/hunts\/\d+/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => BASE_DETAIL });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');
    await screen.findByText('In the News V2');

    fireEvent.change(screen.getByDisplayValue('Create new Sentinel Hunt'), { target: { value: 'guid-1' } });

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/detections/hunts/1/target'),
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify({ target_sentinel_hunt_id: 'guid-1' }),
        }),
      );
    });
    expect(await screen.findByDisplayValue('In the News V2')).toBeInTheDocument();
  });

  test('does not show a Deploy All button to a non-admin viewer', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, BASE_DETAIL);
    render(<HuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    expect(screen.queryByText('Deploy All')).not.toBeInTheDocument();
  });

  test('an admin can Deploy All and see a succeeded/failed summary with the failure reason listed', async () => {
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && url.includes('/deploy-all')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            enabled: true, total: 2, succeeded: 1,
            failed: [{ hunt_id: 5, reason: '500 Internal Server Error' }],
          }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.click(screen.getByText('Deploy All'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/detections/hunts/deploy-all'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/1 succeeded, 1 failed/i)).toBeInTheDocument();
    expect(screen.getByText(/hunt #5: 500 Internal Server Error/i)).toBeInTheDocument();
  });

  test('Deploy All shows a plain message when sync is not enabled', async () => {
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && url.includes('/deploy-all')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ enabled: false, total: 0, succeeded: 0, failed: [] }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.click(screen.getByText('Deploy All'));

    expect(await screen.findByText(/Sentinel sync isn.t enabled yet/i)).toBeInTheDocument();
  });

  test('shows the server-provided error message when Deploy All fails outright', async () => {
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && url.includes('/deploy-all')) {
        return Promise.resolve({
          ok: false,
          json: async () => ({ detail: 'Hunt Sentinel sync is off -- enable manual or auto mode in Settings first.' }),
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));

    fireEvent.click(screen.getByText('Deploy All'));

    expect(await screen.findByText(/enable manual or auto mode/i)).toBeInTheDocument();
  });
});

describe('HuntsPanel tuning suggestions', () => {
  const DETAIL_WITH_SUGGESTION = {
    ...BASE_DETAIL,
    detections: [
      {
        ...BASE_DETAIL.detections[0],
        tuning_suggestion: {
          disposition: 'tuned',
          pending: true,
          final_body: "DeviceProcessEvents | where AccountName != @\"bob\"",
          action: null, performed_by: null, performed_at: null,
        },
      },
      { ...BASE_DETAIL.detections[1], tuning_suggestion: null },
    ],
  };

  test('shows the tuning suggestion badge on a hunt detection card', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, DETAIL_WITH_SUGGESTION);
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText('Suspicious Scheduled Task Creation');

    expect(screen.getByText(/TUNING SUGGESTION AVAILABLE/i)).toBeInTheDocument();
  });

  test('a non-admin viewer never sees the checkbox or bulk action bar', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_HUNT], total: 1 }, DETAIL_WITH_SUGGESTION);
    render(<HuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/Push .* to Sentinel/i)).not.toBeInTheDocument();
  });

  test('selecting a detection and pushing calls the apply endpoint and refreshes the hunt', async () => {
    const authFetch = jest.fn((url, opts) => {
      if (url.includes('/tuning-suggestions/apply')) {
        return Promise.resolve({ ok: true, json: async () => ({ results: [{ analytic_id: 10, success: true, reason: null }] }) });
      }
      if (/\/api\/detections\/hunts\/\d+/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => DETAIL_WITH_SUGGESTION });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<HuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('BTR Reforged'));
    fireEvent.click(screen.getByText('BTR Reforged'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(await screen.findByText(/Push 1 update to Sentinel/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/tuning-suggestions/apply'),
        expect.objectContaining({ method: 'POST', body: JSON.stringify({ analytic_ids: [10] }) }),
      );
    });
    // Refreshes the hunt detail after a successful push.
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/detections/hunts/1'));
    });
  });
});
