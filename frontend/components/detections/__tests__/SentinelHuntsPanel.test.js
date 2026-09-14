import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import SentinelHuntsPanel from '../SentinelHuntsPanel';

const BASE_HUNT = {
  id: 1,
  sentinel_hunt_id: 'hunt-arm-1',
  display_name: 'Suspicious Process Chains',
  description: 'A real Sentinel hunt with a lot of queries.',
  status: 'Active',
  hypothesis_status: 'Unknown',
  attack_tactics: ['Execution'],
  attack_techniques: ['T1059'],
  query_count: 812,
  review_state_counts: { pending: 800, approved: 12 },
  tunable_count: 0,
  synced_at: '2026-09-01T00:00:00Z',
  created_at: '2026-09-01T00:00:00Z',
};

const QUERY_ROW = {
  id: 100,
  hunt_id: 1,
  sentinel_saved_search_id: 'q-1',
  display_name: 'Suspicious child process',
  description: 'flags rare child processes',
  review_state: 'pending',
  backtest_disposition: null,
  last_tested_at: null,
  created_at: '2026-09-01T00:00:00Z',
};

const QUERY_DETAIL = {
  ...QUERY_ROW,
  kql_body: 'DeviceProcessEvents | take 1',
  tags: [],
  control_probe_result: null,
  tune_history: null,
};

function mockAuthFetch({ huntList, queryList, queryDetail, sync } = {}) {
  return jest.fn((url, options) => {
    if (options && options.method === 'POST' && url.includes('/sync')) {
      return Promise.resolve({ ok: true, json: async () => sync || { enabled: false, hunts_synced: 0, queries_synced: 0, errors: [] } });
    }
    if (options && options.method === 'POST' && /\/queries\/\d+\/test/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ ...QUERY_DETAIL, backtest_disposition: 'needs_tuning', control_probe_result: { gate_verdict: 'pass', disposition: 'ok' } }) });
    }
    if (options && options.method === 'POST' && /\/queries\/\d+\/tune/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ ...QUERY_DETAIL, tune_history: { disposition: 'tuned' } }) });
    }
    if (options && options.method === 'PATCH' && /\/queries\/\d+\/review/.test(url)) {
      const body = JSON.parse(options.body);
      return Promise.resolve({ ok: true, json: async () => ({ ...QUERY_DETAIL, review_state: body.review_state }) });
    }
    if (/\/api\/sentinel-hunts\/queries\/\d+$/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => queryDetail || QUERY_DETAIL });
    }
    if (/\/api\/sentinel-hunts\/\d+\/queries/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => queryList || { items: [QUERY_ROW], total: 1 } });
    }
    return Promise.resolve({ ok: true, json: async () => huntList || { items: [BASE_HUNT], total: 1 } });
  });
}

describe('SentinelHuntsPanel', () => {
  test('lists Sentinel hunts by display name with rollup, not individual queries', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious Process Chains')).toBeInTheDocument();
    });
    expect(screen.getByText(/812 queries/i)).toBeInTheDocument();
    expect(screen.getByText(/800 pending/i)).toBeInTheDocument();
    expect(screen.queryByText('Suspicious child process')).not.toBeInTheDocument();
  });

  test('shows a tunable-count badge next to the status badge when a hunt has tunable queries', async () => {
    const authFetch = mockAuthFetch({ huntList: { items: [{ ...BASE_HUNT, tunable_count: 3 }], total: 1 } });
    render(<SentinelHuntsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('3 tunable')).toBeInTheDocument();
    });
  });

  test('hides the tunable-count badge when nothing in the hunt is tunable', async () => {
    const authFetch = mockAuthFetch({ huntList: { items: [{ ...BASE_HUNT, tunable_count: 0 }], total: 1 } });
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    expect(screen.queryByText(/tunable/i)).not.toBeInTheDocument();
  });

  test('shows an empty state when there are no synced hunts', async () => {
    const authFetch = mockAuthFetch({ huntList: { items: [], total: 0 } });
    render(<SentinelHuntsPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText(/No Sentinel hunts synced yet/i)).toBeInTheDocument();
    });
  });

  test('hunt list is paginated', async () => {
    const authFetch = mockAuthFetch({ huntList: { items: [BASE_HUNT], total: 100 } });
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    expect(screen.getByText(/1–24 of 100/)).toBeInTheDocument();
    fireEvent.click(screen.getByText('Next'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('offset=24'));
    });
  });

  test('clicking a hunt drills into its paginated query list', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    fireEvent.click(screen.getByText('Suspicious Process Chains'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/sentinel-hunts/1/queries'));
    });
    expect(await screen.findByText('Suspicious child process')).toBeInTheDocument();
    // The query LIST view must not eagerly show the KQL body -- 800+ rows
    // of full bodies would be exactly the scale problem this pagination
    // exists to avoid.
    expect(screen.queryByText('DeviceProcessEvents | take 1')).not.toBeInTheDocument();
  });

  test('query list within a hunt is independently paginated from the hunt list', async () => {
    const authFetch = mockAuthFetch({ queryList: { items: [QUERY_ROW], total: 812 } });
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    expect(screen.getByText(/QUERIES IN THIS HUNT \(812\)/i)).toBeInTheDocument();
    fireEvent.click(screen.getByText('Next'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('/api/sentinel-hunts/1/queries?limit=25&offset=25'));
    });
  });

  test('has a way back from the query list to the hunt list', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    fireEvent.click(screen.getByText(/Back to Sentinel hunts/i));

    await waitFor(() => {
      expect(screen.queryByText('Suspicious child process')).not.toBeInTheDocument();
    });
    expect(screen.getByText('Suspicious Process Chains')).toBeInTheDocument();
  });

  test('expanding a query row fetches and shows its full KQL body', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    fireEvent.click(screen.getByText('Suspicious child process'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/sentinel-hunts/queries/100'));
    });
    expect(await screen.findByText('DeviceProcessEvents | take 1')).toBeInTheDocument();
  });

  test('does not show admin actions to a non-admin viewer', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    expect(screen.queryByText('Sync now')).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText('DeviceProcessEvents | take 1');

    expect(screen.queryByText('Test')).not.toBeInTheDocument();
    expect(screen.queryByText('Tune')).not.toBeInTheDocument();
  });

  test('an admin can sync, test, and review a query', async () => {
    const authFetch = mockAuthFetch({
      sync: { enabled: true, hunts_synced: 1, queries_synced: 812, errors: [] },
    });
    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    fireEvent.click(screen.getByText('Sync now'));
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-hunts/sync'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/Synced 1 hunt, 812 queries/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText('DeviceProcessEvents | take 1');
  });

  test('sync banner surfaces removed counts and skipped-sweep hunts, never as a clean success', async () => {
    const authFetch = mockAuthFetch({
      sync: {
        enabled: true, hunts_synced: 2, queries_synced: 5, errors: ['hunt-a: relations fetch failed: 500'],
        hunts_removed: 1, queries_removed: 3, sweep_skipped_hunts: ['hunt-a'],
      },
    });
    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    fireEvent.click(screen.getByText('Sync now'));
    expect(await screen.findByText(/Removed 1 hunt and 3 queries no longer in Sentinel/i)).toBeInTheDocument();
    expect(await screen.findByText(/1 hunt skipped this sweep \(fetch error\)/i)).toBeInTheDocument();
  });

  test('a slow-to-arrive Test response cannot clobber a fresher, later response', async () => {
    // Regression test: confirmed live 2026-09-01 -- a Test result (fresh
    // last_tested_at, persisted and returned by POST .../test) was visible
    // in the UI, then re-expanding the row showed an OLDER last_tested_at,
    // meaning a request that was IN FLIGHT before the fresher one arrived
    // was allowed to overwrite it once it finally resolved. Simulate: Test
    // is clicked and its response is held open (slowTest); before it
    // resolves, the row is collapsed and re-expanded, which fetches a
    // detail view that's already newer (as the real DB row would be, since
    // nothing else has raced past it). The late-arriving Test response must
    // not un-do that newer state once it finally resolves.
    let resolveSlowTest;
    const slowTest = new Promise((resolve) => { resolveSlowTest = resolve; });
    const staleDetail = { ...QUERY_DETAIL, last_tested_at: '2026-09-01T20:35:18.161063+00:00' };
    const freshDetail = {
      ...QUERY_DETAIL,
      last_tested_at: '2026-09-01T20:36:37.990606+00:00',
      control_probe_result: { gate_verdict: 'pass', disposition: 'ok' },
      backtest_disposition: 'clean',
    };

    let getCallCount = 0;
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && /\/queries\/\d+\/test/.test(url)) {
        return slowTest.then(() => ({ ok: true, json: async () => staleDetail }));
      }
      if (/\/api\/sentinel-hunts\/queries\/\d+$/.test(url)) {
        getCallCount += 1;
        // First expand loads a plain detail (pre-test); the re-expand
        // after Test was clicked reflects a newer view of the same row.
        const data = getCallCount === 1 ? QUERY_DETAIL : freshDetail;
        return Promise.resolve({ ok: true, json: async () => data });
      }
      if (/\/api\/sentinel-hunts\/\d+\/queries/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => ({ items: [QUERY_ROW], total: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });

    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    // Expand the row so the Test button is available, then click Test --
    // its response is held pending via slowTest.
    fireEvent.click(screen.getByText('Suspicious child process'));
    fireEvent.click(await screen.findByText('Test'));

    // Collapse and re-expand while Test is still in flight -- this fetch
    // resolves immediately with the newer view.
    fireEvent.click(screen.getByText('Suspicious child process'));
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText(/CLEAN/i);

    // The delayed Test response now finally arrives -- it must be discarded,
    // not allowed to overwrite the newer state already shown. Flush
    // microtasks by waiting on something that would only be true post-flush.
    await act(async () => {
      resolveSlowTest();
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(screen.getByText(/CLEAN/i)).toBeInTheDocument();
  });

  test('a tuning suggestion shows Apply/Dismiss controls, and Apply pushes it to Sentinel', async () => {
    const tunedDetail = {
      ...QUERY_DETAIL,
      backtest_disposition: 'needs_tuning',
      tune_history: { disposition: 'tuned', final_body: 'DeviceProcessEvents | take 1 | where X != 1' },
      tuning_suggestion: {
        disposition: 'tuned', pending: true,
        final_body: 'DeviceProcessEvents | take 1 | where X != 1',
        action: null, performed_by: null, performed_at: null, error: null,
      },
    };
    const appliedDetail = {
      ...tunedDetail,
      tuning_suggestion: { ...tunedDetail.tuning_suggestion, pending: false, action: 'applied', performed_by: 'admin' },
    };
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && /tuning-suggestion\/apply/.test(url)) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ result: { query_id: 100, success: true, reason: null }, query: appliedDetail }),
        });
      }
      if (/\/api\/sentinel-hunts\/queries\/\d+$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => tunedDetail });
      }
      if (/\/api\/sentinel-hunts\/\d+\/queries/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => ({ items: [QUERY_ROW], total: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });

    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByText('Apply'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-hunts/queries/100/tuning-suggestion/apply'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/TUNING APPLIED/i)).toBeInTheDocument();
  });

  test('Dismiss records the decision without pushing to Sentinel', async () => {
    const tunedDetail = {
      ...QUERY_DETAIL,
      backtest_disposition: 'needs_tuning',
      tune_history: { disposition: 'tuned', final_body: 'DeviceProcessEvents | take 1 | where X != 1' },
      tuning_suggestion: {
        disposition: 'tuned', pending: true,
        final_body: 'DeviceProcessEvents | take 1 | where X != 1',
        action: null, performed_by: null, performed_at: null, error: null,
      },
    };
    const dismissedDetail = {
      ...tunedDetail,
      tuning_suggestion: { ...tunedDetail.tuning_suggestion, pending: false, action: 'dismissed', performed_by: 'admin' },
    };
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && /tuning-suggestion\/dismiss/.test(url)) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ result: { query_id: 100, success: true, reason: null }, query: dismissedDetail }),
        });
      }
      if (/\/api\/sentinel-hunts\/queries\/\d+$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => tunedDetail });
      }
      if (/\/api\/sentinel-hunts\/\d+\/queries/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => ({ items: [QUERY_ROW], total: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });

    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByText('Dismiss'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-hunts/queries/100/tuning-suggestion/dismiss'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/TUNING DISMISSED/i)).toBeInTheDocument();
  });

  test('a non-admin viewer never sees Apply/Dismiss controls on a tuning suggestion', async () => {
    const tunedDetail = {
      ...QUERY_DETAIL,
      tune_history: { disposition: 'tuned', final_body: 'DeviceProcessEvents | take 1 | where X != 1' },
      tuning_suggestion: {
        disposition: 'tuned', pending: true,
        final_body: 'DeviceProcessEvents | take 1 | where X != 1',
        action: null, performed_by: null, performed_at: null, error: null,
      },
    };
    const authFetch = jest.fn((url) => {
      if (/\/api\/sentinel-hunts\/queries\/\d+$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => tunedDetail });
      }
      if (/\/api\/sentinel-hunts\/\d+\/queries/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => ({ items: [QUERY_ROW], total: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });

    render(<SentinelHuntsPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');
    fireEvent.click(screen.getByText('Suspicious child process'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    expect(screen.queryByText('Apply')).not.toBeInTheDocument();
    expect(screen.queryByText('Dismiss')).not.toBeInTheDocument();
  });

  test('submitting the hunt search box re-fetches hunts with the search query param', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    fireEvent.change(screen.getByPlaceholderText(/Search hunt names/i), { target: { value: 'process' } });
    fireEvent.click(screen.getByText('Search'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('search=process'));
    });
  });

  test('checking "Needs tuning only" within a hunt re-fetches queries with disposition=needs_tuning', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    fireEvent.click(screen.getByLabelText(/Needs tuning only/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('disposition=needs_tuning'));
    });
  });

  test('submitting the query search box within a hunt re-fetches with the search query param', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelHuntsPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));
    fireEvent.click(screen.getByText('Suspicious Process Chains'));
    await screen.findByText('Suspicious child process');

    fireEvent.change(screen.getByPlaceholderText(/Search query names/i), { target: { value: 'child' } });
    fireEvent.click(screen.getByText('Search'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('search=child'));
    });
  });

  test('shows the server error message when a sync fails', async () => {
    const authFetch = jest.fn((url, options) => {
      if (options && options.method === 'POST' && url.includes('/sync')) {
        return Promise.resolve({ ok: false, json: async () => ({ detail: 'missing AZURE_SUBSCRIPTION_ID' }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [BASE_HUNT], total: 1 }) });
    });
    render(<SentinelHuntsPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Process Chains'));

    fireEvent.click(screen.getByText('Sync now'));

    expect(await screen.findByText(/missing AZURE_SUBSCRIPTION_ID/i)).toBeInTheDocument();
  });
});
