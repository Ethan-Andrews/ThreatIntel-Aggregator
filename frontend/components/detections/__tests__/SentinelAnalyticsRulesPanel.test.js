import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import SentinelAnalyticsRulesPanel from '../SentinelAnalyticsRulesPanel';

const RULE_ROW = {
  id: 1,
  sentinel_rule_id: 'rule-1',
  display_name: 'Suspicious PowerShell Download',
  description: 'Detects PowerShell downloading and executing content.',
  severity: 'High',
  enabled: true,
  tactics: ['Execution'],
  techniques: ['T1059.001'],
  review_state: 'pending',
  backtest_disposition: null,
  last_tested_at: null,
  created_at: '2026-09-02T00:00:00Z',
};

const RULE_DETAIL = {
  ...RULE_ROW,
  kql_body: 'DeviceProcessEvents | take 1',
  control_probe_result: null,
  tune_history: null,
};

function mockAuthFetch({ list, detail, sync } = {}) {
  return jest.fn((url, options) => {
    if (options && options.method === 'POST' && url.includes('/sync')) {
      return Promise.resolve({ ok: true, json: async () => sync || { enabled: false, rules_synced: 0, skipped_kinds: 0, errors: [] } });
    }
    if (options && options.method === 'POST' && /\/sentinel-analytics-rules\/\d+\/test/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ ...RULE_DETAIL, backtest_disposition: 'needs_tuning', control_probe_result: { gate_verdict: 'pass', disposition: 'ok' } }) });
    }
    if (options && options.method === 'POST' && /\/sentinel-analytics-rules\/\d+\/tune/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ ...RULE_DETAIL, tune_history: { disposition: 'tuned' } }) });
    }
    if (options && options.method === 'PATCH' && /\/sentinel-analytics-rules\/\d+\/review/.test(url)) {
      const body = JSON.parse(options.body);
      return Promise.resolve({ ok: true, json: async () => ({ ...RULE_DETAIL, review_state: body.review_state }) });
    }
    if (/\/api\/sentinel-analytics-rules\/\d+$/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => detail || RULE_DETAIL });
    }
    return Promise.resolve({ ok: true, json: async () => list || { items: [RULE_ROW], total: 1 } });
  });
}

describe('SentinelAnalyticsRulesPanel', () => {
  test('lists synced analytics rules with severity and review state', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);

    expect(await screen.findByText('Suspicious PowerShell Download')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('PENDING')).toBeInTheDocument();
    // KQL body isn't loaded until the row is expanded.
    expect(screen.queryByText('DeviceProcessEvents | take 1')).not.toBeInTheDocument();
  });

  test('shows an empty state when nothing is synced', async () => {
    const authFetch = mockAuthFetch({ list: { items: [], total: 0 } });
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    expect(await screen.findByText(/No Sentinel analytics rules synced yet/i)).toBeInTheDocument();
  });

  test('expanding a rule fetches and shows its full KQL body plus tactics/techniques', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    fireEvent.click(await screen.findByText('Suspicious PowerShell Download'));

    expect(await screen.findByText('DeviceProcessEvents | take 1')).toBeInTheDocument();
    expect(screen.getByText('Execution')).toBeInTheDocument();
    expect(screen.getByText('T1059.001')).toBeInTheDocument();
  });

  test('does not show admin actions to a non-admin viewer', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="viewer" />);
    fireEvent.click(await screen.findByText('Suspicious PowerShell Download'));
    await screen.findByText('DeviceProcessEvents | take 1');

    expect(screen.queryByText('Test')).not.toBeInTheDocument();
    expect(screen.queryByText('Sync now')).not.toBeInTheDocument();
  });

  test('an admin can sync, test, and review a rule', async () => {
    const authFetch = mockAuthFetch({
      sync: { enabled: true, rules_synced: 3, skipped_kinds: 1, errors: [] },
    });
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Suspicious PowerShell Download');

    fireEvent.click(screen.getByText('Sync now'));
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-analytics-rules/sync'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/Synced 3 rules/i)).toBeInTheDocument();
    expect(screen.getByText(/1 non-Scheduled rule\(s\) skipped/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText('Suspicious PowerShell Download'));
    await screen.findByText('DeviceProcessEvents | take 1');

    fireEvent.click(screen.getByText('Test'));
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-analytics-rules/1/test'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/NEEDS_TUNING/i)).toBeInTheDocument();

    fireEvent.change(screen.getByDisplayValue('Pending'), { target: { value: 'approved' } });
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-analytics-rules/1/review'),
        expect.objectContaining({ method: 'PATCH', body: JSON.stringify({ review_state: 'approved' }) }),
      );
    });
  });

  test('filtering by review state re-fetches with the right query param', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Suspicious PowerShell Download');

    fireEvent.change(screen.getByDisplayValue('All'), { target: { value: 'approved' } });

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('review_state=approved'));
    });
  });

  test('checking "Needs tuning only" re-fetches with disposition=needs_tuning', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Suspicious PowerShell Download');

    fireEvent.click(screen.getByLabelText(/Needs tuning only/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('disposition=needs_tuning'));
    });
  });

  test('submitting the search box re-fetches with the search query param', async () => {
    const authFetch = mockAuthFetch();
    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Suspicious PowerShell Download');

    fireEvent.change(screen.getByPlaceholderText(/Search rule names/i), { target: { value: 'powershell' } });
    fireEvent.click(screen.getByText('Search'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('search=powershell'));
    });
  });

  test('a tuning suggestion shows Apply/Dismiss controls, and Apply pushes it to Sentinel', async () => {
    const tunedDetail = {
      ...RULE_DETAIL,
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
          json: async () => ({ result: { rule_id: 1, success: true, reason: null }, rule: appliedDetail }),
        });
      }
      if (/\/api\/sentinel-analytics-rules\/\d+$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => tunedDetail });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [RULE_ROW], total: 1 }) });
    });

    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    fireEvent.click(await screen.findByText('Suspicious PowerShell Download'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByText('Apply'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-analytics-rules/1/tuning-suggestion/apply'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/TUNING APPLIED/i)).toBeInTheDocument();
  });

  test('Dismiss records the decision without pushing to Sentinel', async () => {
    const tunedDetail = {
      ...RULE_DETAIL,
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
          json: async () => ({ result: { rule_id: 1, success: true, reason: null }, rule: dismissedDetail }),
        });
      }
      if (/\/api\/sentinel-analytics-rules\/\d+$/.test(url)) {
        return Promise.resolve({ ok: true, json: async () => tunedDetail });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [RULE_ROW], total: 1 }) });
    });

    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="admin" />);
    fireEvent.click(await screen.findByText('Suspicious PowerShell Download'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByText('Dismiss'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/sentinel-analytics-rules/1/tuning-suggestion/dismiss'),
        expect.objectContaining({ method: 'POST' }),
      );
    });
    expect(await screen.findByText(/TUNING DISMISSED/i)).toBeInTheDocument();
  });

  test('a non-admin viewer never sees Apply/Dismiss controls on a tuning suggestion', async () => {
    const tunedDetail = {
      ...RULE_DETAIL,
      backtest_disposition: 'needs_tuning',
      tune_history: { disposition: 'tuned', final_body: 'DeviceProcessEvents | take 1 | where X != 1' },
      tuning_suggestion: {
        disposition: 'tuned', pending: true,
        final_body: 'DeviceProcessEvents | take 1 | where X != 1',
        action: null, performed_by: null, performed_at: null, error: null,
      },
    };
    const authFetch = mockAuthFetch({ detail: tunedDetail });

    render(<SentinelAnalyticsRulesPanel authFetch={authFetch} userRole="viewer" />);
    fireEvent.click(await screen.findByText('Suspicious PowerShell Download'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    expect(screen.queryByText('Apply')).not.toBeInTheDocument();
    expect(screen.queryByText('Dismiss')).not.toBeInTheDocument();
  });
});
