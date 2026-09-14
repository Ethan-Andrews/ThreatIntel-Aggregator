import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import AuditPanel from '../AuditPanel';

const FAILING_ITEM = {
  source: 'detection', source_id: 1, title: 'Bad Detection',
  check_type: 'static_gate/control_probe', is_failing: true,
  detail: 'Static gate rejected: literal IP address', checked_at: '2026-09-02T00:00:00Z',
};

const PASSING_ITEM = {
  source: 'sentinel_query', source_id: 2, title: 'Clean Query',
  check_type: 'gate/control_probe', is_failing: false,
  detail: 'Passed gate and control probe', checked_at: '2026-09-02T00:00:00Z',
};

function mockAuthFetch({ summary, failures, all, breakdown } = {}) {
  return jest.fn((url) => {
    if (url.includes('/api/audit/failure-breakdown')) {
      return Promise.resolve({ ok: true, json: async () => (breakdown || { categories: [] }) });
    }
    if (url.includes('/api/audit/summary')) {
      return Promise.resolve({ ok: true, json: async () => summary || { failing: 1, passing: 1 } });
    }
    if (url.includes('outcome=passing')) {
      return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [PASSING_ITEM] }) });
    }
    if (url.includes('outcome=failing') || !url.includes('outcome=')) {
      const items = url.includes('outcome=') ? [FAILING_ITEM] : (all || [FAILING_ITEM, PASSING_ITEM]);
      return Promise.resolve({ ok: true, json: async () => (failures || { total: items.length, items }) });
    }
    return Promise.resolve({ ok: true, json: async () => ({ total: 0, items: [] }) });
  });
}

describe('AuditPanel', () => {
  test('is not shown to a non-admin viewer', () => {
    const authFetch = mockAuthFetch();
    render(<AuditPanel authFetch={authFetch} userRole="viewer" />);
    expect(screen.getByText(/only available to admins/i)).toBeInTheDocument();
    expect(authFetch).not.toHaveBeenCalled();
  });

  test('defaults to showing only failing items, with summary counts', async () => {
    const authFetch = mockAuthFetch();
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);

    expect(await screen.findByText('Bad Detection')).toBeInTheDocument();
    expect(screen.getByText('1 failing')).toBeInTheDocument();
    expect(screen.getByText('1 passing')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Failing only')).toBeInTheDocument();
  });

  test('switching the filter to Passing only re-fetches and shows passing items', async () => {
    const authFetch = mockAuthFetch();
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');

    fireEvent.change(screen.getByDisplayValue('Failing only'), { target: { value: 'passing' } });

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('outcome=passing'));
    });
    expect(await screen.findByText('Clean Query')).toBeInTheDocument();
    expect(screen.queryByText('Bad Detection')).not.toBeInTheDocument();
  });

  test('shows an empty state when nothing is failing', async () => {
    const authFetch = mockAuthFetch({ failures: { total: 0, items: [] } });
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    expect(await screen.findByText(/nothing is currently failing/i)).toBeInTheDocument();
  });

  test('renders a failure-breakdown bubble per category with its count', async () => {
    const authFetch = mockAuthFetch({
      breakdown: { categories: [
        { category: 'Static gate: no_table', count: 18 },
        { category: 'no Sentinel client configured', count: 20 },
      ] },
    });
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);

    expect(await screen.findByText('no_table')).toBeInTheDocument();
    expect(screen.getByText('18')).toBeInTheDocument();
    expect(screen.getByText('no Sentinel client configured')).toBeInTheDocument();
    expect(screen.getByText('20')).toBeInTheDocument();
    expect(screen.getByText('FAILURE BREAKDOWN')).toBeInTheDocument();
  });

  test('shows a color legend instead of decorative color on the bubbles', async () => {
    const authFetch = mockAuthFetch({
      breakdown: { categories: [{ category: 'Static gate: no_table', count: 18 }] },
    });
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);

    await screen.findByText('FAILURE BREAKDOWN');
    expect(screen.getByText('Static gate rejection')).toBeInTheDocument();
    expect(screen.getByText('Auth / RBAC error')).toBeInTheDocument();
    expect(screen.getByText('Other error')).toBeInTheDocument();
  });

  test('renders no breakdown section when there are no failure categories', async () => {
    const authFetch = mockAuthFetch({ breakdown: { categories: [] } });
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');
    expect(screen.queryByText('FAILURE BREAKDOWN')).not.toBeInTheDocument();
  });

  test('clicking a bubble filters the list by category and shows a clearable chip', async () => {
    const CATEGORY_ITEM = {
      source: 'detection', source_id: 3, title: 'No Table Rule',
      check_type: 'static_gate/control_probe', is_failing: true,
      detail: 'Static gate rejected: [{"code":"no_table"}]', checked_at: '2026-09-02T00:00:00Z',
    };
    const authFetch = jest.fn((url) => {
      if (url.includes('/api/audit/failure-breakdown')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ categories: [{ category: 'Static gate: no_table', count: 1 }] }),
        });
      }
      if (url.includes('/api/audit/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ failing: 2, passing: 0 }) });
      }
      if (url.includes('category=')) {
        return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [CATEGORY_ITEM] }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ total: 2, items: [FAILING_ITEM] }) });
    });

    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');

    fireEvent.click(await screen.findByText('no_table'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringMatching(/category=Static\+gate%3A\+no_table|category=Static%20gate%3A%20no_table/)
      );
    });
    expect(await screen.findByText('No Table Rule')).toBeInTheDocument();
    // Forces the outcome dropdown to "Failing only" and disables it while a
    // category filter is active -- a category can never match a passing row.
    expect(screen.getByDisplayValue('Failing only')).toBeDisabled();

    fireEvent.click(screen.getByLabelText('Clear category filter'));
    await waitFor(() => {
      expect(screen.getByDisplayValue('Failing only')).not.toBeDisabled();
    });
    expect(await screen.findByText('Bad Detection')).toBeInTheDocument();
  });

  test('renders the trend chart with the honesty label and a time-range toggle', async () => {
    const authFetch = jest.fn((url) => {
      if (url.includes('/api/audit/trend')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ trend: [{ date: '2026-09-01T00:00:00Z', failing: 3, passing: 5 }] }),
        });
      }
      if (url.includes('/api/audit/failure-breakdown')) {
        return Promise.resolve({ ok: true, json: async () => ({ categories: [] }) });
      }
      if (url.includes('/api/audit/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ failing: 1, passing: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [FAILING_ITEM] }) });
    });

    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');

    expect(screen.getByText('RESULTS BY LAST-CHECKED DATE')).toBeInTheDocument();
    expect(screen.getByText(/not a real/i)).toBeInTheDocument();
    // The trend chart's own TimeRangeToggle instance -- 30D is the default.
    expect(screen.getAllByText('30D').length).toBeGreaterThan(0);
  });

  test('changing the trend window re-fetches /api/audit/trend with the new window', async () => {
    const authFetch = jest.fn((url) => {
      if (url.includes('/api/audit/trend')) {
        return Promise.resolve({ ok: true, json: async () => ({ trend: [] }) });
      }
      if (url.includes('/api/audit/failure-breakdown')) {
        return Promise.resolve({ ok: true, json: async () => ({ categories: [] }) });
      }
      if (url.includes('/api/audit/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ failing: 1, passing: 0 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [FAILING_ITEM] }) });
    });

    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');
    await waitFor(() => expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('window=30d')));

    fireEvent.click(screen.getByText('7D'));
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('window=7d'));
    });
  });

  test('status filter defaults to Unannotated and re-fetches with the status param on change', async () => {
    const authFetch = mockAuthFetch();
    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');
    expect(screen.getByDisplayValue('Unannotated')).toBeInTheDocument();

    fireEvent.change(screen.getByDisplayValue('Unannotated'), { target: { value: 'fixed' } });
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('status=fixed'));
    });
  });

  test('an admin can annotate a row, which saves and re-fetches the list', async () => {
    const authFetch = jest.fn((url, opts) => {
      if (opts && opts.method === 'PATCH') {
        return Promise.resolve({ ok: true, json: async () => ({ status: 'fixed' }) });
      }
      if (url.includes('/api/audit/failure-breakdown')) {
        return Promise.resolve({ ok: true, json: async () => ({ categories: [] }) });
      }
      if (url.includes('/api/audit/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ failing: 1, passing: 0 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [FAILING_ITEM] }) });
    });

    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');

    fireEvent.click(screen.getByText('Annotate'));
    const statusSelects = screen.getAllByRole('combobox');
    fireEvent.change(statusSelects[statusSelects.length - 1], { target: { value: 'fixed' } });
    fireEvent.change(screen.getByPlaceholderText('Closing notes…'), { target: { value: 'resolved manually' } });
    fireEvent.click(screen.getByText('Save'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/audit/detection/1'),
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify({ status: 'fixed', notes: 'resolved manually' }),
        }),
      );
    });
  });

  test('an annotated row shows its badge and notes, with a Clear annotation action', async () => {
    const ANNOTATED_ITEM = {
      ...FAILING_ITEM,
      annotation_status: 'acknowledged',
      annotation_notes: 'triaged, low priority',
    };
    const authFetch = jest.fn((url, opts) => {
      if (opts && opts.method === 'DELETE') {
        return Promise.resolve({ ok: true, json: async () => ({ cleared: true }) });
      }
      if (url.includes('/api/audit/failure-breakdown')) {
        return Promise.resolve({ ok: true, json: async () => ({ categories: [] }) });
      }
      if (url.includes('/api/audit/summary')) {
        return Promise.resolve({ ok: true, json: async () => ({ failing: 0, passing: 1 }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ total: 1, items: [ANNOTATED_ITEM] }) });
    });

    render(<AuditPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText('Bad Detection');

    expect(screen.getByText('ACKNOWLEDGED')).toBeInTheDocument();
    expect(screen.getByText('"triaged, low priority"')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Clear annotation'));
    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/audit/detection/1'),
        expect.objectContaining({ method: 'DELETE' }),
      );
    });
  });
});
