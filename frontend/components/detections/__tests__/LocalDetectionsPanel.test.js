import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import LocalDetectionsPanel from '../LocalDetectionsPanel';

const NOT_CONFIGURED = { configured: false, detail: 'LOCAL_IMPORT_DIR is not configured' };
const CONFIGURED = { configured: true, root: '/data/local-import' };

const RUNNING_JOB = { job_id: 'job-1', status: 'running', total: 2, completed: 0, failed: 0, results: [] };
const COMPLETED_JOB = {
  job_id: 'job-1', status: 'completed', total: 2, completed: 1, failed: 1,
  results: [
    {
      path: 'rules/good.kql', status: 'imported', language: 'kql', hunt_id: 1, analytic_id: 10,
      technique_id: 'T1059', static_gate_verdict: 'pass', static_gate_durability: 0.9,
      control_plan: null, detail: '',
    },
    {
      path: 'rules/broken.txt', status: 'error', language: 'unrecognized', hunt_id: null, analytic_id: null,
      technique_id: null, static_gate_verdict: null, static_gate_durability: null,
      control_plan: null, detail: 'could not classify this file as any recognized detection format',
    },
  ],
};

function mockAuthFetch({ status = CONFIGURED, jobSequence = [] } = {}) {
  let jobCallIndex = 0;
  return jest.fn((url, opts) => {
    if (url.includes('/local-import/status')) {
      return Promise.resolve({ ok: true, json: async () => status });
    }
    if (opts && opts.method === 'POST' && url.endsWith('/local-import')) {
      return Promise.resolve({ ok: true, json: async () => ({ job_id: 'job-1' }) });
    }
    if (url.includes('/local-import/jobs/job-1')) {
      const job = jobSequence[Math.min(jobCallIndex, jobSequence.length - 1)];
      jobCallIndex += 1;
      return Promise.resolve({ ok: true, json: async () => job });
    }
    if (url.includes('/local-import/jobs')) {
      return Promise.resolve({ ok: true, json: async () => ({ jobs: [] }) });
    }
    // HuntsPanel's own list call, reused for the browse section below.
    return Promise.resolve({ ok: true, json: async () => ({ items: [], total: 0 }) });
  });
}

describe('LocalDetectionsPanel', () => {
  test('renders a not-configured message for an admin when the status endpoint reports configured: false', async () => {
    const authFetch = mockAuthFetch({ status: NOT_CONFIGURED });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(await screen.findByText(/^not configured$/i)).toBeInTheDocument();
    expect(screen.getByText(/LOCAL_IMPORT_DIR is not configured/)).toBeInTheDocument();
    expect(screen.getByText('LOCAL_IMPORT_DIR')).toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/team-a\/kql/i)).not.toBeInTheDocument();
  });

  test('renders the sub-path input and Import button for an admin when configured', async () => {
    const authFetch = mockAuthFetch({ status: CONFIGURED });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(await screen.findByText('/data/local-import')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/team-a\/kql/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Import$/i })).toBeInTheDocument();
  });

  test('does not show the import trigger to a non-admin viewer, but still shows the browse section', async () => {
    const authFetch = mockAuthFetch({ status: CONFIGURED });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="viewer" />);

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/detections/hunts'));
    });
    expect(screen.queryByText(/IMPORT FROM LOCAL FOLDER/i)).not.toBeInTheDocument();
    // The HuntsPanel title ("▸ LOCAL DETECTIONS (0)") and the description
    // paragraph ("...via Local Detections Import above...") both contain
    // this substring case-insensitively -- match the tab heading
    // specifically via its leading "▸ " marker.
    expect(screen.getByText(/▸ LOCAL DETECTIONS/)).toBeInTheDocument();
  });

  test('submitting the form calls the POST endpoint, then polls the job endpoint and renders a results table', async () => {
    jest.useFakeTimers();
    try {
      const authFetch = mockAuthFetch({ status: CONFIGURED, jobSequence: [RUNNING_JOB, COMPLETED_JOB] });
      render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

      await screen.findByText('/data/local-import');

      fireEvent.change(screen.getByPlaceholderText(/team-a\/kql/i), { target: { value: 'team-a/kql' } });
      fireEvent.click(screen.getByRole('button', { name: /^Import$/i }));

      await waitFor(() => {
        expect(authFetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/detections/local-import'),
          expect.objectContaining({ method: 'POST', body: JSON.stringify({ sub_path: 'team-a/kql' }) }),
        );
      });

      // First poll: job is still running.
      await waitFor(() => {
        expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/local-import/jobs/job-1'));
      });
      expect(screen.getByText(/Job job-1/)).toBeInTheDocument();

      // Advance past the 1.5s poll interval so the second (completed) fetch fires.
      await jest.advanceTimersByTimeAsync(1500);

      expect(await screen.findByText(/RESULTS \(2\)/i)).toBeInTheDocument();
      // Both paths now also appear in the top-of-results summary alert
      // (added alongside the results table) -- scope to the table itself.
      const table = screen.getByRole('table');
      const importedRow = within(table).getByText('rules/good.kql').closest('tr');
      const errorRow = within(table).getByText('rules/broken.txt').closest('tr');
      expect(importedRow).toHaveTextContent('IMPORTED');
      expect(errorRow).toHaveTextContent('ERROR');
      // Distinct styling, not just distinct text.
      expect(importedRow.querySelector('span.text-green-300')).toBeTruthy();
      expect(errorRow.querySelector('span.text-red-300')).toBeTruthy();
      // Non-KQL/unrecognized rows show the row's own detail instead of a
      // blank static-gate cell -- it appears in both the Detail column and
      // the static-gate fallback, so at least one match is expected, never zero.
      expect(screen.getAllByText(/could not classify this file/i).length).toBeGreaterThan(0);
    } finally {
      jest.useRealTimers();
    }
  });

  test('shows a prominent top-of-results alert naming every failed file, distinct from a flagged-but-imported one', async () => {
    const jobWithFlagged = {
      job_id: 'job-2', status: 'completed', total: 3, completed: 2, failed: 1, flagged: 1,
      results: [
        {
          path: 'rules/good.kql', status: 'imported', language: 'kql', hunt_id: 1, analytic_id: 10,
          technique_id: 'T1059', static_gate_verdict: 'pass', static_gate_durability: 0.9,
          static_gate_findings: [], control_plan: null, detail: '',
        },
        {
          path: 'rules/bad_hash.kql', status: 'imported', language: 'kql', hunt_id: 2, analytic_id: 11,
          technique_id: null, static_gate_verdict: 'reject', static_gate_durability: 0.0,
          static_gate_findings: [{ code: 'hash_predicate', detail: 'degenerate single-hash predicate' }],
          control_plan: null,
          detail: 'Static analysis flagged this as invalid: degenerate single-hash predicate',
        },
        {
          path: 'rules/broken.txt', status: 'error', language: 'unrecognized', hunt_id: null, analytic_id: null,
          technique_id: null, static_gate_verdict: null, static_gate_durability: null,
          static_gate_findings: null, control_plan: null,
          detail: 'could not classify this file as any recognized detection format',
        },
      ],
    };
    const authFetch = mockAuthFetch({ status: CONFIGURED, jobSequence: [jobWithFlagged] });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

    fireEvent.change(await screen.findByPlaceholderText(/team-a\/kql/i), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: /^import$/i }));

    // Failure summary: named explicitly, with its reason, not just a count.
    // "rules/broken.txt" appears both in the alert and in the results
    // table row below it -- at least one match is the point, not exactly one.
    expect(await screen.findByText(/1 file failed to import/i)).toBeInTheDocument();
    expect(screen.getAllByText(/rules\/broken\.txt/).length).toBeGreaterThan(0);

    // Flagged summary: a SEPARATE alert, never conflated with "failed" --
    // this file was successfully imported, just marked invalid.
    expect(screen.getByText(/1 file imported but flagged invalid/i)).toBeInTheDocument();
    expect(screen.getAllByText(/degenerate single-hash predicate/i).length).toBeGreaterThan(0);

    // The flagged row itself is highlighted distinctly from a clean row
    // and from an outright error row -- three visually distinct states,
    // not just two.
    const table = screen.getByRole('table');
    const flaggedRow = within(table).getByText('rules/bad_hash.kql').closest('tr');
    const goodRow = within(table).getByText('rules/good.kql').closest('tr');
    const errorRow = within(table).getByText('rules/broken.txt').closest('tr');
    expect(flaggedRow.className).toContain('yellow');
    expect(errorRow.className).toContain('red');
    expect(goodRow.className).not.toContain('yellow');
    expect(goodRow.className).not.toContain('red');
  });

  test('shows a clean all-clear alert when nothing failed or was flagged', async () => {
    const cleanJob = {
      job_id: 'job-3', status: 'completed', total: 1, completed: 1, failed: 0, flagged: 0,
      results: [
        {
          path: 'rules/good.kql', status: 'imported', language: 'kql', hunt_id: 1, analytic_id: 10,
          technique_id: 'T1059', static_gate_verdict: 'pass', static_gate_durability: 0.9,
          static_gate_findings: [], control_plan: null, detail: '',
        },
      ],
    };
    const authFetch = mockAuthFetch({ status: CONFIGURED, jobSequence: [cleanJob] });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

    fireEvent.click(await screen.findByRole('button', { name: /^import$/i }));

    expect(await screen.findByText(/all 1 file imported cleanly/i)).toBeInTheDocument();
    expect(screen.queryByText(/failed to import/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/flagged invalid/i)).not.toBeInTheDocument();
  });

  test('shows a collapsible supported-formats and sidecar-template reference', async () => {
    const authFetch = mockAuthFetch({ status: CONFIGURED });
    render(<LocalDetectionsPanel authFetch={authFetch} userRole="admin" />);

    const summary = await screen.findByText(/supported formats/i);
    expect(summary).toBeInTheDocument();
    // Collapsed by default. jsdom keeps a <details> element's children in
    // the DOM regardless of its `open` state (only real browser rendering
    // hides them visually), so the meaningful assertion here is on the
    // <details> element's own `open` property, not on child-text presence.
    const details = summary.closest('details');
    expect(details.open).toBe(false);

    fireEvent.click(summary);
    expect(details.open).toBe(true);
    expect(await screen.findByText(/"technique_id": "T1059\.001"/)).toBeInTheDocument();
    expect(screen.getByText(/Scheduled/)).toBeInTheDocument();
  });
});
