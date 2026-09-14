import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DetectionsCatalogPanel from '../DetectionsCatalogPanel';

function mockAuthFetch(data) {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: async () => data,
  });
}

const BASE_ITEM = {
  id: 1,
  strategy_id: 1,
  technique_id: 'T1053.005',
  technique_name: 'Scheduled Task/Job: Scheduled Task',
  objective: 'Detect scheduled task creation',
  artifact_id: 'art-1',
  name: 'Suspicious Scheduled Task Creation',
  description: 'Flags schtasks.exe creating a new scheduled task.',
  kql_body: "DeviceProcessEvents | where FileName == 'schtasks.exe'",
  static_gate_verdict: 'pass',
  static_gate_durability: 0.9,
  backtest_disposition: 'clean',
  review_state: 'approved',
  created_at: '2026-08-30T00:00:00Z',
};

describe('DetectionsCatalogPanel', () => {
  test('shows the detection name as the primary identifier, not just the technique', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
    });
    expect(screen.getByText(/T1053\.005/)).toBeInTheDocument();
  });

  test('falls back to a clear label when name is null (pre-migration rows)', async () => {
    const authFetch = mockAuthFetch({ items: [{ ...BASE_ITEM, name: null }], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText(/Unnamed/i)).toBeInTheDocument();
    });
  });

  test('expands to reveal description and full KQL on click', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    expect(screen.queryByText(/schtasks\.exe.*creating a new scheduled task/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByText('Suspicious Scheduled Task Creation'));

    expect(await screen.findByText(/Flags schtasks\.exe creating a new scheduled task\./)).toBeInTheDocument();
    expect(screen.getByText(BASE_ITEM.kql_body)).toBeInTheDocument();
  });

  test('shows a human-readable detection type label in the table row', async () => {
    const authFetch = mockAuthFetch({ items: [{ ...BASE_ITEM, detection_type: 'sentinel' }], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => {
      expect(screen.getByText('Analytic rule')).toBeInTheDocument();
    });
  });

  test('the search box filters by technique ID or detection name, not just technique ID', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    fireEvent.change(screen.getByPlaceholderText(/Technique ID or detection name/i), {
      target: { value: 'Scheduled Task Creation' },
    });
    fireEvent.click(screen.getByText('Filter'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(
        expect.stringContaining('search=Scheduled+Task+Creation'),
      );
    });
  });

  test('selecting a detection type and filtering requests that type from the API', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    fireEvent.change(screen.getByDisplayValue('All types'), { target: { value: 'mde' } });
    fireEvent.click(screen.getByText('Filter'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenLastCalledWith(expect.stringContaining('detection_type=mde'));
    });
  });

  test('truncates a long multi-line objective in the table row instead of leaking it inline', async () => {
    const longObjective = [
      'rule Suspicious_QR_Phishing_PDF',
      '{',
      '  strings:',
      '    $pdf_magic = { 25 50 44 46 }',
      '    $filename = "Final Lien Waiver.pdf" nocase',
      '  condition:',
      '    $pdf_magic at 0 and $filename',
      '}',
    ].join('\n');
    const authFetch = mockAuthFetch({ items: [{ ...BASE_ITEM, objective: longObjective }], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    const cell = document.querySelector('td[title]');
    expect(cell).not.toBeNull();
    expect(cell.getAttribute('title')).toBe(longObjective);
    expect(cell.className).toEqual(expect.stringContaining('truncate'));
  });

  test('shows a distinct fallback label instead of silently repeating the technique name', async () => {
    const authFetch = mockAuthFetch({
      items: [{ ...BASE_ITEM, objective: 'Scheduled Task/Job: Scheduled Task', objective_is_fallback: true }],
      total: 1,
    });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    expect(screen.getByText('No MITRE objective yet')).toBeInTheDocument();
    expect(screen.queryByText('Scheduled Task/Job: Scheduled Task', { selector: 'td *' })).not.toBeInTheDocument();
  });

  test('shows the real objective text when it is not a fallback', async () => {
    const authFetch = mockAuthFetch({
      items: [{ ...BASE_ITEM, objective_is_fallback: false }],
      total: 1,
    });
    render(<DetectionsCatalogPanel authFetch={authFetch} />);

    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    expect(screen.getByText('Detect scheduled task creation')).toBeInTheDocument();
    expect(screen.queryByText('No MITRE objective yet')).not.toBeInTheDocument();
  });
});

describe('DetectionsCatalogPanel tuning suggestions', () => {
  const PENDING_ITEM = {
    ...BASE_ITEM,
    id: 2,
    tuning_suggestion: {
      disposition: 'tuned',
      pending: true,
      final_body: "DeviceProcessEvents | where AccountName != @\"bob\"",
      action: null, performed_by: null, performed_at: null,
    },
  };

  test('shows the tuning suggestion badge for an admin once expanded', async () => {
    const authFetch = mockAuthFetch({ items: [PENDING_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));

    fireEvent.click(screen.getByText('Suspicious Scheduled Task Creation'));

    expect(await screen.findByText(/TUNING SUGGESTION AVAILABLE/i)).toBeInTheDocument();
  });

  test('checking a row and pushing calls the apply endpoint with its id', async () => {
    const authFetch = jest.fn((url) => {
      if (url.includes('/tuning-suggestions/apply')) {
        return Promise.resolve({ ok: true, json: async () => ({ results: [{ analytic_id: 2, success: true, reason: null }] }) });
      }
      return Promise.resolve({ ok: true, json: async () => ({ items: [PENDING_ITEM], total: 1 }) });
    });
    render(<DetectionsCatalogPanel authFetch={authFetch} userRole="admin" />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));
    fireEvent.click(screen.getByText('Suspicious Scheduled Task Creation'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(await screen.findByText(/Push 1 update to Sentinel/i));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(
        expect.stringContaining('/tuning-suggestions/apply'),
        expect.objectContaining({ method: 'POST', body: JSON.stringify({ analytic_ids: [2] }) }),
      );
    });
  });

  test('a non-admin viewer never sees the checkbox or bulk action bar', async () => {
    const authFetch = mockAuthFetch({ items: [PENDING_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} userRole="viewer" />);
    await waitFor(() => screen.getByText('Suspicious Scheduled Task Creation'));
    fireEvent.click(screen.getByText('Suspicious Scheduled Task Creation'));
    await screen.findByText(/TUNING SUGGESTION AVAILABLE/i);

    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/Push .* to Sentinel/i)).not.toBeInTheDocument();
  });

  test('lockedDetectionType pins the fetch to that type and hides the type selector', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_ITEM], total: 1 });
    render(<DetectionsCatalogPanel authFetch={authFetch} lockedDetectionType="mde" />);

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('detection_type=mde'));
    });
    expect(screen.queryByText('All types')).not.toBeInTheDocument();
  });
});
