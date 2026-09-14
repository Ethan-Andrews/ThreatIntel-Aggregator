import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AlignmentReviewPanel from '../AlignmentReviewPanel';

function mockAuthFetch(pendingData, partialData = { items: [], total: 0 }, pendingReadyData) {
  return jest.fn((url) => {
    let data;
    if (url.includes('ready_only=true')) {
      data = pendingReadyData !== undefined ? pendingReadyData : pendingData;
    } else if (url.includes('/partial')) {
      data = partialData;
    } else {
      data = pendingData;
    }
    return Promise.resolve({ ok: true, json: async () => data });
  });
}

const BASE_REVIEW = {
  id: 1,
  strategy_id: 1,
  analytic_id: 5,
  technique_id: 'T1053.005',
  technique_name: 'Scheduled Task/Job: Scheduled Task',
  our_objective: 'Detect scheduled task creation',
  verdict: 'diverges',
  ai_reasoning: 'The current rule no longer matches the observed TTP.',
  suggested_kql: 'DeviceProcessEvents | take 1',
  validation_result: null,
  status: 'pending_review',
  created_at: '2026-08-30T00:00:00Z',
  detection_name: 'Suspicious Scheduled Task Creation',
  detection_description: 'Flags schtasks.exe creating a new scheduled task.',
  deployed_kql_body: "DeviceProcessEvents | where FileName == 'schtasks.exe'",
};

async function expandPending() {
  fireEvent.click(await screen.findByText(/PENDING REVIEW/));
}

describe('AlignmentReviewPanel', () => {
  test('pending and awaiting re-check groups start collapsed', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_REVIEW], total: 1 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);

    await screen.findByText(/PENDING REVIEW/);
    expect(screen.queryByText('Suspicious Scheduled Task Creation')).not.toBeInTheDocument();
  });

  test('collapsed header shows total and ready-to-accept counts for pending', async () => {
    const authFetch = mockAuthFetch(
      { items: [BASE_REVIEW], total: 3 },
      { items: [], total: 0 },
      { items: [], total: 2 },
    );
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);

    await waitFor(() => {
      expect(screen.getByText(/PENDING REVIEW \(3 total, 2 ready to accept\)/)).toBeInTheDocument();
    });
  });

  test('collapsed header shows total for awaiting re-check, no ready-to-accept count', async () => {
    const authFetch = mockAuthFetch({ items: [], total: 0 }, { items: [], total: 5 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);

    await waitFor(() => {
      expect(screen.getByText(/AWAITING RE-CHECK \(5 total\)/)).toBeInTheDocument();
    });
  });

  test('expanding pending reveals the currently-deployed detection name alongside the technique', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_REVIEW], total: 1 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);
    await expandPending();

    await waitFor(() => {
      expect(screen.getByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
    });
    expect(screen.getByText(/T1053\.005/)).toBeInTheDocument();
  });

  test('falls back to a clear label when no analytic is linked yet', async () => {
    const authFetch = mockAuthFetch({
      items: [{ ...BASE_REVIEW, detection_name: null, detection_description: null, deployed_kql_body: null }],
      total: 1,
    });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);
    await expandPending();

    await waitFor(() => {
      expect(screen.getByText(/No deployed analytic yet/i)).toBeInTheDocument();
    });
  });

  test('shows a human-readable detection type badge, including Hunt', async () => {
    const authFetch = mockAuthFetch({ items: [{ ...BASE_REVIEW, detection_type: 'hunt' }], total: 1 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);
    await expandPending();

    await waitFor(() => {
      expect(screen.getAllByText('Hunt').length).toBeGreaterThan(0);
    });
  });

  test('selecting a detection type re-requests both pending and partial with that filter', async () => {
    const authFetch = mockAuthFetch({ items: [BASE_REVIEW], total: 1 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);
    await screen.findByText(/PENDING REVIEW/);

    fireEvent.change(screen.getByDisplayValue('All types'), { target: { value: 'hunt' } });

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/alignment/pending?detection_type=hunt'));
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/alignment/partial?detection_type=hunt'));
    });
  });

  test('"ready to accept only" hides pending reviews with no suggested_kql', async () => {
    const noKqlReview = { ...BASE_REVIEW, id: 2, suggested_kql: null, detection_name: 'No Fix Available' };
    const authFetch = mockAuthFetch({ items: [BASE_REVIEW, noKqlReview], total: 2 });
    render(<AlignmentReviewPanel authFetch={authFetch} userRole="admin" />);
    await expandPending();

    await waitFor(() => {
      expect(screen.getByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
      expect(screen.getByText('No Fix Available')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByLabelText(/Ready to accept only/i));

    expect(screen.getByText('Suspicious Scheduled Task Creation')).toBeInTheDocument();
    expect(screen.queryByText('No Fix Available')).not.toBeInTheDocument();
  });
});
