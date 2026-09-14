import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DetectionsPanel from '../DetectionsPanel';

function mockAuthFetch() {
  return jest.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [], total: 0 }) });
}

describe('DetectionsPanel', () => {
  test('renders a Generated Hunts tab alongside the existing three, and switching to it fetches /api/detections/hunts', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" />);

    // Exact match -- 'SENTINEL HUNTS' is a separate tab label containing
    // the substring 'HUNTS', so a regex /HUNTS/i here would match both.
    expect(screen.getByText('GENERATED HUNTS')).toBeInTheDocument();

    fireEvent.click(screen.getByText('GENERATED HUNTS'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/detections/hunts'));
    });
  });

  test('renders a Sentinel Hunts tab, and switching to it fetches /api/sentinel-hunts', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(screen.getByText('SENTINEL HUNTS')).toBeInTheDocument();

    fireEvent.click(screen.getByText('SENTINEL HUNTS'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/sentinel-hunts'));
    });
    // Must not hit the AI-generated hunts endpoint instead.
    expect(authFetch).not.toHaveBeenCalledWith(expect.stringContaining('/api/detections/hunts'));
  });

  test('renders a Sentinel Analytics Rules tab, and switching to it fetches /api/sentinel-analytics-rules', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(screen.getByText('SENTINEL ANALYTICS RULES')).toBeInTheDocument();
    fireEvent.click(screen.getByText('SENTINEL ANALYTICS RULES'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/sentinel-analytics-rules'));
    });
  });

  test('shows an Audit Log tab to an admin, and switching to it fetches /api/audit', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(screen.getByText('AUDIT LOG')).toBeInTheDocument();
    fireEvent.click(screen.getByText('AUDIT LOG'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/audit/summary'));
    });
    expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/audit/failures'));
  });

  test('hides the Audit Log tab from a non-admin viewer', () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="viewer" />);
    expect(screen.queryByText('AUDIT LOG')).not.toBeInTheDocument();
  });

  test('renders a Defender Custom Detections tab, and switching to it fetches /api/detections with detection_type=mde', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" />);

    expect(screen.getByText('DEFENDER CUSTOM DETECTIONS')).toBeInTheDocument();
    fireEvent.click(screen.getByText('DEFENDER CUSTOM DETECTIONS'));

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('detection_type=mde'));
    });
  });

  test('initialSubTab lands directly on the requested sub-tab', async () => {
    const authFetch = mockAuthFetch();
    render(<DetectionsPanel authFetch={authFetch} userRole="admin" initialSubTab="sentinel-analytics-rules" />);

    await waitFor(() => {
      expect(authFetch).toHaveBeenCalledWith(expect.stringContaining('/api/sentinel-analytics-rules'));
    });
    expect(authFetch).not.toHaveBeenCalledWith(expect.stringContaining('/api/detections?'));
  });
});
