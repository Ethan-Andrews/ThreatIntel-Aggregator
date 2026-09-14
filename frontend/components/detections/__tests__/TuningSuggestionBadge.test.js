import { render, screen, fireEvent } from '@testing-library/react';
import TuningSuggestionBadge, { TuningBulkActionBar } from '../TuningSuggestionBadge';

const PENDING_ITEM = {
  id: 5,
  name: 'Suspicious Scheduled Task Creation',
  technique_id: 'T1053.005',
  tuning_suggestion: {
    disposition: 'tuned',
    pending: true,
    final_body: "DeviceProcessEvents | where AccountName != @\"bob\"",
    action: null,
    performed_by: null,
    performed_at: null,
  },
};

describe('TuningSuggestionBadge', () => {
  test('renders nothing when there is no suggestion', () => {
    const { container } = render(
      <TuningSuggestionBadge item={{ id: 1, tuning_suggestion: null }} isAdmin={false} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  test('renders nothing when tuning ran but found nothing to suggest', () => {
    const { container } = render(
      <TuningSuggestionBadge
        item={{ id: 1, tuning_suggestion: { pending: false, final_body: null, disposition: 'needs_human_tuning' } }}
        isAdmin={false}
      />
    );
    expect(container).toBeEmptyDOMElement();
  });

  test('shows the pending badge and reveals the proposed KQL on expand', () => {
    render(<TuningSuggestionBadge item={PENDING_ITEM} isAdmin={false} />);

    expect(screen.getByText(/TUNING SUGGESTION AVAILABLE/i)).toBeInTheDocument();
    expect(screen.queryByText(PENDING_ITEM.tuning_suggestion.final_body)).not.toBeInTheDocument();

    fireEvent.click(screen.getByText(/Show proposed KQL/i));

    expect(screen.getByText(PENDING_ITEM.tuning_suggestion.final_body)).toBeInTheDocument();
  });

  test('shows Apply/Dismiss controls only for an admin with a pending suggestion', () => {
    const onApply = jest.fn();
    const onDismiss = jest.fn();
    render(
      <TuningSuggestionBadge
        item={PENDING_ITEM} isAdmin={true} onApply={onApply} onDismiss={onDismiss} busy={false}
      />
    );

    fireEvent.click(screen.getByText('Apply'));
    expect(onApply).toHaveBeenCalledWith(5);

    fireEvent.click(screen.getByText('Dismiss'));
    expect(onDismiss).toHaveBeenCalledWith(5);
  });

  test('hides Apply/Dismiss controls for a non-admin viewer', () => {
    render(<TuningSuggestionBadge item={PENDING_ITEM} isAdmin={false} onApply={jest.fn()} onDismiss={jest.fn()} />);
    expect(screen.queryByText('Apply')).not.toBeInTheDocument();
    expect(screen.queryByText('Dismiss')).not.toBeInTheDocument();
  });

  test('shows the checkbox only for a pending suggestion with an admin and a select handler', () => {
    const onToggleSelect = jest.fn();
    render(
      <TuningSuggestionBadge
        item={PENDING_ITEM} isAdmin={true} selected={false} onToggleSelect={onToggleSelect}
      />
    );
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    expect(onToggleSelect).toHaveBeenCalledWith(5);
  });

  test('shows disposition of an already-applied suggestion without a checkbox or buttons', () => {
    const item = {
      ...PENDING_ITEM,
      tuning_suggestion: {
        ...PENDING_ITEM.tuning_suggestion,
        pending: false,
        action: 'applied',
        performed_by: 'admin@example.com',
      },
    };
    render(<TuningSuggestionBadge item={item} isAdmin={true} onApply={jest.fn()} onDismiss={jest.fn()} />);

    expect(screen.getByText(/TUNING APPLIED/i)).toBeInTheDocument();
    expect(screen.getByText(/applied by admin@example.com/i)).toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByText('Apply')).not.toBeInTheDocument();
  });

  test('shows dismissed disposition distinctly from applied', () => {
    const item = {
      ...PENDING_ITEM,
      tuning_suggestion: { ...PENDING_ITEM.tuning_suggestion, pending: false, action: 'dismissed', performed_by: 'alice' },
    };
    render(<TuningSuggestionBadge item={item} isAdmin={true} />);
    expect(screen.getByText(/TUNING DISMISSED/i)).toBeInTheDocument();
  });
});

describe('TuningBulkActionBar', () => {
  test('renders nothing when nothing is selected', () => {
    const { container } = render(
      <TuningBulkActionBar count={0} busy={false} onApply={jest.fn()} onDismiss={jest.fn()} onClear={jest.fn()} />
    );
    expect(container).toBeEmptyDOMElement();
  });

  test('shows the count and wires apply/dismiss/clear callbacks', () => {
    const onApply = jest.fn();
    const onDismiss = jest.fn();
    const onClear = jest.fn();
    render(
      <TuningBulkActionBar count={3} busy={false} onApply={onApply} onDismiss={onDismiss} onClear={onClear} />
    );

    expect(screen.getByText('3 selected')).toBeInTheDocument();
    fireEvent.click(screen.getByText(/Push 3 updates to Sentinel/i));
    expect(onApply).toHaveBeenCalled();
    fireEvent.click(screen.getByText(/Dismiss selected/i));
    expect(onDismiss).toHaveBeenCalled();
    fireEvent.click(screen.getByText(/Clear selection/i));
    expect(onClear).toHaveBeenCalled();
  });

  test('disables actions and shows a busy label while a push is in flight', () => {
    render(
      <TuningBulkActionBar count={2} busy={true} onApply={jest.fn()} onDismiss={jest.fn()} onClear={jest.fn()} />
    );
    expect(screen.getByText(/Pushing…/i)).toBeInTheDocument();
    expect(screen.getByText(/Pushing…/i)).toBeDisabled();
  });

  test('shows an error message when present', () => {
    render(
      <TuningBulkActionBar count={1} busy={false} error="Push failed." onApply={jest.fn()} onDismiss={jest.fn()} onClear={jest.fn()} />
    );
    expect(screen.getByText('Push failed.')).toBeInTheDocument();
  });
});

describe('TuningSuggestionBadge apply_failed state', () => {
  const APPLY_FAILED_ITEM = {
    id: 5,
    name: 'Suspicious Scheduled Task Creation',
    technique_id: 'T1053.005',
    tuning_suggestion: {
      disposition: 'tuned',
      pending: true,
      final_body: "DeviceProcessEvents | where AccountName != @\"bob\"",
      action: 'apply_failed',
      performed_by: 'admin@example.com',
      performed_at: '2026-09-01T00:00:00Z',
      error: '403 Forbidden',
    },
  };

  test('shows a distinct failure badge, not the green applied pill', () => {
    render(<TuningSuggestionBadge item={APPLY_FAILED_ITEM} isAdmin={true} onApply={jest.fn()} onDismiss={jest.fn()} />);

    expect(screen.getByText(/LAST APPLY FAILED/i)).toBeInTheDocument();
    expect(screen.queryByText(/^TUNING APPLIED$/i)).not.toBeInTheDocument();
    expect(screen.getByText(/403 Forbidden/i)).toBeInTheDocument();
  });

  test('stays retryable: admin still sees Apply/Dismiss and the checkbox', () => {
    const onApply = jest.fn();
    render(
      <TuningSuggestionBadge
        item={APPLY_FAILED_ITEM} isAdmin={true} selected={false}
        onToggleSelect={jest.fn()} onApply={onApply} onDismiss={jest.fn()}
      />
    );

    expect(screen.getByRole('checkbox')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Apply'));
    expect(onApply).toHaveBeenCalledWith(5);
  });
});
