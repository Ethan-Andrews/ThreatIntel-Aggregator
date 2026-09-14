import { render, screen, fireEvent } from '@testing-library/react';
import MetricInfoIcon from '../MetricInfoIcon';

describe('MetricInfoIcon', () => {
  test('renders nothing for an unknown metric', () => {
    const { container } = render(<MetricInfoIcon metric="bogus" />);
    expect(container).toBeEmptyDOMElement();
  });

  test('shows the definition as a native hover title on the icon', () => {
    render(<MetricInfoIcon metric="backtest" />);
    expect(screen.getByRole('button', { name: /Backtest info/i })).toHaveAttribute(
      'title',
      expect.stringContaining('Runs the rule against real telemetry'),
    );
  });

  test('clicking the icon opens a window with the label and formula, closable', () => {
    render(<MetricInfoIcon metric="static_gate" />);
    expect(screen.queryByText(/HOW IT.S CALCULATED/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Static gate info/i }));

    expect(screen.getByText(/HOW IT.S CALCULATED/i)).toBeInTheDocument();
    expect(screen.getByText(/static_gate\.py/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Close/i }));
    expect(screen.queryByText(/HOW IT.S CALCULATED/i)).not.toBeInTheDocument();
  });

  test('review metric explains the human-only, never-automatic nature of the field', () => {
    render(<MetricInfoIcon metric="review" />);
    fireEvent.click(screen.getByRole('button', { name: /Review info/i }));
    expect(screen.getByText(/never computed automatically/i)).toBeInTheDocument();
  });
});
