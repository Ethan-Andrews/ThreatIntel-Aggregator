import { render, screen, fireEvent } from '@testing-library/react';
import TimeRangeToggle from '../TimeRangeToggle';

describe('TimeRangeToggle', () => {
  test('renders all fixed windows plus Custom, defaulting to 30d highlighted', () => {
    const onChange = jest.fn();
    render(<TimeRangeToggle value={{ window: '30d' }} onChange={onChange} />);
    for (const label of ['1D', '7D', '30D', '90D', 'All', 'Custom']) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByText('30D').className).toMatch(/bg-gray-700/);
  });

  test('clicking a fixed window emits {window, from: null, to: null}', () => {
    const onChange = jest.fn();
    render(<TimeRangeToggle value={{ window: '30d' }} onChange={onChange} />);
    fireEvent.click(screen.getByText('7D'));
    expect(onChange).toHaveBeenCalledWith({ window: '7d', from: null, to: null });
  });

  test('clicking All emits window=all', () => {
    const onChange = jest.fn();
    render(<TimeRangeToggle value={{ window: '30d' }} onChange={onChange} />);
    fireEvent.click(screen.getByText('All'));
    expect(onChange).toHaveBeenCalledWith({ window: 'all', from: null, to: null });
  });

  test('clicking Custom reveals date inputs, and Apply only fires once both are set', () => {
    const onChange = jest.fn();
    render(<TimeRangeToggle value={{ window: '30d' }} onChange={onChange} />);
    fireEvent.click(screen.getByText('Custom'));

    expect(screen.getByLabelText('Custom range start')).toBeInTheDocument();
    expect(screen.getByText('Apply')).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Custom range start'), { target: { value: '2026-01-01' } });
    expect(screen.getByText('Apply')).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Custom range end'), { target: { value: '2026-02-01' } });
    expect(screen.getByText('Apply')).not.toBeDisabled();

    fireEvent.click(screen.getByText('Apply'));
    expect(onChange).toHaveBeenLastCalledWith({ window: 'custom', from: '2026-01-01', to: '2026-02-01' });
  });
});
