import { render, screen, fireEvent } from '@testing-library/react';
import SeverityCards from '../SeverityCards';

describe('SeverityCards', () => {
  test('selected=null renders all four as selected', () => {
    render(<SeverityCards selected={null} onChange={jest.fn()} />);
    for (const label of ['Critical', 'High', 'Medium', 'Low']) {
      expect(screen.getByText(label).className).not.toMatch(/text-text-dim/);
    }
  });

  test('deselecting one card from the null (all-selected) state emits the other three, not just the one clicked', () => {
    // Regression test: an earlier version computed the toggle base as []
    // whenever selected was null, so clicking one card emitted [thatCard]
    // instead of the three remaining ones.
    const onChange = jest.fn();
    render(<SeverityCards selected={null} onChange={onChange} />);
    fireEvent.click(screen.getByText('Low'));
    expect(onChange).toHaveBeenCalledWith(
      expect.arrayContaining(['critical', 'high', 'medium']),
    );
    const emitted = onChange.mock.calls[0][0];
    expect(emitted).toHaveLength(3);
    expect(emitted).not.toContain('low');
  });

  test('re-selecting the fourth severity collapses back to null (no restriction)', () => {
    const onChange = jest.fn();
    render(<SeverityCards selected={['critical', 'high', 'medium']} onChange={onChange} />);
    fireEvent.click(screen.getByText('Low'));
    expect(onChange).toHaveBeenCalledWith(null);
  });

  test('clicking a selected severity when a real subset is active removes just that one', () => {
    const onChange = jest.fn();
    render(<SeverityCards selected={['critical', 'high']} onChange={onChange} />);
    fireEvent.click(screen.getByText('Critical'));
    expect(onChange).toHaveBeenCalledWith(['high']);
  });

  test('clicking an unselected severity adds it to the set', () => {
    const onChange = jest.fn();
    render(<SeverityCards selected={['critical']} onChange={onChange} />);
    fireEvent.click(screen.getByText('High'));
    expect(onChange.mock.calls[0][0]).toEqual(expect.arrayContaining(['critical', 'high']));
    expect(onChange.mock.calls[0][0]).toHaveLength(2);
  });
});
