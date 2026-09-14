import '@testing-library/jest-dom';

// jsdom has no ResizeObserver; @radix-ui/react-popover (used by
// TopFilterBar's filter dropdowns) needs one to mount its content.
global.ResizeObserver = global.ResizeObserver || class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
