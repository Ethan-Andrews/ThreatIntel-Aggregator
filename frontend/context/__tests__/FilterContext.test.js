jest.mock("next/router", () => ({
  useRouter: () => ({
    isReady: true,
    query: {},
    pathname: "/",
    push: jest.fn(),
  }),
}));

import { renderHook, act } from "@testing-library/react";
import { FilterProvider, useFilters } from "../FilterContext";

function wrapper({ children }) {
  return <FilterProvider>{children}</FilterProvider>;
}

test("toggleSource adds and removes a source", () => {
  const { result } = renderHook(() => useFilters(), { wrapper });
  act(() => result.current.toggleSource("CISA"));
  expect(result.current.activeSources).toEqual(["CISA"]);
  act(() => result.current.toggleSource("CISA"));
  expect(result.current.activeSources).toEqual([]);
});

test("clearAll resets all filters", () => {
  const { result } = renderHook(() => useFilters(), { wrapper });
  act(() => {
    result.current.toggleSource("CISA");
    result.current.toggleSeverity("Critical");
  });
  act(() => result.current.clearAll());
  expect(result.current.activeSources).toEqual([]);
  expect(result.current.activeSeverities).toEqual([]);
});

test("clearCategory removes only that category's filters", () => {
  const { result } = renderHook(() => useFilters(), { wrapper });
  act(() => {
    result.current.toggleTag("malware_types", "ransomware");
    result.current.toggleSeverity("Critical");
  });
  act(() => result.current.clearCategory("activeTagFilters"));
  expect(result.current.activeTagFilters).toEqual([]);
  expect(result.current.activeSeverities).toEqual(["Critical"]);
});

test("toggleTag prevents duplicates and toggles off on second call", () => {
  const { result } = renderHook(() => useFilters(), { wrapper });
  act(() => result.current.toggleTag("malware_types", "ransomware"));
  expect(result.current.activeTagFilters).toHaveLength(1);
  act(() => result.current.toggleTag("malware_types", "ransomware"));
  expect(result.current.activeTagFilters).toHaveLength(0);
});

test("toggleTag: same value, different category are distinct entries", () => {
  const { result } = renderHook(() => useFilters(), { wrapper });
  act(() => result.current.toggleTag("malware_types", "x"));
  act(() => result.current.toggleTag("indicator_types", "x"));
  expect(result.current.activeTagFilters).toHaveLength(2);
});
