jest.mock("next/router", () => ({
  useRouter: () => ({
    isReady: true,
    query: {},
    pathname: "/",
    push: jest.fn(),
  }),
}));

import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import DashboardWidgets, { useDeltaCountUp } from "../DashboardWidgets";
import { FilterProvider, useFilters } from "../../../context/FilterContext";

const STATS = {
  total: 1284,
  triaged: 842,
  pending: 312,
  needs_retriage: 5,
  severity: [
    { label: "Critical", count: 40 },
    { label: "High", count: 120 },
  ],
  ttps: [{ technique: "T1059", count: 30 }],
  enrichment: {
    iocs_extracted: 3402,
    sources_active: 14,
    dupes_suppressed: 88,
    last_poll: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  },
  tag_distribution: {
    malware_types: [{ value: "Ransomware", count: 22 }],
    threat_actor_types: [{ value: "APT29", count: 9 }],
    target_sectors: [{ value: "Healthcare", count: 15 }],
    platforms: [{ value: "Windows", count: 60 }],
  },
  ioc_distribution: {
    cves: [{ value: "CVE-2026-1234", count: 7 }],
  },
};

function FilterProbe() {
  const { activeTagFilters, activeIocFilters, activeSeverities, activeTtps } = useFilters();
  return (
    <div data-testid="filter-probe">
      {JSON.stringify({ activeTagFilters, activeIocFilters, activeSeverities, activeTtps })}
    </div>
  );
}

function renderWithProviders(props = {}) {
  global.fetch = jest.fn(() =>
    Promise.resolve({ ok: true, json: async () => STATS })
  );
  return render(
    <FilterProvider>
      <DashboardWidgets apiKey="test-key" onSwitchToFeed={jest.fn()} {...props} />
      <FilterProbe />
    </FilterProvider>
  );
}

describe("DashboardWidgets", () => {
  test("renders the signal masthead totals from real stats", async () => {
    renderWithProviders();
    expect(await screen.findByText("1,284")).toBeInTheDocument();
    expect(screen.getByText("842")).toBeInTheDocument();
    expect(screen.getByText("312")).toBeInTheDocument();
    expect(screen.getByText(/TRIAGED \(66%\)/)).toBeInTheDocument();
  });

  test("shows a relative last-poll time", async () => {
    renderWithProviders();
    expect(await screen.findByText(/LAST POLL 2m ago/)).toBeInTheDocument();
  });

  test("keeps the existing severity and TTP panels", async () => {
    renderWithProviders();
    expect(await screen.findByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("T1059")).toBeInTheDocument();
  });

  test("surfaces previously-unused tag/IOC distribution as ranked panels", async () => {
    renderWithProviders();
    expect(await screen.findByText("Ransomware")).toBeInTheDocument();
    expect(screen.getByText("APT29")).toBeInTheDocument();
    expect(screen.getByText("Healthcare")).toBeInTheDocument();
    expect(screen.getByText("Windows")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-1234")).toBeInTheDocument();
  });

  test("clicking a malware row filters by tag and switches to the feed", async () => {
    const onSwitchToFeed = jest.fn();
    renderWithProviders({ onSwitchToFeed });
    fireEvent.click(await screen.findByText("Ransomware"));

    await waitFor(() => {
      expect(screen.getByTestId("filter-probe").textContent).toContain(
        '"activeTagFilters":[{"category":"malware_types","value":"Ransomware"}]'
      );
    });
    expect(onSwitchToFeed).toHaveBeenCalled();
  });

  test("clicking a CVE row filters by IOC category", async () => {
    renderWithProviders();
    fireEvent.click(await screen.findByText("CVE-2026-1234"));

    await waitFor(() => {
      expect(screen.getByTestId("filter-probe").textContent).toContain(
        '"activeIocFilters":[{"category":"cves","value":"CVE-2026-1234"}]'
      );
    });
  });

  test("clicking a severity bar still filters severity, as before", async () => {
    renderWithProviders();
    fireEvent.click(await screen.findByText("Critical"));

    await waitFor(() => {
      expect(screen.getByTestId("filter-probe").textContent).toContain('"activeSeverities":["Critical"]');
    });
  });

  test("shows the pipeline health ticker strip", async () => {
    renderWithProviders();
    expect(await screen.findByText("SOURCES ACTIVE")).toBeInTheDocument();
    expect(screen.getByText("14")).toBeInTheDocument();
    expect(screen.getByText("3,402")).toBeInTheDocument();
    expect(screen.getByText("88")).toBeInTheDocument();
  });

  test("renders a loading state before stats arrive", () => {
    global.fetch = jest.fn(() => new Promise(() => {}));
    render(
      <FilterProvider>
        <DashboardWidgets apiKey="test-key" onSwitchToFeed={jest.fn()} />
      </FilterProvider>
    );
    expect(screen.getByText(/Establishing link/i)).toBeInTheDocument();
  });

  test("every RankedPanel bar (including Top TTPs) renders a real, non-NaN width", async () => {
    // Regression guard for the originally-suspected symptom -- a key
    // mismatch producing `NaN%` on the Top TTPs bar specifically. Asserts
    // on the actual inline style, not just that the label text renders
    // (text renders fine even under a NaN width, which is exactly what
    // made the original symptom easy to miss).
    renderWithProviders();
    await screen.findByText("T1059");
    const bars = document.querySelectorAll(".h-full.rounded-sm[style*='width']");
    expect(bars.length).toBeGreaterThan(0);
    bars.forEach((bar) => {
      const width = bar.style.width;
      expect(width).toMatch(/^\d+(\.\d+)?%$/);
    });
  });

  test("defaults to the All window and fetches with window=all", async () => {
    renderWithProviders();
    await screen.findByText("1,284");
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining("window=all"),
      expect.anything(),
    );
  });

  test("changing the time-range toggle re-fetches with the new window", async () => {
    renderWithProviders();
    await screen.findByText("1,284");

    fireEvent.click(screen.getByText("7D"));
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining("window=7d"),
        expect.anything(),
      );
    });
  });

  test("export button downloads the current stats as JSON, no extra fetch", async () => {
    // jsdom doesn't implement the Blob URL APIs -- stub them, same as any
    // real browser's download flow (see IocTable.js's identical pattern).
    const createObjectURL = jest.fn(() => "blob:mock-url");
    const revokeObjectURL = jest.fn();
    global.URL.createObjectURL = createObjectURL;
    global.URL.revokeObjectURL = revokeObjectURL;
    const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    renderWithProviders();
    await screen.findByText("1,284");
    const fetchCallsBeforeExport = global.fetch.mock.calls.length;

    fireEvent.click(screen.getByText("EXPORT"));

    // The export is built entirely from stats already in memory -- must
    // not trigger a second network round-trip just to download what's
    // already on screen.
    expect(global.fetch.mock.calls.length).toBe(fetchCallsBeforeExport);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = createObjectURL.mock.calls[0][0];
    expect(blob.type).toBe("application/json");
    // jsdom's Blob has no .text() -- FileReader is what it does support.
    const text = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.readAsText(blob);
    });
    const payload = JSON.parse(text);
    expect(payload.total).toBe(1284);
    expect(payload.window).toBe("all");
    expect(payload.severity).toEqual(STATS.severity);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");

    clickSpy.mockRestore();
  });
});

describe("useDeltaCountUp", () => {
  function Harness({ target }) {
    const { display, delta } = useDeltaCountUp(target, /* reduceMotion */ true);
    return <div data-testid="harness">{display}:{delta}</div>;
  }

  test("shows no delta on first mount", () => {
    render(<Harness target={30} />);
    expect(screen.getByTestId("harness").textContent).toBe("30:0");
  });

  test("shows the positive delta when target increases, then clears it after the hold window", () => {
    jest.useFakeTimers();
    const { rerender } = render(<Harness target={30} />);
    rerender(<Harness target={45} />);
    expect(screen.getByTestId("harness").textContent).toBe("45:15");

    act(() => {
      jest.advanceTimersByTime(1500);
    });
    expect(screen.getByTestId("harness").textContent).toBe("45:0");
    jest.useRealTimers();
  });

  test("does not show a delta when the target decreases", () => {
    const { rerender } = render(<Harness target={30} />);
    rerender(<Harness target={20} />);
    expect(screen.getByTestId("harness").textContent).toBe("20:0");
  });
});
