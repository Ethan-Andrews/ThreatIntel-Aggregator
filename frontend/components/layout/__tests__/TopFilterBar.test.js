jest.mock("next/router", () => ({
  useRouter: () => ({
    isReady: true,
    query: {},
    pathname: "/",
    push: jest.fn(),
    replace: jest.fn(),
  }),
}));

import { render, screen, fireEvent } from "@testing-library/react";
import TopFilterBar from "../TopFilterBar";
import { FilterProvider } from "../../../context/FilterContext";

function renderBar(props = {}) {
  return render(
    <FilterProvider>
      <TopFilterBar tagDistribution={{}} iocDistribution={{}} {...props} />
    </FilterProvider>
  );
}

describe("TopFilterBar TTPs dropdown", () => {
  test("shows 'No data' when ttpDistribution is empty/unset", () => {
    renderBar({ ttpDistribution: [] });
    fireEvent.click(screen.getByText("TTPs"));
    expect(screen.getByText("No data")).toBeInTheDocument();
  });

  test("populates from the ttpDistribution prop, not from tagDistribution.ttps", () => {
    // Regression test: dashboard/stats returns `ttps` as a top-level
    // sibling of `tag_distribution`, not nested inside it. A prior bug had
    // TopFilterBar reading `tagDistribution.ttps` (always undefined) and
    // the dropdown permanently showed "No data" regardless of real data.
    renderBar({
      tagDistribution: { malware_types: [{ value: "Ransomware", count: 2 }] },
      ttpDistribution: [
        { value: "T1190", count: 969 },
        { value: "T1566.002", count: 799 },
      ],
    });
    fireEvent.click(screen.getByText("TTPs"));
    expect(screen.getByText("T1190")).toBeInTheDocument();
    expect(screen.getByText("T1566.002")).toBeInTheDocument();
    expect(screen.queryByText("No data")).not.toBeInTheDocument();
  });

  test("checking a TTP row toggles it into the active-filter chips", () => {
    renderBar({ ttpDistribution: [{ value: "T1190", count: 969 }] });
    fireEvent.click(screen.getByText("TTPs"));
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getAllByText("T1190").length).toBeGreaterThan(1); // dropdown row + chip
  });
});
