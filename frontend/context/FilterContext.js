import { createContext, useContext, useReducer, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";

const FilterContext = createContext(null);

function toggleItem(arr, item) {
  return arr.includes(item) ? arr.filter((x) => x !== item) : [...arr, item];
}

function toggleTagItem(arr, category, value) {
  const exists = arr.some((f) => f.category === category && f.value === value);
  return exists
    ? arr.filter((f) => !(f.category === category && f.value === value))
    : [...arr, { category, value }];
}

const initialState = {
  activeSources:     [],
  activeSeverities:  [],
  activeTagFilters:  [],
  activeIocFilters:  [],
  activeTtps:        [],
  search:            "",
  showDuplicates:    false,
  dateWindow:        "7d",
};

function reducer(state, action) {
  switch (action.type) {
    case "TOGGLE_SOURCE":
      return { ...state, activeSources: toggleItem(state.activeSources, action.value) };
    case "TOGGLE_SEVERITY":
      return { ...state, activeSeverities: toggleItem(state.activeSeverities, action.value) };
    case "TOGGLE_TAG":
      return { ...state, activeTagFilters: toggleTagItem(state.activeTagFilters, action.category, action.value) };
    case "TOGGLE_IOC":
      return { ...state, activeIocFilters: toggleTagItem(state.activeIocFilters, action.category, action.value) };
    case "TOGGLE_TTP":
      return { ...state, activeTtps: toggleItem(state.activeTtps, action.value) };
    case "SET_SEARCH":
      return { ...state, search: action.value };
    case "TOGGLE_DUPLICATES":
      return { ...state, showDuplicates: !state.showDuplicates };
    case "SET_DATE_WINDOW":
      return { ...state, dateWindow: action.value };
    case "CLEAR_ALL":
      return { ...initialState };
    case "CLEAR_CATEGORY": {
      const cur = state[action.category];
      const cleared = Array.isArray(cur) ? [] : typeof cur === "boolean" ? false : "";
      return { ...state, [action.category]: cleared };
    }
    case "HYDRATE":
      return { ...state, ...action.payload };
    default:
      return state;
  }
}

function serializeFilters(state) {
  const params = new URLSearchParams();
  state.activeSources.forEach((s)    => params.append("src",  s));
  state.activeSeverities.forEach((s) => params.append("sev",  s));
  state.activeTtps.forEach((t)       => params.append("ttp",  t));
  state.activeTagFilters.forEach((f) => { params.append("tc", f.category); params.append("tv", f.value); });
  state.activeIocFilters.forEach((f) => { params.append("ic", f.category); params.append("iv", f.value); });
  if (state.search)         params.set("q",    state.search);
  if (state.showDuplicates) params.set("dups", "1");
  if (state.dateWindow)     params.set("dw",   state.dateWindow);
  return params;
}

function deserializeFilters(query) {
  const src  = [].concat(query.src  || []);
  const sev  = [].concat(query.sev  || []);
  const ttp  = [].concat(query.ttp  || []);
  const tc   = [].concat(query.tc   || []);
  const tv   = [].concat(query.tv   || []);
  const ic   = [].concat(query.ic   || []);
  const iv   = [].concat(query.iv   || []);
  const tags = tc.map((c, i) => ({ category: c, value: tv[i] || "" })).filter((f) => f.value);
  const iocs = ic.map((c, i) => ({ category: c, value: iv[i] || "" })).filter((f) => f.value);
  return {
    activeSources:    src,
    activeSeverities: sev,
    activeTtps:       ttp,
    activeTagFilters: tags,
    activeIocFilters: iocs,
    search:           query.q    || "",
    showDuplicates:   query.dups === "1",
    dateWindow:       query.dw   || "7d",
  };
}

export function FilterProvider({ children }) {
  const router = useRouter();
  const [state, dispatch] = useReducer(reducer, initialState);
  const [isHydrated, setIsHydrated] = useState(false);
  const [stackMatchOnly, setStackMatchOnly] = useState(false);
  const toggleStackMatchOnly = useCallback(() => setStackMatchOnly((v) => !v), []);

  // Hydrate from URL on mount
  useEffect(() => {
    if (!router.isReady) return;
    const hydrated = deserializeFilters(router.query);
    const hasAny = Object.values(hydrated).some((v) =>
      Array.isArray(v) ? v.length > 0 : Boolean(v)
    );
    if (hasAny) dispatch({ type: "HYDRATE", payload: hydrated });
    setIsHydrated(true);
  }, [router.isReady]); // eslint-disable-line react-hooks/exhaustive-deps

  // Sync state → URL (only after hydration)
  useEffect(() => {
    if (!isHydrated) return;
    const params = serializeFilters(state);
    router.push({ pathname: router.pathname, query: Object.fromEntries(params) }, undefined, { shallow: true });
  }, [state, isHydrated]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggleSource     = useCallback((v)    => dispatch({ type: "TOGGLE_SOURCE",    value: v }),     []);
  const toggleSeverity   = useCallback((v)    => dispatch({ type: "TOGGLE_SEVERITY",  value: v }),     []);
  const toggleTag        = useCallback((c, v) => dispatch({ type: "TOGGLE_TAG",       category: c, value: v }), []);
  const toggleIoc        = useCallback((c, v) => dispatch({ type: "TOGGLE_IOC",       category: c, value: v }), []);
  const toggleTtp        = useCallback((v)    => dispatch({ type: "TOGGLE_TTP",       value: v }),     []);
  const setSearch        = useCallback((v)    => dispatch({ type: "SET_SEARCH",       value: v }),     []);
  const toggleDuplicates = useCallback(()     => dispatch({ type: "TOGGLE_DUPLICATES" }),              []);
  const setDateWindow    = useCallback((v)    => dispatch({ type: "SET_DATE_WINDOW", value: v }),      []);
  const clearAll         = useCallback(()     => dispatch({ type: "CLEAR_ALL" }),                      []);
  const clearCategory    = useCallback((cat)  => dispatch({ type: "CLEAR_CATEGORY",   category: cat }), []);

  return (
    <FilterContext.Provider value={{
      ...state,
      toggleSource, toggleSeverity, toggleTag, toggleIoc, toggleTtp,
      setSearch, toggleDuplicates, setDateWindow, clearAll, clearCategory,
      stackMatchOnly, toggleStackMatchOnly,
    }}>
      {children}
    </FilterContext.Provider>
  );
}

export function useFilters() {
  const ctx = useContext(FilterContext);
  if (!ctx) throw new Error("useFilters must be used inside FilterProvider");
  return ctx;
}
