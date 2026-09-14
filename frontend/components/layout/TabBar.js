const TABS = [
  { value: "feed",       label: "FEED"         },
  { value: "dashboard",  label: "DASHBOARD"    },
  { value: "mitre",      label: "MITRE ATT&CK" },
  { value: "your-stack", label: "YOUR STACK"   },
  { value: "iocs",         label: "IOCs"          },
  { value: "integrations", label: "INTEGRATIONS" },
  { value: "runzero",      label: "RUNZERO"      },
  { value: "detections",   label: "DETECTIONS"   },
  { value: "settings",   label: "SETTINGS"     },
];

export default function TabBar({ activeTab, onTabChange }) {
  return (
    <nav className="flex items-center gap-1 px-4 border-b border-border bg-surface shrink-0">
      {TABS.map((tab) => (
        <button
          key={tab.value}
          onClick={() => onTabChange(tab.value)}
          className={[
            "px-4 py-2 text-xs font-bold tracking-wider border-b-2 -mb-px transition-colors",
            activeTab === tab.value
              ? "border-accent text-accent"
              : "border-transparent text-text-dim hover:text-text",
          ].join(" ")}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
}
