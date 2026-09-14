import React, { useState, useEffect, useCallback, useRef } from "react";
import { useFilters } from "../../context/FilterContext";

const API = process.env.NEXT_PUBLIC_API_URL || "";

function currentToken(fallback) {
  if (typeof window === "undefined") return fallback || "";
  return sessionStorage.getItem("ti_app_token") || fallback || "";
}

const MITRE_MATRIX = [
  {
    id: "TA0043", name: "Reconnaissance", short: "RECON", color: "#4a90d9",
    techniques: [
      { id: "T1595", name: "Active Scanning" },
      { id: "T1592", name: "Host Info Gather" },
      { id: "T1589", name: "Identity Info Gather" },
      { id: "T1590", name: "Network Info Gather" },
      { id: "T1591", name: "Org Info Gather" },
      { id: "T1598", name: "Phishing for Info" },
      { id: "T1597", name: "Search Closed Sources" },
      { id: "T1596", name: "Search Tech DBs" },
      { id: "T1593", name: "Search Open Web" },
      { id: "T1594", name: "Search Victim Sites" },
    ],
  },
  {
    id: "TA0042", name: "Resource Dev", short: "RESDEV", color: "#5b8dd9",
    techniques: [
      { id: "T1583", name: "Acquire Infrastructure" },
      { id: "T1586", name: "Compromise Accounts" },
      { id: "T1584", name: "Compromise Infra" },
      { id: "T1587", name: "Develop Capabilities" },
      { id: "T1585", name: "Establish Accounts" },
      { id: "T1588", name: "Obtain Capabilities" },
      { id: "T1608", name: "Stage Capabilities" },
    ],
  },
  {
    id: "TA0001", name: "Initial Access", short: "INIT", color: "#4aaa8a",
    techniques: [
      { id: "T1189", name: "Drive-by Compromise" },
      { id: "T1190", name: "Exploit Public App" },
      { id: "T1133", name: "External Remote Svcs" },
      { id: "T1200", name: "Hardware Additions" },
      { id: "T1566", name: "Phishing" },
      { id: "T1091", name: "Removable Media" },
      { id: "T1195", name: "Supply Chain" },
      { id: "T1199", name: "Trusted Relationship" },
      { id: "T1078", name: "Valid Accounts" },
    ],
  },
  {
    id: "TA0002", name: "Execution", short: "EXEC", color: "#6aaa4a",
    techniques: [
      { id: "T1059", name: "Command Interpreter" },
      { id: "T1609", name: "Container Admin Cmd" },
      { id: "T1203", name: "Client Exec Exploit" },
      { id: "T1559", name: "Inter-Process Comm" },
      { id: "T1106", name: "Native API" },
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1129", name: "Shared Modules" },
      { id: "T1072", name: "Software Deploy Tools" },
      { id: "T1569", name: "System Services" },
      { id: "T1204", name: "User Execution" },
      { id: "T1047", name: "WMI" },
    ],
  },
  {
    id: "TA0003", name: "Persistence", short: "PERSIST", color: "#8aaa3a",
    techniques: [
      { id: "T1098", name: "Account Manipulation" },
      { id: "T1197", name: "BITS Jobs" },
      { id: "T1547", name: "Boot/Logon Autostart" },
      { id: "T1037", name: "Boot/Logon Init Scripts" },
      { id: "T1176", name: "Browser Extensions" },
      { id: "T1136", name: "Create Account" },
      { id: "T1543", name: "Create System Process" },
      { id: "T1546", name: "Event Triggered Exec" },
      { id: "T1574", name: "Hijack Exec Flow" },
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1505", name: "Server Software Comp" },
      { id: "T1078", name: "Valid Accounts" },
    ],
  },
  {
    id: "TA0004", name: "Priv Escalation", short: "PRIVESC", color: "#aaaa30",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Ctrl" },
      { id: "T1134", name: "Access Token Manip" },
      { id: "T1547", name: "Boot/Logon Autostart" },
      { id: "T1543", name: "Create System Process" },
      { id: "T1546", name: "Event Triggered Exec" },
      { id: "T1068", name: "Exploit for PrivEsc" },
      { id: "T1574", name: "Hijack Exec Flow" },
      { id: "T1055", name: "Process Injection" },
      { id: "T1053", name: "Scheduled Task/Job" },
      { id: "T1078", name: "Valid Accounts" },
    ],
  },
  {
    id: "TA0005", name: "Defense Evasion", short: "DEFEVAS", color: "#aa8020",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Ctrl" },
      { id: "T1140", name: "Deobfuscate/Decode" },
      { id: "T1006", name: "Direct Volume Access" },
      { id: "T1564", name: "Hide Artifacts" },
      { id: "T1574", name: "Hijack Exec Flow" },
      { id: "T1562", name: "Impair Defenses" },
      { id: "T1070", name: "Indicator Removal" },
      { id: "T1036", name: "Masquerading" },
      { id: "T1112", name: "Modify Registry" },
      { id: "T1027", name: "Obfuscated Files" },
      { id: "T1055", name: "Process Injection" },
      { id: "T1014", name: "Rootkit" },
      { id: "T1218", name: "Signed Binary Proxy" },
      { id: "T1553", name: "Subvert Trust Ctrl" },
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1497", name: "Virt/Sandbox Evasion" },
    ],
  },
  {
    id: "TA0006", name: "Credential Access", short: "CREDACC", color: "#aa6a20",
    techniques: [
      { id: "T1110", name: "Brute Force" },
      { id: "T1555", name: "Creds from Stores" },
      { id: "T1212", name: "Exploit for Creds" },
      { id: "T1187", name: "Forced Authentication" },
      { id: "T1606", name: "Forge Web Credentials" },
      { id: "T1056", name: "Input Capture" },
      { id: "T1557", name: "MitM / AiTM" },
      { id: "T1556", name: "Modify Auth Process" },
      { id: "T1528", name: "Steal App Access Token" },
      { id: "T1558", name: "Steal Kerberos Ticket" },
      { id: "T1539", name: "Steal Web Session Cookie" },
    ],
  },
  {
    id: "TA0007", name: "Discovery", short: "DISCO", color: "#aa5020",
    techniques: [
      { id: "T1087", name: "Account Discovery" },
      { id: "T1010", name: "App Window Discovery" },
      { id: "T1580", name: "Cloud Infra Discovery" },
      { id: "T1538", name: "Cloud Service Dashboard" },
      { id: "T1526", name: "Cloud Service Discovery" },
      { id: "T1482", name: "Domain Trust Discovery" },
      { id: "T1083", name: "File & Dir Discovery" },
      { id: "T1046", name: "Network Service Scan" },
      { id: "T1135", name: "Network Share Discovery" },
      { id: "T1057", name: "Process Discovery" },
      { id: "T1018", name: "Remote System Discovery" },
      { id: "T1082", name: "System Info Discovery" },
      { id: "T1016", name: "System Network Config" },
      { id: "T1033", name: "System Owner/User" },
      { id: "T1007", name: "System Service Discovery" },
    ],
  },
  {
    id: "TA0008", name: "Lateral Movement", short: "LATMOV", color: "#aa3828",
    techniques: [
      { id: "T1210", name: "Exploit Remote Svcs" },
      { id: "T1534", name: "Internal Spearphishing" },
      { id: "T1570", name: "Lateral Tool Transfer" },
      { id: "T1563", name: "Remote Svc Session Hijack" },
      { id: "T1021", name: "Remote Services" },
      { id: "T1091", name: "Removable Media" },
      { id: "T1072", name: "Software Deploy Tools" },
      { id: "T1080", name: "Taint Shared Content" },
      { id: "T1550", name: "Use Alternate Auth" },
    ],
  },
  {
    id: "TA0009", name: "Collection", short: "COLLECT", color: "#aa2838",
    techniques: [
      { id: "T1557", name: "AiTM" },
      { id: "T1560", name: "Archive Collected Data" },
      { id: "T1123", name: "Audio Capture" },
      { id: "T1119", name: "Automated Collection" },
      { id: "T1115", name: "Clipboard Data" },
      { id: "T1530", name: "Data from Cloud Storage" },
      { id: "T1213", name: "Data from Info Repos" },
      { id: "T1005", name: "Data from Local System" },
      { id: "T1039", name: "Data from Network Drive" },
      { id: "T1114", name: "Email Collection" },
      { id: "T1056", name: "Input Capture" },
      { id: "T1113", name: "Screen Capture" },
      { id: "T1125", name: "Video Capture" },
    ],
  },
  {
    id: "TA0011", name: "Command & Control", short: "C2", color: "#8a2055",
    techniques: [
      { id: "T1071", name: "App Layer Protocol" },
      { id: "T1092", name: "Comm via Removable Media" },
      { id: "T1132", name: "Data Encoding" },
      { id: "T1001", name: "Data Obfuscation" },
      { id: "T1568", name: "Dynamic Resolution" },
      { id: "T1573", name: "Encrypted Channel" },
      { id: "T1008", name: "Fallback Channels" },
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1104", name: "Multi-Stage Channels" },
      { id: "T1095", name: "Non-App Layer Protocol" },
      { id: "T1572", name: "Protocol Tunneling" },
      { id: "T1090", name: "Proxy" },
      { id: "T1219", name: "Remote Access Software" },
      { id: "T1205", name: "Traffic Signaling" },
      { id: "T1102", name: "Web Service" },
    ],
  },
  {
    id: "TA0010", name: "Exfiltration", short: "EXFIL", color: "#7a1068",
    techniques: [
      { id: "T1020", name: "Automated Exfiltration" },
      { id: "T1030", name: "Data Transfer Size Limit" },
      { id: "T1048", name: "Exfil Over Alt Protocol" },
      { id: "T1041", name: "Exfil Over C2 Channel" },
      { id: "T1011", name: "Exfil Over Other Network" },
      { id: "T1052", name: "Exfil Over Physical" },
      { id: "T1567", name: "Exfil Over Web Service" },
      { id: "T1029", name: "Scheduled Transfer" },
    ],
  },
  {
    id: "TA0040", name: "Impact", short: "IMPACT", color: "#6a0858",
    techniques: [
      { id: "T1531", name: "Account Access Removal" },
      { id: "T1485", name: "Data Destruction" },
      { id: "T1486", name: "Data Encrypted/Ransom" },
      { id: "T1565", name: "Data Manipulation" },
      { id: "T1491", name: "Defacement" },
      { id: "T1561", name: "Disk Wipe" },
      { id: "T1499", name: "Endpoint DoS" },
      { id: "T1495", name: "Firmware Corruption" },
      { id: "T1490", name: "Inhibit System Recovery" },
      { id: "T1498", name: "Network DoS" },
      { id: "T1496", name: "Resource Hijacking" },
      { id: "T1489", name: "Service Stop" },
      { id: "T1529", name: "System Shutdown/Reboot" },
    ],
  },
];

export default function MitreMatrix({ apiKey, onSwitchToFeed }) {
  const [coverage, setCoverage] = useState({});
  const { activeTtps, toggleTtp } = useFilters();

  // Zoom / pan state
  const [zoom, setZoom]       = useState(1);
  const [pan, setPan]         = useState({ x: 0, y: 0 });
  const dragging              = useRef(false);
  const lastPos               = useRef({ x: 0, y: 0 });
  const containerRef          = useRef(null);

  // Technique options modal
  const [selectedTech, setSelectedTech] = useState(null);

  const fetchCoverage = useCallback(() => {
    const token = currentToken(apiKey);
    if (!token) return;
    fetch(`${API}/api/mitre/coverage`, {
      headers: { Authorization: "Bearer " + token },
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`mitre ${r.status}`))))
      .then((d) => setCoverage(d || {}))
      .catch(() => {});
  }, [apiKey]);

  useEffect(() => {
    fetchCoverage();
    const interval = setInterval(fetchCoverage, 60000);
    return () => clearInterval(interval);
  }, [fetchCoverage]);

  // Wheel zoom — zoom toward cursor position
  function handleWheel(e) {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.1 : -0.1;
    setZoom((z) => Math.min(2.5, Math.max(0.3, z + delta)));
  }

  function handlePointerDown(e) {
    if (e.button !== 0) return;
    // Don't capture on buttons — let clicks propagate normally
    if (e.target.tagName === "BUTTON" || e.target.closest("button")) return;
    dragging.current = true;
    lastPos.current = { x: e.clientX, y: e.clientY };
    e.currentTarget.setPointerCapture(e.pointerId);
  }

  function handlePointerMove(e) {
    if (!dragging.current) return;
    const dx = e.clientX - lastPos.current.x;
    const dy = e.clientY - lastPos.current.y;
    lastPos.current = { x: e.clientX, y: e.clientY };
    setPan((p) => ({ x: p.x + dx, y: p.y + dy }));
  }

  function handlePointerUp() {
    dragging.current = false;
  }

  function handleReset() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  // Convert hex color to RGB object
  function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16),
    } : null;
  }

  // Vibrancy: normalize by max count, log scale for better differentiation (0.15 to 0.95)
  function getVibrancyAlpha(count, maxCount = 1) {
    if (!count || maxCount <= 0) return 0.15;
    // Log scale: gives more spread across the range
    const normalized = Math.log(count + 1) / Math.log(maxCount + 1);
    return Math.max(0.15, Math.min(0.15 + normalized * 0.8, 0.95));
  }

  function handleTechniqueClick(id) {
    // Only fire click if we weren't dragging
    if (!dragging.current) setSelectedTech(id);
  }

  function handleViewMitrePage() {
    if (selectedTech) {
      window.open(`https://attack.mitre.org/techniques/${selectedTech}/`, "_blank");
      setSelectedTech(null);
    }
  }

  function handleFilterFeed() {
    if (selectedTech) {
      toggleTtp(selectedTech);
      setSelectedTech(null);
      onSwitchToFeed?.();
    }
  }

  const observedTechniques      = new Set(Object.keys(coverage));
  const observedTactics         = MITRE_MATRIX.filter((tac) =>
    tac.techniques.some((t) => observedTechniques.has(t.id))
  ).length;
  const totalTechniquesObserved = observedTechniques.size;
  const maxCount                = Math.max(...Object.values(coverage), 1);

  return (
    <div className="p-4 flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center justify-between mb-3 shrink-0">
        <span className="text-xs text-text-dim">
          {totalTechniquesObserved} techniques observed across {observedTactics} of {MITRE_MATRIX.length} tactics
        </span>
        <div className="flex items-center gap-2">
          {activeTtps.length > 0 && (
            <button
              onClick={onSwitchToFeed}
              className="text-xs border border-accent text-accent rounded-sm px-2 py-0.5 hover:bg-accent hover:text-background transition-colors"
            >
              View in Feed →
            </button>
          )}
          {/* Zoom controls */}
          <div className="flex items-center gap-1 border border-border rounded-sm px-1">
            <button
              onClick={() => setZoom((z) => Math.max(0.3, +(z - 0.1).toFixed(1)))}
              className="text-text-dim hover:text-text w-5 text-center text-sm leading-none select-none"
              title="Zoom out"
            >−</button>
            <span className="text-[10px] text-text-dim w-10 text-center select-none">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom((z) => Math.min(2.5, +(z + 0.1).toFixed(1)))}
              className="text-text-dim hover:text-text w-5 text-center text-sm leading-none select-none"
              title="Zoom in"
            >+</button>
          </div>
          <button
            onClick={handleReset}
            className="text-[10px] text-text-dim border border-border rounded-sm px-2 py-0.5 hover:text-text hover:border-text transition-colors"
            title="Reset zoom and pan"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Pan/zoom canvas */}
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden rounded-sm border border-border relative select-none"
        style={{ cursor: dragging.current ? "grabbing" : "grab", minHeight: 0 }}
        onWheel={handleWheel}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
      >
        <div
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "top left",
            display: "inline-flex",
            gap: 4,
            padding: 8,
          }}
        >
          {MITRE_MATRIX.map((tactic) => (
            <div key={tactic.id} className="flex flex-col" style={{ width: 82 }}>
              <div
                className="text-[8px] font-bold text-center py-0.5 rounded-t border border-b-0 border-border tracking-wider"
                style={{ background: tactic.color + "22", color: tactic.color }}
              >
                {tactic.short}
              </div>
              <div className="border border-border rounded-b overflow-hidden">
                {tactic.techniques.map((tech) => {
                  const count    = coverage[tech.id] || 0;
                  const selected = activeTtps.includes(tech.id);
                  const rgb      = hexToRgb(tactic.color);
                  const alpha    = getVibrancyAlpha(count, maxCount);
                  const bgColor  = rgb ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})` : undefined;
                  return (
                    <button
                      key={tech.id}
                      onClick={() => handleTechniqueClick(tech.id)}
                      title={`${tech.id} — ${tech.name} (${count} entries)`}
                      style={!selected && count > 0
                        ? { backgroundColor: bgColor }
                        : undefined}
                      className={[
                        "w-full text-left px-1 py-px text-[8px] border-b border-border last:border-0 transition-all leading-tight",
                        selected ? "bg-accent text-background font-bold" :
                        count > 0 ? "text-white hover:brightness-125" :
                                    "text-text-dim hover:bg-border",
                      ].join(" ")}
                    >
                      <span className="font-mono opacity-60">{tech.id}</span>
                      {count > 0 && <span className="float-right font-bold text-[7px] opacity-90">{count}</span>}
                      <span className="block truncate">{tech.name}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        {/* Zoom hint */}
        <div className="absolute bottom-2 right-2 text-[9px] text-text-dim pointer-events-none opacity-50">
          Scroll to zoom · Drag to pan
        </div>
      </div>

      {/* Technique options modal */}
      {selectedTech && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-sm w-full mx-4 shadow-lg">
            <div className="mb-4">
              <div className="text-sm font-bold text-text mb-1">{selectedTech}</div>
              <div className="text-xs text-text-dim">
                {MITRE_MATRIX.flatMap(t => t.techniques).find(t => t.id === selectedTech)?.name || ""}
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <button
                onClick={handleViewMitrePage}
                className="w-full text-sm border border-accent text-accent rounded-sm px-3 py-2 hover:bg-accent hover:text-background transition-colors font-medium"
              >
                View MITRE ATT&CK Page
              </button>
              <button
                onClick={handleFilterFeed}
                className="w-full text-sm border border-accent text-accent rounded-sm px-3 py-2 hover:bg-accent hover:text-background transition-colors font-medium"
              >
                Filter Feed with This TTP
              </button>
              <button
                onClick={() => setSelectedTech(null)}
                className="w-full text-sm border border-border text-text-dim rounded-sm px-3 py-2 hover:text-text hover:border-text transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
