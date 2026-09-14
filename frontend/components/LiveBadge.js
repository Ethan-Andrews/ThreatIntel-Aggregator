export default function LiveBadge({ lastPoll }) {
  return (
    <div style={badge}>
      <span style={dot} />
      LIVE {lastPoll ? `· Last poll ${lastPoll}` : ""}
    </div>
  );
}
const badge = { display: "flex", alignItems: "center", gap: "0.4rem",
                fontSize: "0.7rem", color: "#00ff88", letterSpacing: "0.08em" };
const dot   = { width: "7px", height: "7px", borderRadius: "50%",
                background: "#00ff88", boxShadow: "0 0 6px #00ff88",
                animation: "pulse 1.5s infinite" };