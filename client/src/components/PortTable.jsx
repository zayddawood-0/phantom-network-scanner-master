export default function PortTable({ ports }) {

  const riskColor = {
    Critical: "#ff4d4d",
    High: "#f85149",
    Medium: "#d29922",
    Low: "#3fb950",
    None: "var(--dim)"
  };

  const pillStyle = (status) => ({
    padding: "2px 8px",
    borderRadius: "4px",
    fontSize: "11px",
    fontWeight: "600",
    textTransform: "uppercase",
    letterSpacing: "0.3px",
    background:
      status === "open"
        ? "rgba(63, 185, 80, 0.12)"
        : status === "filtered"
        ? "rgba(210, 153, 34, 0.12)"
        : "rgba(255,255,255,0.05)",
    color:
      status === "open"
        ? "#3fb950"
        : status === "filtered"
        ? "#d29922"
        : "var(--dim)",
    border:
      status === "open"
        ? "1px solid rgba(63,185,80,0.25)"
        : status === "filtered"
        ? "1px solid rgba(210,153,34,0.25)"
        : "1px solid var(--border2)"
  });

  return (
    <div className="p-table-wrap">
      <table className="p-table">

        <thead>
          <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
            <th>Risk</th>
          </tr>
        </thead>

        <tbody>
          {ports.map((p, i) => (
            <tr key={i}>

              {/* PORT */}
              <td className="p-port-num">
                {p.port_number}/tcp
              </td>

              {/* STATUS */}
              <td>
                <span style={pillStyle(p.status)}>
                  {p.status}
                </span>
              </td>

              {/* SERVICE */}
              <td style={{ color: "var(--muted)" }}>
                {p.service || "-"}
              </td>

              {/* VERSION (NEW) */}
              <td style={{ color: "var(--dim)", fontSize: "12px" }}>
                {p.product || ""}{" "}
                {p.version || ""}
                {(!p.product && !p.version) && "-"}
              </td>

              {/* RISK */}
              <td
                style={{
                  fontSize: "11px",
                  fontWeight: "700",
                  color:
                    p.status === "open"
                      ? (riskColor[p.risk] || riskColor.Low)
                      : "var(--dim)"
                }}
              >
                {p.status === "open" ? p.risk : "—"}
              </td>

            </tr>
          ))}
        </tbody>

      </table>
    </div>
  );
}