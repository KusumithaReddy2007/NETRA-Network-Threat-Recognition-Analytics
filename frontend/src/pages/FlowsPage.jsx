import {
  ArrowDownUp,
  Database,
  Network,
  Search,
  Activity,
} from "lucide-react";

function FlowsPage({ analytics, flowResults = [] }) {
  const visibleFlows = Array.isArray(flowResults)
    ? flowResults
    : [];
  return (
    <div className="special-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            NETWORK TELEMETRY
          </div>

          <h1>Flow Explorer</h1>

          <p>
            Flow-level metadata processed by the NETRA
            detection engine.
          </p>
        </div>
      </div>

      <div className="flow-toolbar">
        <div className="flow-search">
          <Search size={17} />
          <input placeholder="Search flow ID or network attribute..." />
        </div>

        <button className="secondary-button">
          <ArrowDownUp size={15} />
          SORT
        </button>
      </div>

      <div className="flow-summary">
        <FlowMetric
          icon={Network}
          label="OBSERVED FLOWS"
          value={analytics?.total_flows ?? "—"}
        />

        <FlowMetric
          icon={Activity}
          label="THREAT FLOWS"
          value={analytics?.threat_flows ?? "—"}
        />

        <FlowMetric
          icon={Database}
          label="SOURCE DATA"
          value="CIC-IDS2017"
        />
      </div>

      <div className="flow-panel">
        <div className="special-card-heading">
          <div>
            <span>FLOW INVENTORY</span>
            <h3>Network Telemetry</h3>
          </div>
        </div>

        {visibleFlows.length > 0 ? (
          <div className="flow-table-wrap">
            <table className="investigation-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>EXPECTED</th>
                  <th>PREDICTED</th>
                  <th>CONFIDENCE</th>
                  <th>ALERT</th>
                  <th>SEVERITY</th>
                  <th>LATENCY</th>
                </tr>
              </thead>
              <tbody>
                {visibleFlows.map((flow, index) => (
                  <tr key={index}>
                    <td className="mono-cell">
                      {flow.flow_number}
                    </td>
                    <td>{flow.expected_class}</td>
                    <td>{flow.predicted_class}</td>
                    <td className="confidence-cell">
                      {Number(flow.confidence).toFixed(2)}%
                    </td>
                    <td>
                      {flow.alert_generated ? "YES" : "NO"}
                    </td>
                    <td>
                      {flow.severity || "BENIGN"}
                    </td>
                    <td>
                      {Number(flow.processing_time_ms).toFixed(3)} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flow-empty">
            <Network size={28} />
            <strong>No replayed flows yet</strong>
            <span>
              Run Flow Replay to populate the real processed-flow inventory.
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function FlowMetric({ icon: Icon, label, value }) {
  return (
    <div className="flow-metric">
      <div>
        <Icon size={19} />
      </div>

      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default FlowsPage;
