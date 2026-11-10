import {
  Download,
  FileBarChart,
  FileText,
  Printer,
  ShieldCheck,
} from "lucide-react";

function ReportsPage({ analytics }) {
  const threatTypes = Object.entries(
    analytics?.threat_types || {},
  )
    .map(([name, value]) => ({
      name,
      value: Number(value) || 0,
    }))
    .sort((a, b) => {
      const order = [
        "DDOS",
        "DOS",
        "PORTSCAN",
        "BRUTE_FORCE",
        "BOT",
        "BOT_C2",
        "DGA",
        "DNS_TUNNEL",
        "DNS_RECORD_ANOMALY",
        "EXFILTRATION",
      ];

      const aIndex = order.indexOf(
        String(a.name).toUpperCase(),
      );

      const bIndex = order.indexOf(
        String(b.name).toUpperCase(),
      );

      if (aIndex !== -1 && bIndex !== -1) {
        return aIndex - bIndex;
      }

      if (aIndex !== -1) return -1;
      if (bIndex !== -1) return 1;

      return b.value - a.value;
    });

  const severity = analytics?.severity_breakdown || {};

  const critical = Number(severity.CRITICAL || 0);
  const high = Number(severity.HIGH || 0);
  const totalThreats = critical + high;

  const processing = analytics?.processing || {};

  const exportJSON = () => {
    const report = buildReportPayload(
      analytics,
      threatTypes,
      severity,
    );

    downloadFile(
      JSON.stringify(report, null, 2),
      "application/json",
      `netra-security-report-${timestampForFile()}.json`,
    );
  };

  const exportCSV = () => {
    const rows = threatTypes.map((item) => [
      displayThreat(item.name),
      item.value,
      getNtroCategory(item.name),
    ]);

    const csv = [
      ["Threat Type", "Count", "NTRO Category"],
      ...rows,
      [],
      ["Total Flows", analytics?.total_flows ?? ""],
      ["Benign Flows", analytics?.benign_flows ?? ""],
      ["Threat Flows", analytics?.threat_flows ?? ""],
      ["Threat Rate", `${analytics?.threat_percentage ?? 0}%`],
      ["Critical", critical],
      ["High", high],
      [
        "Replay Throughput",
        `${processing.flows_per_second ?? 0} flows/s`,
      ],
      [
        "Processing Time",
        `${processing.total_time_seconds ?? 0}s`,
      ],
    ]
      .map((row) => row.map(csvCell).join(","))
      .join("\n");

    downloadFile(
      csv,
      "text/csv;charset=utf-8;",
      `netra-security-report-${timestampForFile()}.csv`,
    );
  };

  const printReport = () => {
    window.print();
  };

  const topThreats = threatTypes.slice(0, 5);

  const averageConfidence =
    analytics?.average_confidence ??
    analytics?.processing?.average_confidence;

  return (
    <div className="special-page reports-page">
      <div className="page-heading report-page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SECURITY REPORTING
          </div>

          <h1>Reports</h1>

          <p>
            Generate a security summary from the current
            NETRA replay analysis window.
          </p>
        </div>

        <div className="report-toolbar">
          <button
            className="secondary-button"
            onClick={printReport}
            disabled={!analytics}
          >
            <Printer size={15} />
            PRINT / PDF
          </button>

          <button
            className="primary-button"
            onClick={exportCSV}
            disabled={!analytics}
          >
            <Download size={15} />
            EXPORT CSV
          </button>

          <button
            className="primary-button"
            onClick={exportJSON}
            disabled={!analytics}
          >
            <Download size={15} />
            EXPORT JSON
          </button>
        </div>
      </div>

      <div className="report-context-strip">
        <span>
          REPORT WINDOW <strong>CURRENT REPLAY ANALYSIS</strong>
        </span>
        <span>
          DATA SOURCE <strong>CIC-IDS2017-DERIVED</strong>
        </span>
        <span>
          MODE <strong>PASSIVE / READ-ONLY</strong>
        </span>
        <span>
          GENERATED <strong>{formatDateTime(new Date())}</strong>
        </span>
      </div>

      <div className="report-sheet">
        <div className="report-header">
          <div>
            <div className="report-brand">
              <ShieldCheck size={23} />
              NETRA
            </div>

            <span>
              NETWORK THREAT RECOGNITION & ANALYTICS
            </span>
          </div>

          <FileBarChart size={28} />
        </div>

        <div className="report-title">
          <span>SECURITY ANALYSIS REPORT</span>
          <h2>Network Threat Summary</h2>
          <p>
            Generated from the current NETRA replay analytics
            window.
          </p>
        </div>

        <section className="report-section report-executive">
          <h3>Executive Summary</h3>

          <div className="report-grid">
            <ReportValue
              label="TOTAL FLOWS"
              value={analytics?.total_flows ?? "—"}
            />

            <ReportValue
              label="BENIGN FLOWS"
              value={analytics?.benign_flows ?? "—"}
            />

            <ReportValue
              label="THREAT FLOWS"
              value={analytics?.threat_flows ?? "—"}
            />

            <ReportValue
              label="THREAT RATE"
              value={`${analytics?.threat_percentage ?? 0}%`}
            />
          </div>

          <div className="report-summary-callout">
            <div>
              <span>STATUS</span>
              <strong>
                {Number(analytics?.threat_percentage || 0) > 50
                  ? "ELEVATED THREAT ACTIVITY"
                  : "MONITORING WITHIN CURRENT WINDOW"}
              </strong>
            </div>

            <div>
              <span>AVERAGE CONFIDENCE</span>
              <strong>
                {Number.isFinite(Number(averageConfidence))
                  ? `${Number(averageConfidence).toFixed(2)}%`
                  : "N/A"}
              </strong>
            </div>
          </div>
        </section>

        <section className="report-section">
          <h3>Detection Summary</h3>

          {threatTypes.length ? (
            <div className="report-table-wrap">
              <table className="report-table">
                <thead>
                  <tr>
                    <th>THREAT TYPE</th>
                    <th>COUNT</th>
                    <th>NTRO CATEGORY</th>
                    <th>% OF THREATS</th>
                  </tr>
                </thead>

                <tbody>
                  {threatTypes.map((item) => (
                    <tr key={item.name}>
                      <td>
                        <strong>
                          {displayThreat(item.name)}
                        </strong>
                      </td>

                      <td>{item.value}</td>

                      <td>{getNtroCategory(item.name)}</td>

                      <td>
                        {analytics?.threat_flows
                          ? (
                              (item.value /
                                Number(
                                  analytics.threat_flows,
                                )) *
                              100
                            ).toFixed(1)
                          : "0.0"}
                        %
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="report-empty">
              No threat classification data is available.
            </div>
          )}
        </section>

        <section className="report-two-column">
          <div className="report-section">
            <h3>Severity Distribution</h3>

            <div className="report-severity-list">
              <ReportSeverity
                label="CRITICAL"
                value={critical}
                total={totalThreats}
              />

              <ReportSeverity
                label="HIGH"
                value={high}
                total={totalThreats}
              />
            </div>

            <div className="report-total-severity">
              TOTAL ALERTS <strong>{totalThreats}</strong>
            </div>
          </div>

          <div className="report-section">
            <h3>Engine Performance</h3>

            <div className="report-performance-grid">
              <ReportPerformance
                label="REPLAY THROUGHPUT"
                value={`${processing.flows_per_second ?? 0} flows/s`}
              />

              <ReportPerformance
                label="PROCESSING TIME"
                value={`${processing.total_time_seconds ?? 0}s`}
              />

              <ReportPerformance
                label="STREAMING BENCHMARK"
                value="103.79 flows/sec"
              />

              <ReportPerformance
                label="BENCHMARK FLOWS"
                value="10,000"
              />
            </div>

            <div className="report-performance-note">
              <strong>VALIDATED ENGINE BENCHMARK</strong>
              <span>
                0 dropped; average latency 9.623 ms;
                p95 latency 19.780 ms.
              </span>
            </div>
          </div>
        </section>

        <section className="report-section">
          <h3>Top Threats</h3>

          <div className="report-top-threats">
            {topThreats.length ? (
              topThreats.map((item, index) => (
                <div
                  className="report-top-threat"
                  key={item.name}
                >
                  <span>0{index + 1}</span>

                  <div>
                    <strong>
                      {displayThreat(item.name)}
                    </strong>
                    <small>
                      {getNtroCategory(item.name)}
                    </small>
                  </div>

                  <strong>{item.value}</strong>
                </div>
              ))
            ) : (
              <div className="report-empty">
                No threat data available.
              </div>
            )}
          </div>
        </section>

        <section className="report-section">
          <h3>NTRO Detector Coverage</h3>

          <div className="report-coverage-grid">
            <ReportCoverage
              title="DDoS"
              status="ACTIVE"
              detail="Flow rate, entropy and protocol signals"
            />

            <ReportCoverage
              title="Reconnaissance"
              status="ACTIVE"
              detail="Port and host fan-out detection"
            />

            <ReportCoverage
              title="Botnet C2"
              status="ACTIVE"
              detail="Periodic beaconing analysis"
            />

            <ReportCoverage
              title="DNS DGA / Tunnelling"
              status="VALIDATED"
              detail="DNS behavioral and entropy analysis"
            />

            <ReportCoverage
              title="Encrypted Sessions"
              status="VALIDATED"
              detail="TLS / QUIC metadata only; no decryption"
            />

            <ReportCoverage
              title="Data Exfiltration"
              status="VALIDATED"
              detail="Outbound / inbound asymmetry"
            />
          </div>
        </section>

        <section className="report-section">
          <h3>Assessment & Recommendations</h3>

          <div className="report-recommendations">
            <Recommendation
              text={`${analytics?.threat_percentage ?? 0}% threat rate indicates elevated activity in the current replay window.`}
            />

            <Recommendation
              text={
                threatTypes.length
                  ? `${displayThreat(
                      topThreats[0]?.name,
                    )} is the most frequent detected class with ${topThreats[0]?.value ?? 0} detections.`
                  : "No dominant threat class is available."
              }
            />

            <Recommendation
              text="PortScan activity is mapped to reconnaissance coverage where present in the model output."
            />

            <Recommendation
              text="Monitoring remains passive/read-only; no probing, mitigation or payload decryption is performed."
            />
          </div>
        </section>

        <div className="report-footer">
          <div>
            <strong>
              NETRA SECURITY ENGINE • PASSIVE MONITORING
            </strong>
            <span>
              READ-ONLY DETECTION MODE • NO PAYLOAD DECRYPTION
            </span>
          </div>

          <div>
            <span>
              DATA SOURCE: CIC-IDS2017-DERIVED
            </span>
            <span>
              GENERATED: {formatDateTime(new Date())}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ReportSeverity({ label, value, total }) {
  const percentage = total
    ? (value / total) * 100
    : 0;

  return (
    <div className="report-severity-row">
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>

      <div className="report-severity-track">
        <div
          style={{ width: `${percentage}%` }}
        />
      </div>

      <small>{percentage.toFixed(1)}%</small>
    </div>
  );
}

function ReportPerformance({ label, value }) {
  return (
    <div className="report-performance-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ReportCoverage({ title, status, detail }) {
  return (
    <div className="report-coverage-item">
      <div>
        <strong>{title}</strong>
        <span>{status}</span>
      </div>

      <small>{detail}</small>
    </div>
  );
}

function Recommendation({ text }) {
  return (
    <div className="report-recommendation">
      <span>•</span>
      <p>{text}</p>
    </div>
  );
}

function ReportValue({ label, value }) {
  return (
    <div className="report-value">
      <FileText size={17} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function displayThreat(name) {
  const mapping = {
    DDOS: "DDoS",
    DOS: "DoS",
    PORTSCAN: "PortScan",
    BRUTE_FORCE: "Brute Force",
    BOT: "Bot C2",
    BOT_C2: "Bot C2",
    DGA: "DGA",
    DNS_TUNNEL: "DNS Tunnel",
    DNS_RECORD_ANOMALY: "DNS Record Anomaly",
    EXFILTRATION: "Exfiltration",
    WEB_ATTACK: "Web Attack",
  };

  return (
    mapping[String(name || "").toUpperCase()] ||
    name ||
    "Unknown"
  );
}

function getNtroCategory(name) {
  const value = String(name || "").toUpperCase();

  const mapping = {
    DDOS: "Volumetric / Protocol DDoS",
    DOS: "Volumetric / Protocol DDoS",
    PORTSCAN: "Reconnaissance",
    BOT: "Botnet C2 Beaconing",
    BOT_C2: "Botnet C2 Beaconing",
    DGA: "DGA / DNS Tunnelling",
    DNS_TUNNEL: "DGA / DNS Tunnelling",
    DNS_RECORD_ANOMALY: "DNS Anomaly",
    EXFILTRATION: "Data Exfiltration",
    BRUTE_FORCE: "Additional ML Class",
    WEB_ATTACK: "Additional ML Class",
  };

  return mapping[value] || "Additional ML Class";
}

function buildReportPayload(
  analytics,
  threatTypes,
  severity,
) {
  return {
    report_type: "NETRA Security Analysis Report",
    generated_at: new Date().toISOString(),
    data_source: "CIC-IDS2017-DERIVED",
    monitoring_mode: "PASSIVE / READ-ONLY",
    analysis_window: "CURRENT REPLAY ANALYSIS",
    executive_summary: {
      total_flows: analytics?.total_flows ?? null,
      benign_flows: analytics?.benign_flows ?? null,
      threat_flows: analytics?.threat_flows ?? null,
      threat_rate: analytics?.threat_percentage ?? 0,
    },
    detection_summary: threatTypes.map((item) => ({
      threat_type: displayThreat(item.name),
      raw_class: item.name,
      count: item.value,
      ntro_category: getNtroCategory(item.name),
    })),
    severity_breakdown: severity,
    engine_performance: {
      replay_throughput:
        analytics?.processing?.flows_per_second ?? null,
      processing_time:
        analytics?.processing?.total_time_seconds ?? null,
      validated_benchmark_flows_per_second: 103.79,
      validated_benchmark_flow_count: 10000,
      validated_dropped_flows: 0,
      validated_average_latency_ms: 9.623,
      validated_p95_latency_ms: 19.780,
    },
    ntro_detector_coverage: [
      "DDoS",
      "Reconnaissance",
      "Botnet C2 Beaconing",
      "DGA / DNS Tunnelling",
      "Encrypted Sessions via TLS / QUIC metadata",
      "Data Exfiltration",
    ],
  };
}

function csvCell(value) {
  const stringValue =
    value === null || value === undefined
      ? ""
      : String(value);

  return `"${stringValue.replace(/"/g, '""')}"`;
}

function downloadFile(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
}

function timestampForFile() {
  return new Date()
    .toISOString()
    .replace(/[:.]/g, "-");
}

function formatDateTime(date) {
  return date.toLocaleString();
}

export default ReportsPage;
