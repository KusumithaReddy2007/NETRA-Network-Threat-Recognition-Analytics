import { Activity, AlertTriangle, Database, Eye, Gauge, Network, Server, ShieldAlert, ShieldCheck, Target } from "lucide-react";
import { motion } from "framer-motion";

function DashboardPage({
  analytics,
  alerts,
  threatTypes,
  severity,
  replaying,
  dataLoading,
  error,
  runReplay,
}) {
  const total = analytics?.total_flows ?? 0;
  const benign = analytics?.benign_flows ?? 0;
  const threats = analytics?.threat_flows ?? 0;
  const threatPercentage = analytics?.threat_percentage ?? 0;

  const critical = Number(severity?.CRITICAL ?? 0);
  const high = Number(severity?.HIGH ?? 0);
  const severityTotal = critical + high;

  return (
    <>
      <PageHeader
        eyebrow="SECURITY OPERATIONS CENTER"
        title="Threat Intelligence Dashboard"
        description="Replay-based visibility across the NETRA network threat detection engine."
        action={
          <button
            className="primary-button"
            onClick={runReplay}
            disabled={replaying}
          >
            <Activity size={16} />
            {replaying ? "PROCESSING..." : "REPLAY TRAFFIC"}
          </button>
        }
      />

      {error && (
        <div className="api-warning">
          <AlertTriangle size={17} />
          <span>{error}</span>
        </div>
      )}

      <section className="kpi-grid">
        <Kpi
          label="TOTAL NETWORK FLOWS"
          value={total}
          icon={Network}
          tone="cyan"
          loading={dataLoading}
        />

        <Kpi
          label="BENIGN TRAFFIC"
          value={benign}
          icon={ShieldCheck}
          tone="green"
          loading={dataLoading}
        />

        <Kpi
          label="THREATS DETECTED"
          value={threats}
          icon={ShieldAlert}
          tone="red"
          loading={dataLoading}
        />

        <Kpi
          label="THREAT PERCENTAGE"
          value={`${threatPercentage}%`}
          icon={Gauge}
          tone="orange"
          loading={dataLoading}
        />
      </section>

      <div className="dashboard-note">
        <span>DISPLAY WINDOW: 100 FLOWS</span>
        <span>ENGINE BENCHMARK: 10,000 FLOWS</span>
      </div>

      <section className="dashboard-grid">
        <Panel title="Traffic Distribution" subtitle="BENIGN VS THREAT" wide>
          <div className="traffic-layout">
            <div
              className="traffic-donut"
              style={{
                background: `conic-gradient(
                  #fb4b55 0 ${threatPercentage}%,
                  #34d399 ${threatPercentage}% 100%
                )`,
              }}
            >
              <div className="donut-core">
                <strong>{total || "—"}</strong>
                <span>TOTAL FLOWS</span>
              </div>
            </div>

            <div className="distribution-info">
              <Distribution
                label="BENIGN TRAFFIC"
                value={benign}
                percentage={
                  total
                    ? `${((benign / total) * 100).toFixed(1)}%`
                    : "0%"
                }
                tone="green"
              />

              <Distribution
                label="THREAT TRAFFIC"
                value={threats}
                percentage={`${threatPercentage}%`}
                tone="red"
              />
            </div>
          </div>
        </Panel>

        <Panel title="Threat Types" subtitle="ML CLASSIFICATION">
          {dataLoading ? (
            <PanelSync />
          ) : threatTypes.length ? (
            <ThreatBars data={threatTypes} />
          ) : (
            <Empty text="No threat classifications available" />
          )}
        </Panel>

        <Panel title="SIH Threat Coverage" subtitle="REQUIRED THREAT CLASSES">
          <ThreatCoverage />
        </Panel>

        <Panel
          title="Latest Threats"
          subtitle="LATEST REPLAY SECURITY EVENTS"
          action={`${alerts.length} ALERTS`}
        >
          <AlertList alerts={alerts} />
        </Panel>

        <Panel title="Processing Performance" subtitle="INFERENCE ENGINE" wide>
          {dataLoading ? (
            <PanelSync />
          ) : (
            <Performance analytics={analytics} />
          )}
        </Panel>

        <Panel title="Severity Breakdown" subtitle="ALERT DISTRIBUTION">
          {dataLoading ? (
            <PanelSync />
          ) : (
            <Severity
              critical={critical}
              high={high}
              total={severityTotal}
            />
          )}
        </Panel>

        <Panel title="Threat Distribution Matrix" subtitle="CLASSIFICATION ACTIVITY">
          <Matrix analytics={analytics} threatTypes={threatTypes} />
        </Panel>

        <Panel title="Recent Threat Detections" subtitle="SECURITY EVENT STREAM" wide>
          <RecentAlerts alerts={alerts} />
        </Panel>
      </section>
    </>
  );
}

function PageHeader({ eyebrow, title, description, action }) {
  return (
    <motion.div
      className="page-heading"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div>
        <div className="eyebrow">
          <span className="eyebrow-line" />
          {eyebrow}
        </div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>

      {action && <div className="heading-actions">{action}</div>}
    </motion.div>
  );
}

function Kpi({ label, value, icon: Icon, tone, loading }) {
  return (
    <motion.div
      className={`kpi-card ${tone}`}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -5, scale: 1.01 }}
    >
      <div className="kpi-scan" />

      <div className="kpi-header">
        <span>{label}</span>
        <div className="kpi-icon">
          <Icon size={21} />
        </div>
      </div>

      <div className="kpi-value">
        {loading ? "—" : value}
      </div>

      <div className="kpi-sub">
        <span className="kpi-live-dot" />
        REPLAY TELEMETRY
      </div>

      <div className="kpi-wave">
        {[20, 45, 30, 68, 42, 80, 55, 93].map((height, i) => (
          <span
            key={i}
            style={{
              height: `${height}%`,
              animationDelay: `${i * 0.12}s`,
            }}
          />
        ))}
      </div>
    </motion.div>
  );
}

function Panel({ title, subtitle, children, wide, action }) {
  return (
    <motion.section
      className={`dashboard-card ${wide ? "wide" : ""}`}
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="card-header">
        <div>
          <span>{subtitle}</span>
          <h2>{title}</h2>
        </div>

        {action && <div className="card-action">{action}</div>}
      </div>

      <div className="card-body">{children}</div>
    </motion.section>
  );
}

function Distribution({ label, value, percentage, tone }) {
  return (
    <div className="distribution-row">
      <span className={`legend-dot ${tone}`} />

      <div>
        <strong>{label}</strong>
        <span>{percentage}</span>
      </div>

      <b>{value}</b>
    </div>
  );
}

function ThreatBars({ data }) {
  const max = Math.max(...data.map((x) => x.value), 1);

  return (
    <div className="threat-chart">
      <div className="chart-grid-lines">
        <span />
        <span />
        <span />
        <span />
      </div>

      <div className="bars">
        {data.map((item, index) => (
          <div className="bar-column" key={item.name}>
            <span className="bar-number">{item.value}</span>

            <div className="bar-track">
              <motion.div
                className="bar"
                initial={{ height: 0 }}
                animate={{
                  height: `${(item.value / max) * 100}%`,
                }}
                transition={{
                  duration: 0.8,
                  delay: index * 0.06,
                }}
              />
            </div>

            <span className="bar-label">
              {item.name.replaceAll("_", " ")}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AlertList({ alerts }) {
  if (!alerts.length) {
    return <Empty text="Run traffic replay to populate detections" />;
  }

  return (
    <div className="live-threats">
      {alerts.slice(0, 5).map((alert, index) => (
        <motion.div
          className="live-alert"
          key={alert.alert_id || index}
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.05 }}
        >
          <div
            className={`live-alert-icon ${String(
              alert.severity || "HIGH"
            ).toLowerCase()}`}
          >
            <AlertTriangle size={17} />
          </div>

          <div className="live-alert-copy">
            <strong>{alert.threat_class}</strong>
            <span>{alert.flow_id || "FLOW IDENTIFIED"}</span>
          </div>

          <div className="live-alert-meta">
            <span>{formatTime(alert.timestamp)}</span>
            <Badge severity={alert.severity} />
          </div>
        </motion.div>
      ))}
    </div>
  );
}

function Performance({ analytics }) {
  const speed = analytics?.processing?.flows_per_second ?? 0;
  const time = analytics?.processing?.total_time_seconds ?? 0;

  const percent = Math.min((Number(speed) / 12) * 100, 100);

  return (
    <div className="performance-layout">
      <div className="performance-main">
        <div
          className="performance-gauge"
          style={{
            background: `conic-gradient(
              #22d3ee 0 ${percent}%,
              rgba(34,211,238,0.08) ${percent}% 100%
            )`,
          }}
        >
          <div className="gauge-core">
            <strong>{speed}</strong>
            <span>FLOWS / SEC</span>
          </div>
        </div>

        <div className="performance-copy">
          <span>REPLAY THROUGHPUT</span>
          <h3>{speed} flows/sec</h3>
          <p>End-to-end replay rate.</p>
          <div className="performance-status">
            <i />
            TESTED ENGINE BENCHMARK&nbsp; 103.79 FLOWS/SEC
          </div>
          <p className="performance-note">10,000-flow streaming benchmark.</p>

          <div className="performance-status">
            <i />
            INFERENCE ENGINE ACTIVE
          </div>
        </div>
      </div>

      <div className="performance-stats">
        <Metric icon={Gauge} label="PROCESSING TIME" value={`${time} sec`} />
        <Metric icon={Network} label="FLOWS ANALYZED" value={analytics?.total_flows ?? 0} />
        <Metric icon={Database} label="DATA SOURCE" value="CIC-IDS2017-DERIVED" />
        <Metric icon={Target} label="MONITORING MODE" value="PASSIVE / READ-ONLY" />
      </div>
    </div>
  );
}

function Metric({ icon: Icon, label, value }) {
  return (
    <div className="metric-box">
      <div className="metric-box-icon">
        <Icon size={17} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function Severity({ critical, high, total }) {
  const criticalPct = total ? (critical / total) * 100 : 0;

  return (
    <div className="severity-layout">
      <div
        className="severity-donut"
        style={{
          background: `conic-gradient(
            #fb4b55 0 ${criticalPct}%,
            #f59e0b ${criticalPct}% 100%
          )`,
        }}
      >
        <div>
          <strong>{total}</strong>
          <span>ALERTS</span>
        </div>
      </div>

      <div className="severity-list">
        <SeverityLine
          name="CRITICAL"
          value={critical}
          tone="critical"
          percentage={total ? `${((critical / total) * 100).toFixed(1)}%` : "0%"}
        />

        <SeverityLine
          name="HIGH"
          value={high}
          tone="high"
          percentage={total ? `${((high / total) * 100).toFixed(1)}%` : "0%"}
        />
      </div>
    </div>
  );
}

function SeverityLine({ name, value, percentage, tone }) {
  return (
    <div className="severity-line">
      <span className={`severity-dot ${tone}`} />

      <div>
        <strong>{name}</strong>
        <span>{percentage}</span>
      </div>

      <b>{value}</b>
    </div>
  );
}

function Matrix({ analytics, threatTypes }) {
  const totalThreats = Number(
    analytics?.threat_flows ?? 0
  );

  return (
    <div className="matrix">
      <div className="matrix-top">
        <div>
          <span>FLOW ANALYSIS</span>
          <strong>
            {analytics?.total_flows ?? "—"}
          </strong>
        </div>

        <div>
          <span>THREAT CLASSES</span>
          <strong>
            {threatTypes.length || "—"}
          </strong>
        </div>
      </div>

      {threatTypes.length ? (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "12px",
            width: "100%",
          }}
        >
          {threatTypes.map((item) => {
            const count = Number(item.value) || 0;
            const percentage =
              totalThreats > 0
                ? (count / totalThreats) * 100
                : 0;

            return (
              <div
                key={item.name}
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "110px minmax(0, 1fr) 42px",
                  alignItems: "center",
                  gap: "10px",
                }}
              >
                <span
                  style={{
                    fontSize: "10px",
                    fontWeight: 700,
                    letterSpacing: "0.05em",
                    color:
                      "rgba(226,232,240,0.82)",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {item.name.replaceAll("_", " ")}
                </span>

                <div
                  style={{
                    height: "10px",
                    borderRadius: "999px",
                    background:
                      "rgba(148,163,184,0.10)",
                    overflow: "hidden",
                    border:
                      "1px solid rgba(148,163,184,0.08)",
                  }}
                >
                  <div
                    style={{
                      width: `${Math.min(
                        percentage,
                        100
                      )}%`,
                      height: "100%",
                      borderRadius: "999px",
                      background:
                        "linear-gradient(90deg, rgba(34,211,238,0.85), rgba(244,63,94,0.85))",
                      transition:
                        "width 500ms ease",
                    }}
                  />
                </div>

                <span
                  style={{
                    fontSize: "11px",
                    fontWeight: 800,
                    textAlign: "right",
                    color: "#e2e8f0",
                  }}
                >
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      ) : (
        <Empty text="No threat classifications available" />
      )}

      <div
        style={{
          marginTop: "14px",
          fontSize: "9px",
          color:
            "rgba(148,163,184,0.75)",
          letterSpacing: "0.05em",
        }}
      >
        REAL THREAT COUNTS FROM CURRENT REPLAY
      </div>
    </div>
  );
}

function evidenceValue(evidence, keys) {
  for (const key of keys) {
    const value = evidence?.[key];
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return null;
}

function formatEvidenceNumber(value) {
  const number = Number(value);
  return Number.isFinite(number)
    ? Number(number.toFixed(2))
    : value;
}

function summarizeEvidence(alert) {
  const evidence =
    alert?.supporting_evidence ||
    alert?.evidence ||
    {};

  const threat = String(alert?.threat_class || "").toUpperCase();
  const parts = [];

  if (threat.includes("PORTSCAN")) {
    const ports = evidenceValue(evidence, [
      "unique_destination_port_count",
      "unique_dest_port_count",
      "unique_ports",
      "destination_port_count",
      "port_count",
    ]);

    const hosts = evidenceValue(evidence, [
      "unique_destination_host_count",
      "unique_dest_host_count",
      "unique_hosts",
      "destination_host_count",
      "host_count",
    ]);

    if (ports !== null) parts.push(`ports:${formatEvidenceNumber(ports)}`);
    if (hosts !== null) parts.push(`hosts:${formatEvidenceNumber(hosts)}`);
  }

  if (threat.includes("DDOS") || threat === "DOS") {
    const rate = evidenceValue(evidence, [
      "packet_rate",
      "source_rate",
      "event_rate_per_second",
      "flow_rate",
    ]);

    const sources = evidenceValue(evidence, [
      "unique_source_count",
      "source_count",
      "unique_sources",
    ]);

    const entropy = evidenceValue(evidence, [
      "destination_source_entropy",
      "source_entropy",
      "entropy",
    ]);

    if (rate !== null) parts.push(`rate:${formatEvidenceNumber(rate)}`);
    if (sources !== null) parts.push(`sources:${formatEvidenceNumber(sources)}`);
    if (entropy !== null) parts.push(`entropy:${formatEvidenceNumber(entropy)}`);
  }

  if (threat.includes("BOT") || threat.includes("C2")) {
    const events = evidenceValue(evidence, [
      "event_count",
      "beacon_events",
    ]);

    const interval = evidenceValue(evidence, [
      "average_interval_seconds",
      "mean_interval_seconds",
      "interval_seconds",
    ]);

    const cv = evidenceValue(evidence, [
      "coefficient_of_variation",
      "periodicity_cv",
    ]);

    if (events !== null) parts.push(`events:${formatEvidenceNumber(events)}`);
    if (interval !== null) parts.push(`interval:${formatEvidenceNumber(interval)}s`);
    if (cv !== null) parts.push(`cv:${formatEvidenceNumber(cv)}`);
  }

  if (threat.includes("EXFIL")) {
    const ratio = evidenceValue(evidence, [
      "outbound_inbound_byte_ratio",
      "byte_ratio",
      "ratio",
    ]);

    if (ratio !== null) parts.push(`ratio:${formatEvidenceNumber(ratio)}`);
  }

  if (!parts.length) {
    const source = evidenceValue(evidence, [
      "source_ip",
      "src_ip",
      "source",
    ]);

    const destination = evidenceValue(evidence, [
      "destination_ip",
      "dst_ip",
      "destination",
    ]);

    const packets = evidenceValue(evidence, [
      "packet_count",
      "orig_packets",
    ]);

    const bytes = evidenceValue(evidence, [
      "byte_rate",
      "orig_bytes",
      "total_bytes",
    ]);

    if (source !== null) parts.push(`src:${source}`);
    if (destination !== null) parts.push(`dst:${destination}`);
    if (packets !== null) parts.push(`pkts:${formatEvidenceNumber(packets)}`);
    if (bytes !== null) parts.push(`bytes:${formatEvidenceNumber(bytes)}`);
  }

  if (!parts.length) {
    const signals =
      evidence?.anomaly_signals ||
      evidence?.supporting_signals ||
      evidence?.signals;

    if (Array.isArray(signals) && signals.length) {
      return signals.slice(0, 3).join(" • ");
    }
  }

  return parts.length ? parts.slice(0, 3).join(" • ") : "Evidence recorded";
}

function ThreatCoverage() {
  const items = [
    {
      label: "VOLUMETRIC / PROTOCOL DDOS",
      detail: "Flow ML + behavioral detection",
    },
    {
      label: "BOTNET C2 BEACONING",
      detail: "TLS + flow periodicity detection",
    },
    {
      label: "DGA / DNS TUNNELING",
      detail: "DNS ML + behavioral detection",
    },
    {
      label: "MALWARE IN ENCRYPTED SESSIONS",
      detail: "TLS / QUIC metadata analysis",
    },
    {
      label: "RECONNAISSANCE / PORT SCANNING",
      detail: "Fan-out + flow classification",
    },
    {
      label: "DATA EXFILTRATION",
      detail: "Outbound / inbound asymmetry analysis",
    },
  ];

  return (
    <div className="coverage-grid">
      {items.map((item) => (
        <div className="coverage-item" key={item.label}>
          <div className="coverage-status">
            <i />
            COVERED
          </div>
          <strong>{item.label}</strong>
          <span>{item.detail}</span>
        </div>
      ))}

      <div className="coverage-note">
        <strong>ADDITIONAL FLOW CLASS</strong>
        <span>BRUTE_FORCE is retained as an observed ML class and is not relabeled as an SIH threat category.</span>
      </div>
    </div>
  );
}

function RecentAlerts({ alerts }) {
  if (!alerts.length) {
    return <Empty text="No detection events available" />;
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>TIME</th>
            <th>THREAT</th>
            <th>FLOW ID</th>
            <th>SEVERITY</th>
            <th>CONFIDENCE</th>
            <th>EVIDENCE</th>
          </tr>
        </thead>

        <tbody>
          {alerts.slice(0, 10).map((alert, index) => (
            <tr key={alert.alert_id || index}>
              <td>{formatTime(alert.timestamp)}</td>
              <td>
                <span className="table-threat">
                  {alert.threat_class}
                </span>
              </td>
              <td>
                <span className="flow-id">
                  {alert.flow_id || "—"}
                </span>
              </td>
              <td>
                <Badge severity={alert.severity} />
              </td>
              <td>
                <span className="table-confidence">
                  {alert.confidence ?? 0}%
                </span>
              </td>
              <td>
                <span className="table-evidence">
                  {summarizeEvidence(alert)}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Badge({ severity }) {
  const value = String(severity || "HIGH").toUpperCase();

  return (
    <span className={`severity-badge ${value.toLowerCase()}`}>
      {value}
    </span>
  );
}

function PanelSync() {
  return (
    <div className="data-loading">
      <div className="data-loading-ring" />
      <strong>SYNCING TELEMETRY</strong>
      <span>NETRA analytics engine is processing data...</span>
    </div>
  );
}

function Empty({ text }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Activity size={20} />
      </div>
      <span>{text}</span>
    </div>
  );
}

function formatTime(timestamp) {
  if (!timestamp) return "--:--:--";

  try {
    return new Date(timestamp).toLocaleTimeString([], {
      hour12: false,
    });
  } catch {
    return "--:--:--";
  }
}

export default DashboardPage;
