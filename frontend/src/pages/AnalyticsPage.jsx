import {
  BarChart3,
  Gauge,
  Network,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import { motion } from "framer-motion";

function AnalyticsPage({ analytics, alerts = [] }) {
  const threatTypes = Object.entries(
    analytics?.threat_types || {}
  )
    .map(([name, value]) => ({
      name,
      value: Number(value),
    }))
    .sort((a, b) => b.value - a.value);

  const severity = analytics?.severity_breakdown || {};

  const displayThreatName = (name) => {
    const value = String(name || "").toUpperCase();

    const mapping = {
      DDOS: "DDoS",
      DOS: "DoS",
      PORTSCAN: "PortScan",
      BOT: "Bot C2",
      BOT_C2: "Bot C2",
      DGA: "DGA",
      DNS_TUNNEL: "DNS Tunnel",
      DNS_RECORD_ANOMALY: "DNS Record Anomaly",
      EXFILTRATION: "Exfiltration",
      BRUTE_FORCE: "Brute Force",
      WEB_ATTACK: "Web Attack",
    };

    return mapping[value] || name;
  };

  const ntroCategory = (name) => {
    const value = String(name || "").toUpperCase();

    const mapping = {
      DDOS: "VOLUMETRIC / PROTOCOL DDoS",
      DOS: "VOLUMETRIC / PROTOCOL DDoS",
      PORTSCAN: "RECONNAISSANCE",
      BOT: "BOTNET C2 BEACONING",
      BOT_C2: "BOTNET C2 BEACONING",
      DGA: "DNS TUNNELLING / DGA",
      DNS_TUNNEL: "DNS TUNNELLING",
      DNS_RECORD_ANOMALY: "DNS ANOMALY",
      EXFILTRATION: "DATA EXFILTRATION",
      BRUTE_FORCE: "ADDITIONAL ML CLASS",
      WEB_ATTACK: "ADDITIONAL ML CLASS",
    };

    return mapping[value] || "ADDITIONAL ML CLASS";
  };

  const confidenceValues = Array.isArray(alerts)
    ? alerts
        .map((alert) => Number(alert?.confidence))
        .filter((value) => Number.isFinite(value))
    : [];

  const averageConfidence = confidenceValues.length
    ? confidenceValues.reduce(
        (sum, value) => sum + value,
        0,
      ) / confidenceValues.length
    : 0;

  const confidenceBuckets = [
    { label: "100%", min: 99.5, max: 100.01 },
    { label: "99–99.5%", min: 99, max: 99.5 },
    { label: "98–99%", min: 98, max: 99 },
    { label: "<98%", min: -Infinity, max: 98 },
  ].map((bucket) => ({
    ...bucket,
    count: confidenceValues.filter(
      (value) =>
        value >= bucket.min &&
        value < bucket.max,
    ).length,
  }));

  const maxConfidenceBucket = Math.max(
    ...confidenceBuckets.map((bucket) => bucket.count),
    1,
  );

  return (
    <div className="special-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SECURITY ANALYTICS
          </div>

          <h1>Analytics Center</h1>

          <p>
            Statistical view of threat classification,
            severity and replay inference performance.
          </p>
        </div>
      </div>

      <section className="analytics-kpis">
        <AnalyticsMetric
          icon={Network}
          label="TOTAL FLOWS"
          value={analytics?.total_flows ?? "—"}
        />

        <AnalyticsMetric
          icon={ShieldAlert}
          label="THREAT RATE"
          value={`${analytics?.threat_percentage ?? 0}%`}
          red
        />

        <AnalyticsMetric
          icon={BarChart3}
          label="THREAT CLASSES"
          value={threatTypes.length}
        />

        <AnalyticsMetric
          icon={Gauge}
          label="REPLAY THROUGHPUT"
          value={`${analytics?.processing?.flows_per_second ?? 0}/s`}
        />
      </section>

      <section className="analytics-grid">
        <div className="analytics-panel large">
          <PanelHeading
            title="Threat Classification"
            subtitle="MODEL OUTPUT / NTRO COVERAGE"
          />

          <div className="analytics-bars">
            {threatTypes.map((item, index) => {
              const maximum = Math.max(
                ...threatTypes.map((x) => x.value),
                1,
              );

              return (
                <div
                  className="analytics-bar-row"
                  key={item.name}
                >
                  <div className="analytics-threat-name">
                    <span>{displayThreatName(item.name)}</span>
                    <small>{ntroCategory(item.name)}</small>
                  </div>

                  <div>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{
                        width: `${(item.value / maximum) * 100}%`,
                      }}
                      transition={{
                        delay: index * 0.08,
                        duration: 0.7,
                      }}
                    />
                  </div>

                  <strong>{item.value}</strong>
                </div>
              );
            })}
          </div>

          <div className="analytics-source-note">
            <strong>NTRO DETECTION COVERAGE</strong>
            <span>
              The replay dashboard maps the required NTRO categories
              to dedicated NETRA detectors. DNS tunnelling/DGA,
              encrypted-session metadata and exfiltration are also
              validated through protocol-specific replay paths.
              BRUTE_FORCE and WEB_ATTACK remain additional ML classes.
            </span>
          </div>
        </div>

        <div className="analytics-panel">
          <PanelHeading
            title="Severity"
            subtitle="ALERT DISTRIBUTION"
          />

          <div className="analytics-severity">
            <SeverityRow
              label="CRITICAL"
              value={severity.CRITICAL ?? 0}
              red
            />

            <SeverityRow
              label="HIGH"
              value={severity.HIGH ?? 0}
            />

            <SeverityRow
              label="TOTAL"
              value={
                Number(severity.CRITICAL || 0) +
                Number(severity.HIGH || 0)
              }
            />

            <div className="severity-visual">
              <div>
                <span>CRITICAL</span>
                <div className="severity-track">
                  <div
                    className="severity-fill critical"
                    style={{
                      width: `${
                        (
                          Number(severity.CRITICAL || 0) /
                          Math.max(
                            Number(severity.CRITICAL || 0) +
                              Number(severity.HIGH || 0),
                            1,
                          )
                        ) * 100
                      }%`,
                    }}
                  />
                </div>
              </div>

              <div>
                <span>HIGH</span>
                <div className="severity-track">
                  <div
                    className="severity-fill high"
                    style={{
                      width: `${
                        (
                          Number(severity.HIGH || 0) /
                          Math.max(
                            Number(severity.CRITICAL || 0) +
                              Number(severity.HIGH || 0),
                            1,
                          )
                        ) * 100
                      }%`,
                    }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="analytics-panel">
          <PanelHeading
            title="Processing"
            subtitle="ENGINE PERFORMANCE"
          />

          <div className="engine-metrics">
            <EngineMetric
              label="PROCESSING TIME"
              value={`${analytics?.processing?.total_time_seconds ?? 0}s`}
            />

            <EngineMetric
              label="REPLAY THROUGHPUT"
              value={`${analytics?.processing?.flows_per_second ?? 0} flows/s`}
            />
          </div>

          <div className="engine-visual">
            <TrendingUp size={20} />
            <span>REPLAY INFERENCE BASELINE</span>
          </div>

          <div className="performance-note">
            <strong>TESTED ENGINE BENCHMARK</strong>
            <span>
              103.79 flows/sec over 10,000 streaming flows;
              0 dropped; average latency 9.623 ms; p95 19.780 ms.
            </span>
          </div>
        </div>

        <div className="analytics-panel large">
          <PanelHeading
            title="Threat Composition"
            subtitle="NETWORK OBSERVATION"
          />

          <div className="composition">
            <div
              className="composition-ring"
              style={{
                background: `conic-gradient(
                  #fb4b55 0 ${analytics?.threat_percentage ?? 0}%,
                  #34d399 ${analytics?.threat_percentage ?? 0}% 100%
                )`,
              }}
            >
              <div>
                <strong>
                  {analytics?.threat_percentage ?? 0}%
                </strong>
                <span>THREAT RATE</span>
              </div>
            </div>

            <div className="composition-copy">
              <p>
                <span className="green-dot" />
                Benign flows
                <strong>
                  {analytics?.benign_flows ?? 0}
                </strong>
              </p>

              <p>
                <span className="red-dot" />
                Threat flows
                <strong>
                  {analytics?.threat_flows ?? 0}
                </strong>
              </p>
            </div>
          </div>

          <div className="analytics-source-note">
            <strong>REPLAY DATA CONTEXT</strong>
            <span>
              Current composition reflects the CIC-IDS2017-derived
              replay analysis window, not live production traffic.
            </span>
          </div>
        </div>
      </section>

      <section className="analytics-grid analytics-secondary-grid">
        <div className="analytics-panel large">
          <PanelHeading
            title="NTRO Detector Coverage"
            subtitle="PROTOCOL-SPECIFIC VALIDATION"
          />

          <div className="detector-coverage-grid">
            <div className="detector-coverage-item">
              <span>DDoS</span>
              <strong>ACTIVE</strong>
              <small>Flow-rate / entropy / protocol signals</small>
            </div>

            <div className="detector-coverage-item">
              <span>Reconnaissance</span>
              <strong>ACTIVE</strong>
              <small>Destination port and host fan-out</small>
            </div>

            <div className="detector-coverage-item">
              <span>Botnet C2</span>
              <strong>ACTIVE</strong>
              <small>Periodic beaconing behavior</small>
            </div>

            <div className="detector-coverage-item">
              <span>DNS DGA / Tunnel</span>
              <strong>VALIDATED</strong>
              <small>DNS behavioral replay and entropy signals</small>
            </div>

            <div className="detector-coverage-item">
              <span>Encrypted Malware</span>
              <strong>VALIDATED</strong>
              <small>TLS / QUIC metadata only; no decryption</small>
            </div>

            <div className="detector-coverage-item">
              <span>Data Exfiltration</span>
              <strong>VALIDATED</strong>
              <small>Outbound / inbound asymmetry</small>
            </div>
          </div>

          <div className="analytics-source-note">
            <strong>IMPORTANT</strong>
            <span>
              Model-output counts above come from the CIC-IDS2017-derived
              flow replay. Protocol-specific validation is shown separately
              so the dashboard does not fabricate mixed-dataset threat counts.
            </span>
          </div>
        </div>
      </section>

      <section className="analytics-grid analytics-secondary-grid">
        <div className="analytics-panel large">
          <PanelHeading
            title="Confidence Distribution"
            subtitle="DETECTION CONFIDENCE"
          />

          {confidenceValues.length ? (
            <>
              <div className="confidence-summary">
                <div>
                  <span>AVERAGE CONFIDENCE</span>
                  <strong>{averageConfidence.toFixed(2)}%</strong>
                </div>

                <div>
                  <span>ALERTS ANALYZED</span>
                  <strong>{confidenceValues.length}</strong>
                </div>
              </div>

              <div className="confidence-bars">
                {confidenceBuckets.map((bucket) => (
                  <div
                    className="confidence-row"
                    key={bucket.label}
                  >
                    <span>{bucket.label}</span>

                    <div className="confidence-track">
                      <motion.div
                        className="confidence-fill"
                        initial={{ width: 0 }}
                        animate={{
                          width: `${
                            (bucket.count /
                              maxConfidenceBucket) *
                            100
                          }%`,
                        }}
                        transition={{ duration: 0.5 }}
                      />
                    </div>

                    <strong>{bucket.count}</strong>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="analytics-empty-state">
              Run traffic replay to populate confidence metrics.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function AnalyticsMetric({
  icon: Icon,
  label,
  value,
  red,
}) {
  return (
    <motion.div
      className={`analytics-metric ${
        red ? "red" : ""
      }`}
      whileHover={{ y: -4 }}
    >
      <div>
        <Icon size={19} />
      </div>

      <span>{label}</span>
      <strong>{value}</strong>
    </motion.div>
  );
}

function PanelHeading({ title, subtitle }) {
  return (
    <div className="special-card-heading">
      <div>
        <span>{subtitle}</span>
        <h3>{title}</h3>
      </div>
    </div>
  );
}

function SeverityRow({ label, value, red }) {
  return (
    <div className="analytics-severity-row">
      <span className={red ? "red-text" : ""}>
        {label}
      </span>
      <strong>{value}</strong>
    </div>
  );
}

function EngineMetric({ label, value }) {
  return (
    <div className="engine-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default AnalyticsPage;
