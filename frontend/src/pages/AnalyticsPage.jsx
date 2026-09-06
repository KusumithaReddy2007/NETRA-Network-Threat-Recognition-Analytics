import {
  BarChart3,
  Gauge,
  Network,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import { motion } from "framer-motion";

function AnalyticsPage({ analytics }) {
  const threatTypes = Object.entries(
    analytics?.threat_types || {}
  )
    .map(([name, value]) => ({
      name,
      value: Number(value),
    }))
    .sort((a, b) => b.value - a.value);

  const severity = analytics?.severity_breakdown || {};

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
            severity and inference performance.
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
          label="THROUGHPUT"
          value={`${analytics?.processing?.flows_per_second ?? 0}/s`}
        />
      </section>

      <section className="analytics-grid">
        <div className="analytics-panel large">
          <PanelHeading
            title="Threat Classification"
            subtitle="MODEL OUTPUT"
          />

          <div className="analytics-bars">
            {threatTypes.map((item, index) => {
              const maximum =
                Math.max(
                  ...threatTypes.map(
                    (x) => x.value
                  ),
                  1
                );

              return (
                <div
                  className="analytics-bar-row"
                  key={item.name}
                >
                  <span>
                    {item.name}
                  </span>

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
              label="THROUGHPUT"
              value={`${analytics?.processing?.flows_per_second ?? 0} flows/s`}
            />
          </div>

          <div className="engine-visual">
            <TrendingUp size={20} />
            <span>LIVE INFERENCE BASELINE</span>
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
