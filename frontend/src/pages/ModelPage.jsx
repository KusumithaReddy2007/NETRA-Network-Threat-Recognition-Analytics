import {
  BrainCircuit,
  Database,
  Layers3,
  Target,
  Zap,
  ShieldCheck,
} from "lucide-react";
import { motion } from "framer-motion";

function ModelPage({ analytics }) {
  const classes = [
    "BENIGN",
    "DOS",
    "PORTSCAN",
    "DDOS",
    "BRUTE_FORCE",
    "WEB_ATTACK",
    "BOT",
  ];

  const features = [
    ["Destination Port", "Target port of the network flow."],
    ["Flow Duration", "Duration of the observed flow."],
    ["Total Fwd Packets", "Packets sent in the forward direction."],
    ["Total Backward Packets", "Packets sent in the backward direction."],
    ["Total Length of Fwd Packets", "Forward-direction bytes transferred."],
    ["Total Length of Bwd Packets", "Backward-direction bytes transferred."],
    ["Flow Bytes/s", "Byte transfer rate for the flow."],
    ["Flow Packets/s", "Packet transfer rate for the flow."],
    ["Flow IAT Mean", "Mean inter-arrival time between flow packets."],
    ["Flow IAT Std", "Variation of packet inter-arrival times."],
    ["Fwd Packet Length Mean", "Mean forward packet length."],
    ["Bwd Packet Length Mean", "Mean backward packet length."],
    ["Packet Length Mean", "Mean packet length across the flow."],
    ["Packet Length Std", "Variation in packet lengths."],
    ["SYN Flag Count", "Number of observed SYN flags."],
    ["ACK Flag Count", "Number of observed ACK flags."],
    ["Down/Up Ratio", "Ratio of downstream to upstream traffic."],
    ["Average Packet Size", "Average size of observed packets."],
    ["Active Mean", "Mean duration of active flow periods."],
    ["Idle Mean", "Mean duration of idle flow periods."],
  ];

  const mapping = [
    ["DDOS", "Volumetric / Protocol DDoS"],
    ["DOS", "Volumetric / Protocol DDoS"],
    ["PORTSCAN", "Reconnaissance / Port Scanning"],
    ["BOT", "Botnet C2 Beaconing"],
    ["BENIGN", "N/A — Normal Traffic"],
    ["BRUTE_FORCE", "Additional ML Class"],
    ["WEB_ATTACK", "Additional ML Class"],
  ];

  return (
    <div className="special-page model-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            AI DETECTION ENGINE
          </div>

          <h1>NETRA Model</h1>

          <p>
            Machine-learning architecture currently used
            for network flow classification.
          </p>
        </div>
      </div>

      <section className="model-hero">
        <div className="model-core">
          <BrainCircuit size={42} />
          <div className="model-pulse" />
        </div>

        <div>
          <span>ACTIVE MODEL</span>
          <h2>Random Forest Classifier</h2>
          <p>
            Balanced CIC-IDS2017-derived training data with
            standardized NETRA threat classes and 20 flow-level
            input features.
          </p>
        </div>
      </section>

      <section className="model-grid">
        <ModelCard
          icon={Database}
          title="TRAINING DATA"
          value="CIC-IDS2017-DERIVED"
          text="Public benchmark-derived flow data used for the current prototype model."
        />

        <ModelCard
          icon={Layers3}
          title="FEATURE SPACE"
          value="20"
          text="Twenty standardized flow-level metadata features."
        />

        <ModelCard
          icon={Target}
          title="CLASSIFICATION"
          value={`${classes.length} CLASSES`}
          text="BENIGN plus six threat-oriented ML classes."
        />

        <ModelCard
          icon={Zap}
          title="REPLAY INFERENCE"
          value={`${analytics?.processing?.flows_per_second ?? 0}/s`}
          text="Current replay-window throughput."
        />
      </section>

      <section className="model-columns">
        <div className="model-panel">
          <div className="special-card-heading">
            <div>
              <span>MODEL OVERVIEW</span>
              <h3>Architecture & Validation</h3>
            </div>
          </div>

          <div className="model-info-grid">
            <ModelInfo
              label="MODEL TYPE"
              value="Random Forest Classifier"
            />

            <ModelInfo
              label="TRAINING DATA"
              value="CIC-IDS2017-derived"
            />

            <ModelInfo
              label="TRAINING ROWS"
              value="170,495"
            />

            <ModelInfo
              label="HOLDOUT ROWS"
              value="42,624"
            />

            <ModelInfo
              label="FEATURES"
              value="20"
            />

            <ModelInfo
              label="CLASSES"
              value="7"
            />

            <ModelInfo
              label="VALIDATION"
              value="Stratified holdout"
            />

            <ModelInfo
              label="MODEL VERSION"
              value="Not reported"
            />
          </div>

          <div className="model-validation-note">
            <ShieldCheck size={16} />
            <span>
              The documented evaluation is a practical per-source-file
              stratified holdout, not an independent temporal/session
              benchmark.
            </span>
          </div>
        </div>

        <div className="model-panel">
          <div className="special-card-heading">
            <div>
              <span>MODEL PERFORMANCE</span>
              <h3>Validated Flow Classifier</h3>
            </div>
          </div>

          <div className="model-performance-grid">
            <PerformanceMetric
              label="ACCURACY"
              value="99.39%"
            />

            <PerformanceMetric
              label="MACRO F1"
              value="96.59%"
            />

            <PerformanceMetric
              label="WEIGHTED F1"
              value="99.41%"
            />

            <PerformanceMetric
              label="PRECISION"
              value="N/R"
            />

            <PerformanceMetric
              label="RECALL"
              value="N/R"
            />

            <PerformanceMetric
              label="FALSE POSITIVE RATE"
              value="N/R"
            />
          </div>

          <div className="model-metric-note">
            N/R = not reported as a single overall flow-model metric
            in the current validation evidence.
          </div>
        </div>
      </section>

      <section className="model-panel model-wide-panel">
        <div className="special-card-heading">
          <div>
            <span>CLASSIFICATION SPACE</span>
            <h3>Threat Classes & NTRO Mapping</h3>
          </div>
        </div>

        <div className="model-mapping-table-wrap">
          <table className="model-mapping-table">
            <thead>
              <tr>
                <th>THREAT CLASS</th>
                <th>NTRO CATEGORY</th>
                <th>ROLE</th>
              </tr>
            </thead>

            <tbody>
              {mapping.map(([name, category]) => (
                <tr key={name}>
                  <td>
                    <strong>{displayClass(name)}</strong>
                  </td>

                  <td>{category}</td>

                  <td>
                    {name === "BENIGN"
                      ? "Normal traffic"
                      : name === "BRUTE_FORCE" ||
                        name === "WEB_ATTACK"
                      ? "Additional ML capability"
                      : "Required NTRO coverage"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="model-panel model-wide-panel">
        <div className="special-card-heading">
          <div>
            <span>FEATURE PIPELINE</span>
            <h3>20 Flow Features</h3>
          </div>

          <span className="model-feature-count">
            {features.length} / 20 SHOWN
          </span>
        </div>

        <div className="model-feature-table-wrap">
          <table className="model-feature-table">
            <thead>
              <tr>
                <th>#</th>
                <th>FEATURE</th>
                <th>DESCRIPTION</th>
              </tr>
            </thead>

            <tbody>
              {features.map(([name, description], index) => (
                <tr key={name}>
                  <td>{String(index + 1).padStart(2, "0")}</td>
                  <td>
                    <strong>{name}</strong>
                  </td>
                  <td>{description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="model-training-panel">
        <div>
          <span>TRAINING / EVALUATION CONTEXT</span>
          <h3>Current Prototype Evidence</h3>
        </div>

        <div className="model-training-grid">
          <ModelTrainingItem
            label="DATA REPRESENTATION"
            value="Flow-level metadata"
          />

          <ModelTrainingItem
            label="TRAINING SET"
            value="170,495 rows"
          />

          <ModelTrainingItem
            label="HOLDOUT SET"
            value="42,624 rows"
          />

          <ModelTrainingItem
            label="VALIDATION METHOD"
            value="Stratified source-file holdout"
          />

          <ModelTrainingItem
            label="MODEL TYPE"
            value="Random Forest"
          />

          <ModelTrainingItem
            label="TRAINING DATE"
            value="Not reported"
          />
        </div>
      </section>

      <div className="model-note">
        <Target size={17} />
        <span>
          Performance figures describe the documented prototype
          evaluation and should not be interpreted as guaranteed
          production-world accuracy or performance on unseen traffic.
        </span>
      </div>

      <div className="model-compliance">
        <strong>
          NETRA SECURITY ENGINE • PASSIVE / READ-ONLY
        </strong>
        <span>
          Flow classification uses passively collected metadata;
          no active probing, payload decryption or mitigation is
          performed by the monitoring pipeline.
        </span>
      </div>
    </div>
  );
}

function ModelCard({
  icon: Icon,
  title,
  value,
  text,
}) {
  return (
    <motion.div
      className="model-card"
      whileHover={{ y: -4 }}
    >
      <div>
        <Icon size={19} />
      </div>

      <span>{title}</span>
      <strong>{value}</strong>
      <p>{text}</p>
    </motion.div>
  );
}

function ModelInfo({ label, value }) {
  return (
    <div className="model-info-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PerformanceMetric({ label, value }) {
  return (
    <div className="model-performance-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ModelTrainingItem({ label, value }) {
  return (
    <div className="model-training-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function displayClass(name) {
  const mapping = {
    BENIGN: "BENIGN",
    DOS: "DoS",
    PORTSCAN: "PortScan",
    DDOS: "DDoS",
    BRUTE_FORCE: "Brute Force",
    WEB_ATTACK: "Web Attack",
    BOT: "Bot C2",
  };

  return mapping[name] || name;
}

export default ModelPage;
