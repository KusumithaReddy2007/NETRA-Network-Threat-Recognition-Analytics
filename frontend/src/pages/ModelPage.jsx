import {
  BrainCircuit,
  Database,
  Layers3,
  Target,
  Zap,
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
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Active Mean",
    "Idle Mean",
  ];

  return (
    <div className="special-page">
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
            Balanced CIC-IDS2017-derived training dataset
            with standardized NETRA threat classes.
          </p>
        </div>
      </section>

      <section className="model-grid">
        <ModelCard
          icon={Database}
          title="DATASET"
          value="CIC-IDS2017"
          text={`${analytics?.total_flows ?? 0} flows in current analysis window`}
        />

        <ModelCard
          icon={Layers3}
          title="FEATURE SPACE"
          value="20"
          text="Selected flow-level metadata features"
        />

        <ModelCard
          icon={Target}
          title="CLASSES"
          value={classes.length}
          text="NETRA detection categories"
        />

        <ModelCard
          icon={Zap}
          title="INFERENCE"
          value={`${analytics?.processing?.flows_per_second ?? 0}/s`}
          text="Current replay baseline"
        />
      </section>

      <section className="model-columns">
        <div className="model-panel">
          <div className="special-card-heading">
            <div>
              <span>CLASSIFICATION SPACE</span>
              <h3>Threat Classes</h3>
            </div>
          </div>

          <div className="class-grid">
            {classes.map((item, index) => (
              <motion.div
                key={item}
                className={
                  item === "BENIGN"
                    ? "class-chip benign"
                    : "class-chip"
                }
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{
                  delay: index * 0.05,
                }}
              >
                {item}
              </motion.div>
            ))}
          </div>
        </div>

        <div className="model-panel">
          <div className="special-card-heading">
            <div>
              <span>FEATURE PIPELINE</span>
              <h3>Flow Features</h3>
            </div>
          </div>

          <div className="feature-list">
            {features.map((feature) => (
              <span key={feature}>{feature}</span>
            ))}
          </div>
        </div>
      </section>

      <div className="model-note">
        <Target size={17} />
        <span>
          The displayed model metrics represent the current
          prototype training/evaluation setup and should not
          be interpreted as production-world accuracy.
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

export default ModelPage;
