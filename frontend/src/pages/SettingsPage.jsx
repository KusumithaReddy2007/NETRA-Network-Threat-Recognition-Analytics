import { useState } from "react";
import {
  Activity,
  Database,
  Gauge,
  MonitorCog,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";

function SettingsPage() {
  const [replayFlows, setReplayFlows] = useState(100);
  const [animations, setAnimations] = useState(true);
  const [passiveMode, setPassiveMode] = useState(true);

  return (
    <div className="special-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SYSTEM CONFIGURATION
          </div>

          <h1>Settings</h1>

          <p>
            Configure NETRA replay, monitoring display,
            and interface behavior.
          </p>
        </div>
      </div>

      <section className="settings-grid">
        <SettingsSection
          icon={MonitorCog}
          title="MONITORING"
          description="Frontend monitoring configuration"
        >
          <SettingRow
            label="Passive monitoring"
            description="Read-only network observation mode"
          >
            <Toggle
              value={passiveMode}
              setValue={setPassiveMode}
            />
          </SettingRow>

          <SettingRow
            label="Replay flows"
            description="Number of flows processed per replay"
          >
            <input
              className="setting-number"
              type="number"
              min="1"
              max="1000"
              value={replayFlows}
              onChange={(e) =>
                setReplayFlows(
                  Number(e.target.value)
                )
              }
            />
          </SettingRow>
        </SettingsSection>

        <SettingsSection
          icon={Activity}
          title="INTERFACE"
          description="NETRA visual experience"
        >
          <SettingRow
            label="Professional animations"
            description="Cybersecurity visual effects"
          >
            <Toggle
              value={animations}
              setValue={setAnimations}
            />
          </SettingRow>
        </SettingsSection>

        <SettingsSection
          icon={Database}
          title="DATA"
          description="Current NETRA data configuration"
        >
          <InfoSetting
            label="Dataset"
            value="CIC-IDS2017"
          />

          <InfoSetting
            label="Storage"
            value="CSV / Prototype"
          />

          <InfoSetting
            label="Database"
            value="Persistence layer planned"
          />
        </SettingsSection>

        <SettingsSection
          icon={Gauge}
          title="DETECTION ENGINE"
          description="Current inference configuration"
        >
          <InfoSetting
            label="Model"
            value="Random Forest"
          />

          <InfoSetting
            label="Detection mode"
            value="Passive"
          />

          <InfoSetting
            label="Streaming"
            value="CSV Replay"
          />
        </SettingsSection>
      </section>

      <div className="settings-note">
        <SlidersHorizontal size={17} />

        <span>
          These controls currently configure the frontend
          experience. Runtime engine configuration will be
          connected as the NETRA ingestion and persistence
          layers are expanded.
        </span>
      </div>
    </div>
  );
}

function SettingsSection({
  icon: Icon,
  title,
  description,
  children,
}) {
  return (
    <section className="settings-card">
      <div className="settings-card-heading">
        <div className="settings-icon">
          <Icon size={19} />
        </div>

        <div>
          <span>{title}</span>
          <p>{description}</p>
        </div>
      </div>

      <div className="settings-body">
        {children}
      </div>
    </section>
  );
}

function SettingRow({
  label,
  description,
  children,
}) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <span>{description}</span>
      </div>

      {children}
    </div>
  );
}

function InfoSetting({ label, value }) {
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <span>{value}</span>
      </div>

      <ShieldCheck
        size={17}
        className="setting-ok"
      />
    </div>
  );
}

function Toggle({ value, setValue }) {
  return (
    <button
      type="button"
      className={`toggle ${value ? "on" : ""}`}
      onClick={() => setValue(!value)}
      aria-label="Toggle setting"
    >
      <span />
    </button>
  );
}

export default SettingsPage;
