import { useEffect, useState } from "react";
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Database,
  Monitor,
  Cpu,
  RotateCcw,
  Save,
} from "lucide-react";

const DEFAULT_SETTINGS = {
  passiveMonitoring: true,
  replayFlows: 100,
  replayThroughput: 10000,
  datasetFormat: "JSON",
  storageLocation: "Local",
  retentionDays: 30,
  theme: "Dark",
  animations: true,
  refreshRate: 5,
  activeModel: "Random Forest",
  confidenceThreshold: 0.995,
  maxFlowQueue: 10000,
};

function SettingsPage() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("netra_settings");
      if (stored) {
        setSettings({
          ...DEFAULT_SETTINGS,
          ...JSON.parse(stored),
          passiveMonitoring: true,
          activeModel: "Random Forest",
        });
      }
    } catch {
      setSettings(DEFAULT_SETTINGS);
    }
  }, []);

  function update(key, value) {
    setSettings((current) => ({
      ...current,
      [key]: value,
    }));
    setSaved(false);
  }

  function saveSettings() {
    const safeSettings = {
      ...settings,
      passiveMonitoring: true,
      activeModel: "Random Forest",
    };

    localStorage.setItem(
      "netra_settings",
      JSON.stringify(safeSettings)
    );

    setSettings(safeSettings);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 1800);
  }

  function resetSettings() {
    setSettings(DEFAULT_SETTINGS);
    localStorage.setItem(
      "netra_settings",
      JSON.stringify(DEFAULT_SETTINGS)
    );
    setSaved(false);
  }

  return (
    <div className="special-page settings-page">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SYSTEM CONFIGURATION
          </div>

          <h1>Settings</h1>

          <p>
            Configure NETRA replay, monitoring display,
            interface behavior, and detection settings.
          </p>
        </div>
      </div>

      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Monitor size={17} />
          </div>

          <div>
            <span>MONITORING</span>
            <h3>Observation & Replay</h3>
          </div>
        </div>

        <div className="settings-list">
          <SettingRow
            label="Passive Monitoring"
            description="Enable passive network observation without active probing."
            control={
              <Toggle
                checked={true}
                disabled={true}
                onChange={() => {}}
              />
            }
          />

          <SettingRow
            label="Replay Flows per Request"
            description="Number of flows processed per replay request."
            control={
              <select
                className="settings-select"
                value={settings.replayFlows}
                onChange={(e) =>
                  update("replayFlows", Number(e.target.value))
                }
              >
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={250}>250</option>
                <option value={500}>500</option>
                <option value={1000}>1,000</option>
              </select>
            }
          />

          <SettingRow
            label="Replay Throughput Limit"
            description="Maximum flow rate used for replay processing."
            control={
              <select
                className="settings-select"
                value={settings.replayThroughput}
                onChange={(e) =>
                  update("replayThroughput", Number(e.target.value))
                }
              >
                <option value={1000}>1,000 flows/sec</option>
                <option value={5000}>5,000 flows/sec</option>
                <option value={10000}>10,000 flows/sec</option>
                <option value={25000}>25,000 flows/sec</option>
              </select>
            }
          />

          <SettingRow
            label="Alert Latency Threshold"
            description="Display threshold for acceptable alert-processing latency."
            control={
              <div className="settings-inline-control">
                <select
                  className="settings-select"
                  value={settings.alertLatency ?? 500}
                  onChange={(e) =>
                    update("alertLatency", Number(e.target.value))
                  }
                >
                  <option value={100}>100 ms</option>
                  <option value={250}>250 ms</option>
                  <option value={500}>500 ms</option>
                  <option value={1000}>1,000 ms</option>
                </select>
              </div>
            }
          />
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Database size={17} />
          </div>

          <div>
            <span>DATA</span>
            <h3>Storage & Export</h3>
          </div>
        </div>

        <div className="settings-list">
          <SettingRow
            label="Dataset Format"
            description="Format used for report and exported detection data."
            control={
              <select
                className="settings-select"
                value={settings.datasetFormat}
                onChange={(e) =>
                  update("datasetFormat", e.target.value)
                }
              >
                <option value="JSON">JSON</option>
                <option value="CSV">CSV</option>
              </select>
            }
          />

          <SettingRow
            label="Storage Location"
            description="Storage scope for processed flow data."
            control={
              <select
                className="settings-select"
                value={settings.storageLocation}
                onChange={(e) =>
                  update("storageLocation", e.target.value)
                }
              >
                <option value="Local">Local</option>
                <option value="Remote">Remote</option>
              </select>
            }
          />

          <SettingRow
            label="Database Connection"
            description="Persistent database integration status."
            control={
              <div className="settings-status-control">
                <span className="settings-status-dot" />
                Not Configured
              </div>
            }
          />

          <SettingRow
            label="Retention Period"
            description="Duration for retaining historical flow data in the interface configuration."
            control={
              <select
                className="settings-select"
                value={settings.retentionDays}
                onChange={(e) =>
                  update("retentionDays", Number(e.target.value))
                }
              >
                <option value={7}>7 Days</option>
                <option value={30}>30 Days</option>
                <option value={90}>90 Days</option>
                <option value={180}>180 Days</option>
              </select>
            }
          />

          <div className="settings-current-source">
            <Database size={15} />
            <span>
              Current data source:{" "}
              <strong>CIC-IDS2017-DERIVED</strong>
            </span>
          </div>
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Monitor size={17} />
          </div>

          <div>
            <span>INTERFACE</span>
            <h3>Dashboard Display</h3>
          </div>
        </div>

        <div className="settings-list">
          <SettingRow
            label="Theme"
            description="Dashboard color scheme."
            control={
              <select
                className="settings-select"
                value={settings.theme}
                onChange={(e) =>
                  update("theme", e.target.value)
                }
              >
                <option value="Dark">Dark</option>
                <option value="Light">Light</option>
                <option value="System">System</option>
              </select>
            }
          />

          <SettingRow
            label="Animations"
            description="Enable dashboard transitions and visual animations."
            control={
              <Toggle
                checked={settings.animations}
                onChange={(value) =>
                  update("animations", value)
                }
              />
            }
          />

          <SettingRow
            label="Refresh Rate"
            description="Dashboard data refresh interval."
            control={
              <select
                className="settings-select"
                value={settings.refreshRate}
                onChange={(e) =>
                  update("refreshRate", Number(e.target.value))
                }
              >
                <option value={1}>1 second</option>
                <option value={5}>5 seconds</option>
                <option value={10}>10 seconds</option>
                <option value={30}>30 seconds</option>
              </select>
            }
          />
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-heading">
          <div className="settings-section-icon">
            <Cpu size={17} />
          </div>

          <div>
            <span>DETECTION ENGINE</span>
            <h3>Model & Processing</h3>
          </div>
        </div>

        <div className="settings-list">
          <SettingRow
            label="Active Model"
            description="Currently deployed flow-classification model."
            control={
              <select
                className="settings-select"
                value={settings.activeModel}
                disabled
                onChange={() => {}}
              >
                <option value="Random Forest">
                  Random Forest
                </option>
              </select>
            }
          />

          <div className="settings-engine-state">
            <div>
              <span>Detection Mode</span>
              <strong>
                <span className="settings-passive-dot" />
                PASSIVE
              </strong>
            </div>

            <p>
              Passive observation with no active probing,
              mitigation, or payload decryption.
            </p>
          </div>

          <SettingRow
            label="Confidence Threshold"
            description="Minimum confidence displayed for a model classification alert."
            control={
              <div className="settings-range-control">
                <input
                  type="range"
                  min="0.5"
                  max="1"
                  step="0.005"
                  value={settings.confidenceThreshold}
                  onChange={(e) =>
                    update(
                      "confidenceThreshold",
                      Number(e.target.value)
                    )
                  }
                />

                <strong>
                  {(settings.confidenceThreshold * 100).toFixed(1)}%
                </strong>
              </div>
            }
          />

          <SettingRow
            label="Max Flow Queue"
            description="Maximum configured flow-processing queue size."
            control={
              <select
                className="settings-select"
                value={settings.maxFlowQueue}
                onChange={(e) =>
                  update("maxFlowQueue", Number(e.target.value))
                }
              >
                <option value={1000}>1,000 flows</option>
                <option value={5000}>5,000 flows</option>
                <option value={10000}>10,000 flows</option>
                <option value={25000}>25,000 flows</option>
              </select>
            }
          />
        </div>
      </section>

      <section className="settings-actions">
        <button
          className="settings-action secondary"
          onClick={resetSettings}
          type="button"
        >
          <RotateCcw size={15} />
          RESET TO DEFAULTS
        </button>

        <button
          className="settings-action primary"
          onClick={saveSettings}
          type="button"
        >
          <Save size={15} />
          {saved ? "SAVED" : "SAVE CHANGES"}
        </button>
      </section>

      <section className="settings-compliance">
        <div className="settings-compliance-icon">
          <ShieldCheck size={18} />
        </div>

        <div>
          <strong>
            NETRA SECURITY ENGINE • PASSIVE MONITORING
          </strong>

          <span>
            READ-ONLY DETECTION MODE • NO ACTIVE PROBING •
            NO MITIGATION • NO PAYLOAD DECRYPTION
          </span>
        </div>
      </section>

      <div className="settings-config-note">
        <SettingsIcon size={14} />
        <span>
          Settings are persisted locally in this browser.
          Detection-engine deployment values remain fixed to
          the currently validated NETRA prototype configuration.
        </span>
      </div>
    </div>
  );
}

function SettingRow({ label, description, control }) {
  return (
    <div className="settings-row">
      <div className="settings-row-copy">
        <strong>{label}</strong>
        <span>{description}</span>
      </div>

      <div className="settings-row-control">
        {control}
      </div>
    </div>
  );
}

function Toggle({ checked, onChange, disabled = false }) {
  return (
    <button
      type="button"
      className={`settings-toggle ${checked ? "active" : ""}`}
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      aria-pressed={checked}
    >
      <span className="settings-toggle-track">
        <span className="settings-toggle-thumb" />
      </span>

      <span className="settings-toggle-label">
        {checked ? "ON" : "OFF"}
      </span>
    </button>
  );
}

export default SettingsPage;
