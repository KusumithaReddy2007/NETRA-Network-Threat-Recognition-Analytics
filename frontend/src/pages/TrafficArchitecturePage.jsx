import { useEffect, useMemo, useState } from "react";
import { Activity, Eye, ShieldAlert, ArrowRight } from "lucide-react";

const BASE_STREAMS = [
  { y: 7, curve: -55, color: "blue", speed: 5.8, width: 3.2 },
  { y: 13, curve: 32, color: "red", speed: 4.7, width: 3.4 },
  { y: 19, curve: -28, color: "green", speed: 6.6, width: 3 },
  { y: 25, curve: 48, color: "blue", speed: 5.5, width: 3.1 },
  { y: 31, curve: -42, color: "red", speed: 4.4, width: 3.7 },
  { y: 37, curve: 28, color: "yellow", speed: 5.2, width: 3.1 },
  { y: 43, curve: -35, color: "blue", speed: 6.3, width: 3 },
  { y: 49, curve: 45, color: "red", speed: 4.6, width: 3.6 },
  { y: 55, curve: -30, color: "green", speed: 6.1, width: 3.1 },
  { y: 61, curve: 38, color: "red", speed: 4.8, width: 3.5 },
  { y: 67, curve: -46, color: "blue", speed: 5.9, width: 3 },
  { y: 73, curve: 31, color: "green", speed: 6.5, width: 3 },
  { y: 79, curve: -35, color: "red", speed: 4.5, width: 3.6 },
  { y: 85, curve: 42, color: "blue", speed: 5.7, width: 3 },
  { y: 91, curve: -22, color: "yellow", speed: 5.3, width: 3 },
];

function normalizeClass(value) {
  return String(value || "BENIGN").trim().toUpperCase();
}

function labelFor(value) {
  const labels = {
    BENIGN: "NORMAL TRAFFIC",
    DDOS: "DDOS",
    DOS: "DOS",
    PORTSCAN: "PORT SCAN",
    BOT: "BOT C2",
    BRUTE_FORCE: "BRUTE FORCE",
    WEB_ATTACK: "WEB ATTACK",
  };

  return labels[normalizeClass(value)] || normalizeClass(value);
}

function modeFor(value) {
  const cls = normalizeClass(value);

  if (cls === "DDOS" || cls === "DOS") return "flood";
  if (cls === "PORTSCAN") return "scan";
  if (cls === "BOT") return "beacon";
  if (cls === "BENIGN") return "normal";
  return "threat";
}

function TrafficArchitecturePage({
  flowResults = [],
  runReplay,
  replaying,
}) {
  const [currentIndex, setCurrentIndex] = useState(-1);

  const total = Array.isArray(flowResults)
    ? flowResults.length
    : 0;

  const currentFlow =
    currentIndex >= 0 && currentIndex < total
      ? flowResults[currentIndex]
      : null;

  const currentClass = normalizeClass(
    currentFlow?.predicted_class
  );

  const mode = modeFor(currentClass);

  const confidence = Number(
    currentFlow?.confidence || 0
  );

  useEffect(() => {
    if (!total) {
      setCurrentIndex(-1);
      return undefined;
    }

    setCurrentIndex(0);

    const timer = setInterval(() => {
      setCurrentIndex((value) =>
        value >= total - 1 ? 0 : value + 1
      );
    }, 320);

    return () => clearInterval(timer);
  }, [total]);

  const streams = useMemo(() => {
    let result = [...BASE_STREAMS];

    if (mode === "flood") {
      result = [
        ...result,
        { y: 10, curve: 45, color: "red", speed: 3.8, width: 4 },
        { y: 17, curve: -38, color: "red", speed: 3.6, width: 4 },
        { y: 23, curve: 52, color: "red", speed: 3.9, width: 4.2 },
        { y: 29, curve: -48, color: "red", speed: 3.5, width: 4 },
        { y: 35, curve: 36, color: "red", speed: 3.7, width: 4.3 },
        { y: 41, curve: -28, color: "red", speed: 3.4, width: 4 },
        { y: 47, curve: 46, color: "red", speed: 3.8, width: 4.4 },
        { y: 53, curve: -44, color: "red", speed: 3.6, width: 4 },
        { y: 59, curve: 34, color: "red", speed: 3.5, width: 4.2 },
        { y: 65, curve: -52, color: "red", speed: 3.9, width: 4 },
        { y: 71, curve: 42, color: "red", speed: 3.7, width: 4.3 },
        { y: 77, curve: -35, color: "red", speed: 3.5, width: 4 },
      ];
    }

    return result;
  }, [mode]);

  const particles = useMemo(() => {
    return streams.flatMap((stream, streamIndex) => {
      const count =
        mode === "flood" && stream.color === "red"
          ? 9
          : 5;

      return Array.from({ length: count }, (_, index) => ({
        id: `${streamIndex}-${index}`,
        streamIndex,
        offset:
          (index / count) * streams[streamIndex].speed,
        radius:
          stream.color === "red"
            ? 3.6 + (index % 3) * 0.8
            : 2.7 + (index % 3) * 0.6,
      }));
    });
  }, [streams, mode]);

  async function replay() {
    if (
      replaying ||
      typeof runReplay !== "function"
    ) {
      return;
    }

    setCurrentIndex(-1);
    await runReplay();
  }

  return (
    <div className="netra-flow-visual">
      <style>{`
        .netra-flow-visual {
          padding: 18px 22px 28px;
          min-height: 100%;
          color: #e6f4ff;
        }

        .nfw-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 18px;
          margin-bottom: 15px;
        }

        .nfw-kicker {
          font-size: 9px;
          letter-spacing: .2em;
          font-weight: 900;
          color: #38bdf8;
          text-transform: uppercase;
          opacity: .8;
        }

        .nfw-title {
          margin: 5px 0 0;
          font-size: 28px;
          font-weight: 900;
          letter-spacing: -.035em;
        }

        .nfw-description {
          max-width: 900px;
          margin: 6px 0 0;
          font-size: 11px;
          line-height: 1.6;
          color: rgba(226,244,255,.54);
        }

        .nfw-button {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 10px 14px;
          border-radius: 9px;
          color: #7dd3fc;
          border: 1px solid rgba(56,189,248,.3);
          background: rgba(8,47,73,.35);
          font-size: 10px;
          font-weight: 900;
          cursor: pointer;
          box-shadow: 0 0 18px rgba(14,165,233,.07);
        }

        .nfw-button:hover {
          border-color: rgba(56,189,248,.6);
          box-shadow: 0 0 24px rgba(14,165,233,.13);
        }

        .nfw-button:disabled {
          opacity: .5;
          cursor: not-allowed;
        }

        .nfw-stage {
          position: relative;
          height: 650px;
          overflow: hidden;
          border-radius: 20px;
          border: 1px solid rgba(56,189,248,.16);
          background:
            radial-gradient(
              circle at 14% 50%,
              rgba(14,165,233,.13),
              transparent 18%
            ),
            radial-gradient(
              circle at 67% 50%,
              rgba(239,68,68,.055),
              transparent 22%
            ),
            radial-gradient(
              circle at 92% 50%,
              rgba(34,197,94,.1),
              transparent 17%
            ),
            linear-gradient(
              180deg,
              #020713 0%,
              #03101c 48%,
              #020713 100%
            );
          box-shadow:
            inset 0 0 100px rgba(0,150,255,.045),
            0 25px 70px rgba(0,0,0,.22);
        }

        .nfw-grid {
          position: absolute;
          inset: 0;
          background-image:
            linear-gradient(
              rgba(56,189,248,.032) 1px,
              transparent 1px
            ),
            linear-gradient(
              90deg,
              rgba(56,189,248,.032) 1px,
              transparent 1px
            );
          background-size: 28px 28px;
          mask-image: linear-gradient(
            90deg,
            transparent,
            black 11%,
            black 89%,
            transparent
          );
        }

        .nfw-stars {
          position: absolute;
          inset: 0;
          background-image:
            radial-gradient(
              circle,
              rgba(255,255,255,.35) 1px,
              transparent 1.6px
            );
          background-size: 52px 52px;
          opacity: .10;
        }

        .nfw-vignette {
          position: absolute;
          inset: 0;
          background:
            linear-gradient(
              90deg,
              rgba(2,7,19,.72),
              transparent 15%,
              transparent 84%,
              rgba(2,7,19,.58)
            );
          pointer-events: none;
          z-index: 4;
        }

        /* GLOBE */

        .nfw-globe {
          position: absolute;
          left: -78px;
          top: 50%;
          width: 290px;
          height: 290px;
          transform: translateY(-50%);
          border-radius: 50%;
          border: 1px solid rgba(56,189,248,.42);
          box-shadow:
            inset 0 0 60px rgba(14,165,233,.17),
            0 0 70px rgba(14,165,233,.12);
          z-index: 2;
        }

        .nfw-globe::before {
          content: "";
          position: absolute;
          inset: 18px;
          border-radius: 50%;
          border: 1px solid rgba(56,189,248,.2);
        }

        .nfw-globe::after {
          content: "";
          position: absolute;
          left: 32%;
          right: 32%;
          top: 0;
          bottom: 0;
          border-left: 1px solid rgba(56,189,248,.17);
          border-right: 1px solid rgba(56,189,248,.17);
          border-radius: 50%;
        }

        .nfw-globe-grid {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          background:
            linear-gradient(
              0deg,
              transparent 48%,
              rgba(56,189,248,.18) 49%,
              rgba(56,189,248,.18) 50%,
              transparent 51%
            ),
            linear-gradient(
              90deg,
              transparent 48%,
              rgba(56,189,248,.13) 49%,
              rgba(56,189,248,.13) 50%,
              transparent 51%
            );
        }

        .nfw-globe-dot {
          position: absolute;
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: #38bdf8;
          box-shadow:
            0 0 10px #38bdf8,
            0 0 18px rgba(56,189,248,.4);
        }

        .nfw-globe-dot.a { left: 43%; top: 26%; }
        .nfw-globe-dot.b { left: 28%; top: 44%; }
        .nfw-globe-dot.c { left: 58%; top: 35%; }
        .nfw-globe-dot.d { left: 66%; top: 62%; }
        .nfw-globe-dot.e { left: 36%; top: 70%; }

        .nfw-globe-label {
          position: absolute;
          left: 45px;
          top: calc(50% + 165px);
          z-index: 4;
          color: #38bdf8;
          font-size: 7px;
          letter-spacing: .16em;
          font-weight: 900;
          opacity: .65;
        }

        /* TRAFFIC */

        .nfw-stream-zone {
          position: absolute;
          left: 8%;
          right: 8%;
          top: 50%;
          height: 510px;
          transform: translateY(-50%);
          z-index: 3;
        }

        .nfw-stream-svg {
          width: 100%;
          height: 100%;
          overflow: visible;
        }

        .stream-base {
          fill: none;
          stroke-linecap: round;
          opacity: .18;
        }

        .stream-base.blue {
          stroke: #38bdf8;
        }

        .stream-base.green {
          stroke: #4ade80;
        }

        .stream-base.yellow {
          stroke: #facc15;
        }

        .stream-base.red {
          stroke: #ef4444;
        }

        .stream-glow {
          fill: none;
          stroke-linecap: round;
          opacity: .25;
          filter: url(#blurGlow);
        }

        .stream-glow.blue { stroke: #38bdf8; }
        .stream-glow.green { stroke: #4ade80; }
        .stream-glow.yellow { stroke: #facc15; }
        .stream-glow.red { stroke: #ef4444; }

        .particle.blue {
          fill: #38bdf8;
          filter: url(#particleGlow);
        }

        .particle.green {
          fill: #4ade80;
          filter: url(#particleGlow);
        }

        .particle.yellow {
          fill: #facc15;
          filter: url(#particleGlow);
        }

        .particle.red {
          fill: #ff3b4f;
          filter: url(#redGlow);
        }

        /* THREAT NODES */

        .nfw-threat-node {
          fill: #ef4444;
          stroke: rgba(255,185,185,.95);
          stroke-width: 1.1;
          filter: url(#redGlow);
        }

        .nfw-threat-ring {
          fill: none;
          stroke: rgba(239,68,68,.45);
          stroke-width: 1;
          transform-box: fill-box;
          transform-origin: center;
          animation: threatRing 1.35s ease-out infinite;
        }

        @keyframes threatRing {
          0% {
            transform: scale(.65);
            opacity: .9;
          }
          100% {
            transform: scale(2);
            opacity: 0;
          }
        }

        /* GATE */

        .nfw-gate {
          position: absolute;
          left: 37%;
          top: 50%;
          width: 105px;
          height: 470px;
          transform: translate(-50%, -50%);
          z-index: 8;
        }

        .nfw-gate-panel {
          position: absolute;
          inset: 0;
          border-left: 2px solid rgba(245,158,11,.85);
          border-right: 2px solid rgba(245,158,11,.25);
          background:
            linear-gradient(
              90deg,
              rgba(245,158,11,.025),
              rgba(245,158,11,.11),
              rgba(245,158,11,.015)
            );
          box-shadow:
            inset 0 0 30px rgba(245,158,11,.08),
            0 0 30px rgba(245,158,11,.08);
        }

        .nfw-gate-core {
          position: absolute;
          top: 50%;
          left: 50%;
          width: 18px;
          height: 18px;
          transform: translate(-50%, -50%);
          border-radius: 50%;
          background: #fbbf24;
          box-shadow:
            0 0 10px #f59e0b,
            0 0 35px rgba(245,158,11,.65),
            0 0 70px rgba(245,158,11,.25);
          animation: gatePulse 1.7s ease-in-out infinite;
        }

        @keyframes gatePulse {
          0%,100% {
            transform: translate(-50%,-50%) scale(.9);
          }
          50% {
            transform: translate(-50%,-50%) scale(1.18);
          }
        }

        .nfw-gate-arrow {
          position: absolute;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          color: #fff3b0;
          filter: drop-shadow(0 0 8px rgba(245,158,11,.8));
        }

        .nfw-gate-label {
          position: absolute;
          left: 50%;
          top: -14px;
          transform: translateX(-50%);
          white-space: nowrap;
          color: #fbbf24;
          font-size: 7px;
          font-weight: 900;
          letter-spacing: .17em;
        }

        .nfw-gate-sub {
          position: absolute;
          left: 50%;
          bottom: -15px;
          transform: translateX(-50%);
          white-space: nowrap;
          color: rgba(251,191,36,.65);
          font-size: 6px;
          letter-spacing: .12em;
          font-weight: 900;
        }

        /* NETRA */

        .nfw-netra {
          position: absolute;
          right: 23px;
          top: 50%;
          transform: translateY(-50%);
          z-index: 10;
          width: 158px;
        }

        .nfw-netra-card {
          padding: 18px 13px;
          border-radius: 17px;
          border: 1px solid rgba(34,197,94,.36);
          background:
            linear-gradient(
              180deg,
              rgba(7,34,27,.83),
              rgba(3,18,18,.84)
            );
          box-shadow:
            0 0 25px rgba(34,197,94,.09),
            inset 0 0 25px rgba(34,197,94,.035);
          backdrop-filter: blur(9px);
          text-align: center;
        }

        .nfw-netra-icon {
          position: relative;
          width: 54px;
          height: 54px;
          margin: 0 auto 10px;
          display: grid;
          place-items: center;
          border-radius: 15px;
          color: #4ade80;
          background: rgba(34,197,94,.08);
          border: 1px solid rgba(34,197,94,.23);
          box-shadow:
            0 0 25px rgba(34,197,94,.07);
        }

        .nfw-netra-icon::after {
          content: "";
          position: absolute;
          inset: -6px;
          border-radius: 19px;
          border: 1px solid rgba(34,197,94,.1);
          animation: netraPulse 2s ease-in-out infinite;
        }

        @keyframes netraPulse {
          0%,100% { transform: scale(.95); opacity: .35; }
          50% { transform: scale(1.1); opacity: .8; }
        }

        .nfw-netra-title {
          font-size: 12px;
          font-weight: 900;
          letter-spacing: .12em;
          color: #d1fae5;
        }

        .nfw-netra-status {
          margin-top: 4px;
          color: #4ade80;
          font-size: 7px;
          font-weight: 900;
          letter-spacing: .1em;
        }

        .nfw-netra-copy {
          margin-top: 7px;
          color: rgba(226,255,242,.45);
          font-size: 8px;
          line-height: 1.55;
        }

        /* LABEL */

        .nfw-threat-label {
          position: absolute;
          left: 54%;
          top: 25%;
          z-index: 13;
          min-width: 145px;
          padding: 10px 13px;
          border-radius: 11px;
          border: 1px solid rgba(239,68,68,.45);
          background:
            linear-gradient(
              180deg,
              rgba(94,12,20,.82),
              rgba(47,7,12,.78)
            );
          box-shadow:
            0 0 30px rgba(239,68,68,.13),
            inset 0 0 22px rgba(239,68,68,.04);
          backdrop-filter: blur(9px);
          text-align: center;
          animation: threatFloat 1.5s ease-in-out infinite;
        }

        @keyframes threatFloat {
          0%,100% {
            transform: translateY(0);
          }
          50% {
            transform: translateY(-4px);
          }
        }

        .nfw-threat-kicker {
          color: #fca5a5;
          font-size: 6px;
          font-weight: 900;
          letter-spacing: .16em;
        }

        .nfw-threat-name {
          margin-top: 3px;
          color: #fff1f2;
          font-size: 13px;
          font-weight: 900;
          letter-spacing: .08em;
        }

        .nfw-threat-score {
          margin-top: 3px;
          color: rgba(254,202,202,.66);
          font-size: 8px;
          font-weight: 800;
        }

        /* STATUS */

        .nfw-top-right {
          position: absolute;
          top: 18px;
          right: 20px;
          z-index: 15;
          display: flex;
          align-items: center;
          gap: 7px;
          color: #4ade80;
          font-size: 7px;
          letter-spacing: .14em;
          font-weight: 900;
        }

        .nfw-live-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: #4ade80;
          box-shadow:
            0 0 8px #4ade80,
            0 0 16px rgba(74,222,128,.45);
          animation: liveBlink 1.4s ease-in-out infinite;
        }

        @keyframes liveBlink {
          0%,100% { opacity: .45; }
          50% { opacity: 1; }
        }

        .nfw-bottom {
          position: absolute;
          left: 19px;
          right: 19px;
          bottom: 16px;
          z-index: 15;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .nfw-current {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 11px;
          border-radius: 8px;
          background: rgba(2,6,23,.82);
          border: 1px solid rgba(148,163,184,.13);
          font-size: 8px;
          font-weight: 900;
          letter-spacing: .03em;
        }

        .nfw-current-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: #38bdf8;
          box-shadow: 0 0 9px rgba(56,189,248,.75);
        }

        .nfw-current-dot.alert {
          background: #ef4444;
          box-shadow: 0 0 10px rgba(239,68,68,.9);
        }

        .nfw-progress {
          flex: 1;
          height: 3px;
          border-radius: 999px;
          overflow: hidden;
          background: rgba(148,163,184,.1);
        }

        .nfw-progress-fill {
          height: 100%;
          border-radius: inherit;
          background: linear-gradient(
            90deg,
            #0ea5e9,
            #38bdf8
          );
          transition: width .3s linear;
          box-shadow: 0 0 9px rgba(56,189,248,.35);
        }

        .nfw-readonly {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 7px 9px;
          border-radius: 8px;
          background: rgba(66,47,4,.58);
          border: 1px solid rgba(245,158,11,.22);
          color: #fbbf24;
          font-size: 7px;
          letter-spacing: .11em;
          font-weight: 900;
        }

        .nfw-data {
          display: grid;
          grid-template-columns: repeat(6, 1fr);
          gap: 7px;
          margin-top: 10px;
        }

        .nfw-data-card {
          padding: 9px 10px;
          border-radius: 9px;
          background: rgba(8,16,32,.52);
          border: 1px solid rgba(56,189,248,.08);
        }

        .nfw-data-label {
          font-size: 6px;
          text-transform: uppercase;
          letter-spacing: .1em;
          font-weight: 900;
          opacity: .4;
        }

        .nfw-data-value {
          margin-top: 4px;
          font-size: 9px;
          font-weight: 900;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }


        .nfw-legend {
          position: absolute;
          left: 20px;
          bottom: 55px;
          z-index: 18;
          width: 205px;
          padding: 11px 12px;
          border-radius: 11px;
          border: 1px solid rgba(56,189,248,.13);
          background: rgba(2,8,20,.78);
          box-shadow: 0 8px 25px rgba(0,0,0,.22);
          backdrop-filter: blur(9px);
        }

        .nfw-legend-title {
          margin-bottom: 8px;
          color: rgba(226,244,255,.78);
          font-size: 7px;
          font-weight: 900;
          letter-spacing: .15em;
          text-transform: uppercase;
        }

        .nfw-legend-row {
          display: flex;
          align-items: center;
          gap: 8px;
          margin: 6px 0;
          color: rgba(226,244,255,.58);
          font-size: 8px;
          line-height: 1.25;
        }

        .nfw-legend-symbol {
          position: relative;
          flex: 0 0 auto;
          width: 24px;
          height: 9px;
        }

        .nfw-legend-line {
          position: absolute;
          left: 0;
          right: 0;
          top: 50%;
          height: 2px;
          transform: translateY(-50%);
          border-radius: 99px;
        }

        .nfw-legend-line.blue {
          background: #38bdf8;
          box-shadow: 0 0 8px rgba(56,189,248,.75);
        }

        .nfw-legend-line.green {
          background: #4ade80;
          box-shadow: 0 0 8px rgba(74,222,128,.7);
        }

        .nfw-legend-line.yellow {
          background: #facc15;
          box-shadow: 0 0 8px rgba(250,204,21,.7);
        }

        .nfw-legend-line.red {
          background: #ef4444;
          box-shadow: 0 0 9px rgba(239,68,68,.85);
        }

        .nfw-legend-dot {
          position: absolute;
          left: 8px;
          top: 50%;
          width: 7px;
          height: 7px;
          transform: translate(-50%, -50%);
          border-radius: 50%;
        }

        .nfw-legend-dot.red {
          background: #ef4444;
          box-shadow:
            0 0 7px #ef4444,
            0 0 13px rgba(239,68,68,.6);
        }

        .nfw-legend-dot.yellow {
          background: #facc15;
          box-shadow:
            0 0 7px #facc15,
            0 0 13px rgba(250,204,21,.55);
        }

        .nfw-legend-direction {
          color: #fbbf24;
          font-size: 14px;
          line-height: 1;
          font-weight: 900;
          filter: drop-shadow(0 0 5px rgba(245,158,11,.55));
        }

        .nfw-legend-ring {
          position: relative;
          width: 11px;
          height: 11px;
          flex: 0 0 auto;
          border-radius: 50%;
          border: 1px solid #ef4444;
          box-shadow: 0 0 8px rgba(239,68,68,.55);
        }

        .nfw-legend-ring::after {
          content: "";
          position: absolute;
          left: 50%;
          top: 50%;
          width: 4px;
          height: 4px;
          transform: translate(-50%, -50%);
          border-radius: 50%;
          background: #ef4444;
          box-shadow: 0 0 7px #ef4444;
        }

        .nfw-legend-note {
          margin-top: 8px;
          padding-top: 7px;
          border-top: 1px solid rgba(148,163,184,.09);
          color: rgba(226,244,255,.38);
          font-size: 7px;
          line-height: 1.45;
        }

        @media (max-width: 1050px) {
          .nfw-netra {
            right: 10px;
            width: 125px;
          }

          .nfw-gate {
            left: 36%;
          }

          .nfw-data {
            grid-template-columns: repeat(3, 1fr);
          }
        }

        @media (max-width: 700px) {
          .netra-flow-visual {
            padding: 15px;
          }

          .nfw-header {
            flex-direction: column;
          }

          .nfw-stage {
            height: 560px;
          }


          .nfw-legend {
            left: 10px;
            bottom: 52px;
            width: 178px;
            padding: 9px 10px;
          }

          .nfw-legend-row {
            font-size: 7px;
            margin: 5px 0;
          }

          .nfw-globe {
            width: 190px;
            height: 190px;
            left: -90px;
          }

          .nfw-flow-zone {
            left: 4%;
            right: 4%;
            height: 380px;
          }

          .nfw-gate {
            display: none;
          }

          .nfw-netra {
            width: 94px;
          }

          .nfw-netra-card {
            padding: 11px 7px;
          }

          .nfw-netra-icon {
            width: 38px;
            height: 38px;
          }

          .nfw-threat-label {
            left: 49%;
          }

          .nfw-progress {
            max-width: 90px;
          }

          .nfw-data {
            grid-template-columns: repeat(2, 1fr);
          }
        }
      `}</style>

      <div className="nfw-header">
        <div>
          <div className="nfw-kicker">
            NETRA / PASSIVE OBSERVATION
          </div>

          <h1 className="nfw-title">
            Unidirectional IP Traffic
          </h1>

          <p className="nfw-description">
            Animated representation of the one-way traffic stream observed
            by NETRA. The visual behavior changes according to the actual
            threat classification returned by the backend.
          </p>
        </div>

        <button
          className="nfw-button"
          onClick={replay}
          disabled={replaying}
        >
          <Activity size={13} />
          {replaying
            ? "PROCESSING..."
            : "REPLAY TRAFFIC"}
        </button>
      </div>

      <div className="nfw-stage">
        <div className="nfw-grid" />
        <div className="nfw-stars" />
        <div className="nfw-map" />

        <div className="nfw-globe">
          <div className="nfw-globe-grid" />
          <span className="nfw-globe-dot a" />
          <span className="nfw-globe-dot b" />
          <span className="nfw-globe-dot c" />
          <span className="nfw-globe-dot d" />
          <span className="nfw-globe-dot e" />
        </div>

        <div className="nfw-globe-label">
          OBSERVED NETWORK
        </div>

        <div className="nfw-top-right">
          <span className="nfw-live-dot" />
          PASSIVE SENSOR ACTIVE
        </div>

        <div className="nfw-stream-zone">
          <svg
            className="nfw-stream-svg"
            viewBox="0 0 1100 510"
            preserveAspectRatio="none"
          >
            <defs>
              <filter
                id="blurGlow"
                x="-40%"
                y="-40%"
                width="180%"
                height="180%"
              >
                <feGaussianBlur stdDeviation="4" />
              </filter>

              <filter
                id="particleGlow"
                x="-100%"
                y="-100%"
                width="300%"
                height="300%"
              >
                <feGaussianBlur
                  in="SourceGraphic"
                  stdDeviation="1.6"
                  result="blur"
                />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <filter
                id="redGlow"
                x="-150%"
                y="-150%"
                width="400%"
                height="400%"
              >
                <feGaussianBlur
                  in="SourceGraphic"
                  stdDeviation="2.5"
                  result="blur"
                />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {streams.map((stream, index) => {
              const startY = (stream.y / 100) * 465 + 22;
              const midY = startY + stream.curve;
              const endY = startY;

              const path = `
                M -30 ${startY}
                C 145 ${startY - stream.curve},
                  275 ${midY},
                  470 ${midY}
                S 760 ${endY + stream.curve},
                  1130 ${endY}
              `;

              const particleCount =
                mode === "flood" &&
                stream.color === "red"
                  ? 10
                  : 5;

              return (
                <g key={index}>
                  <path
                    d={path}
                    className={`stream-glow ${stream.color}`}
                    strokeWidth={stream.width + 5}
                  />

                  <path
                    d={path}
                    className={`stream-base ${stream.color}`}
                    strokeWidth={stream.width}
                  />

                  {Array.from({
                    length: particleCount,
                  }).map((_, particleIndex) => (
                    <circle
                      key={particleIndex}
                      className={`particle ${stream.color}`}
                      r={
                        stream.color === "red"
                          ? 4 + (particleIndex % 3)
                          : 3 + (particleIndex % 2)
                      }
                    >
                      <animateMotion
                        dur={`${stream.speed}s`}
                        begin={`-${(
                          particleIndex *
                          (stream.speed / particleCount)
                        ).toFixed(2)}s`}
                        repeatCount="indefinite"
                        path={path}
                      />

                      <animate
                        attributeName="opacity"
                        values="0;1;1;.65;0"
                        dur={`${stream.speed}s`}
                        begin={`-${(
                          particleIndex *
                          (stream.speed / particleCount)
                        ).toFixed(2)}s`}
                        repeatCount="indefinite"
                      />
                    </circle>
                  ))}

                  {stream.color === "red" &&
                    [0, 1].map((threatIndex) => {
                      const x =
                        270 + threatIndex * 95;
                      const y =
                        midY +
                        (threatIndex === 0
                          ? -2
                          : 3);

                      return (
                        <g key={threatIndex}>
                          <circle
                            cx={x}
                            cy={y}
                            r="8"
                            className="nfw-threat-ring"
                          />

                          <circle
                            cx={x}
                            cy={y}
                            r="4.7"
                            className="nfw-threat-node"
                          />
                        </g>
                      );
                    })}
                </g>
              );
            })}
          </svg>
        </div>

        {(currentFlow?.alert_generated ||
          mode === "flood") && (
          <div className="nfw-threat-label">
            <div className="nfw-threat-kicker">
              NETRA DETECTED
            </div>

            <div className="nfw-threat-name">
              {currentFlow
                ? labelFor(currentClass)
                : "THREAT STREAM"}
            </div>

            <div className="nfw-threat-score">
              {currentFlow
                ? `${currentFlow.severity || "ALERT"} · ${confidence.toFixed(1)}%`
                : "ANOMALOUS TRAFFIC"}
            </div>
          </div>
        )}


        <div className="nfw-legend">
          <div className="nfw-legend-title">
            Traffic Visualization
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-symbol">
              <span className="nfw-legend-line blue" />
            </span>
            <span>
              <strong>Blue</strong> — normal traffic
            </span>
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-symbol">
              <span className="nfw-legend-line green" />
            </span>
            <span>
              <strong>Green</strong> — legitimate flow
            </span>
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-symbol">
              <span className="nfw-legend-line yellow" />
            </span>
            <span>
              <strong>Yellow</strong> — suspicious behavior
            </span>
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-symbol">
              <span className="nfw-legend-line red" />
              <span className="nfw-legend-dot red" />
            </span>
            <span>
              <strong>Red</strong> — detected threat flow
            </span>
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-ring" />
            <span>
              <strong>Red pulse</strong> — threat event marker
            </span>
          </div>

          <div className="nfw-legend-row">
            <span className="nfw-legend-direction">→</span>
            <span>
              <strong>Arrow</strong> — one-way traffic
            </span>
          </div>

          <div className="nfw-legend-note">
            Colors represent the visualized traffic behavior and
            NETRA detection state; they are not packet-level labels.
          </div>
        </div>

        <div className="nfw-gate">
          <div className="nfw-gate-panel" />
          <div className="nfw-gate-core" />

          <div className="nfw-gate-arrow">
            <ArrowRight size={31} />
          </div>

          <div className="nfw-gate-label">
            ONE-WAY ENFORCEMENT
          </div>

          <div className="nfw-gate-sub">
            NO RETURN PATH
          </div>
        </div>

        <div className="nfw-netra">
          <div className="nfw-netra-card">
            <div className="nfw-netra-icon">
              <Eye size={27} />
            </div>

            <div className="nfw-netra-title">
              NETRA
            </div>

            <div className="nfw-netra-status">
              SENSOR ONLINE
            </div>

            <div className="nfw-netra-copy">
              Observe
              <br />
              Extract
              <br />
              Infer
              <br />
              Alert
            </div>
          </div>
        </div>

        <div className="nfw-vignette" />

        <div className="nfw-bottom">
          <div className="nfw-current">
            <span
              className={`nfw-current-dot ${
                currentFlow?.alert_generated
                  ? "alert"
                  : ""
              }`}
            />

            <span>
              {currentFlow
                ? `FLOW #${currentFlow.flow_number} · ${labelFor(
                    currentClass
                  )}`
                : "TRAFFIC STREAM ACTIVE"}
            </span>
          </div>

          <div className="nfw-progress">
            <div
              className="nfw-progress-fill"
              style={{
                width:
                  total > 0 && currentIndex >= 0
                    ? `${((currentIndex + 1) / total) * 100}%`
                    : "0%",
              }}
            />
          </div>

          <div className="nfw-readonly">
            <ShieldAlert size={10} />
            READ-ONLY / PASSIVE
          </div>
        </div>
      </div>

    </div>
  );
}

export default TrafficArchitecturePage;
