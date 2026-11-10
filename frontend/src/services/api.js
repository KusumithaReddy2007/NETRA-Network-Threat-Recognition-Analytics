import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
  headers: {
    "Content-Type": "application/json",
  },
});


/* =====================================
   SYSTEM HEALTH
===================================== */

export async function healthCheck() {
  const response = await api.get("/health");
  return response.data;
}


/* =====================================
   ANALYTICS
===================================== */

export async function getAnalytics(maxFlows = 100) {
  const response = await api.get(
    "/analytics/summary",
    {
      params: {
        max_flows: maxFlows,
      },
    }
  );

  return response.data;
}


/* =====================================
   FLOW REPLAY
===================================== */

export async function replayTraffic(
  maxFlows = 100,
  delay = 0
) {
  const response = await api.post(
    "/stream/replay",
    null,
    {
      params: {
        max_flows: maxFlows,
        delay,
      },
    }
  );

  return response.data;
}


/* =====================================
   FLOW THREAT ANALYSIS
===================================== */

export async function analyzeFlow(flowData) {
  const response = await api.post(
    "/threat/analyze",
    flowData
  );

  return response.data;
}


/* =====================================
   DNS REPLAY
===================================== */

export async function replayDns(
  maxRecords = 100
) {
  const response = await api.post(
    "/stream/dns-replay",
    null,
    {
      params: {
        max_records: maxRecords,
      },
    }
  );

  return response.data;
}


/* =====================================
   TLS REPLAY
===================================== */

export async function replayTls(
  maxRecords = 100
) {
  const response = await api.post(
    "/stream/tls-replay",
    null,
    {
      params: {
        max_records: maxRecords,
      },
    }
  );

  return response.data;
}


/* =====================================
   QUIC REPLAY
===================================== */

export async function replayQuic(
  maxRecords = 100
) {
  const response = await api.post(
    "/stream/quic-replay",
    null,
    {
      params: {
        max_records: maxRecords,
      },
    }
  );

  return response.data;
}


/* =====================================
   LIVE NETWORK MONITORING
===================================== */

export async function getLiveStatus() {
  const response = await api.get(
    "/live/status"
  );

  return response.data;
}


export async function pollLiveNetwork(
  maxRecords = 100
) {
  const response = await api.post(
    "/live/poll",
    null,
    {
      params: {
        max_records: maxRecords,
      },
    }
  );

  return response.data;
}


export async function getLiveEvents(
  limit = 50
) {
  const response = await api.get(
    "/live/events",
    {
      params: {
        limit,
      },
    }
  );

  return response.data;
}


export async function getLiveAlerts(
  limit = 50
) {
  const response = await api.get(
    "/live/alerts",
    {
      params: {
        limit,
      },
    }
  );

  return response.data;
}


export async function resetLiveMonitor() {
  const response = await api.post(
    "/live/reset"
  );

  return response.data;
}


export default api;
