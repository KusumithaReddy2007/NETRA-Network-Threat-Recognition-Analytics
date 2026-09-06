import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 120000,
  headers: {
    "Content-Type": "application/json",
  },
});

export async function healthCheck() {
  const response = await api.get("/health");
  return response.data;
}

export async function getAnalytics(maxFlows = 100) {
  const response = await api.get("/analytics/summary", {
    params: {
      max_flows: maxFlows,
    },
  });

  return response.data;
}

export async function replayTraffic(maxFlows = 100, delay = 0) {
  const response = await api.post("/stream/replay", null, {
    params: {
      max_flows: maxFlows,
      delay,
    },
  });

  return response.data;
}

export async function analyzeFlow(flowData) {
  const response = await api.post("/threat/analyze", flowData);
  return response.data;
}

export default api;

export async function replayDns(maxRecords = 100) {
  const response = await api.post("/stream/dns-replay", null, {
    params: {
      max_records: maxRecords,
    },
  });

  return response.data;
}

export async function replayTls(maxRecords = 100) {
  const response = await api.post("/stream/tls-replay", null, {
    params: {
      max_records: maxRecords,
    },
  });

  return response.data;
}

export async function replayQuic(maxRecords = 100) {
  const response = await api.post("/stream/quic-replay", null, {
    params: {
      max_records: maxRecords,
    },
  });

  return response.data;
}
