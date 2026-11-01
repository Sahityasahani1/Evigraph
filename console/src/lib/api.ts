const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api";

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    throw new Error(`API ${res.status} ${res.statusText} at ${path}`);
  }
  return res.json();
}

export async function getIncidents() {
  return fetchJson<any[]>("/incidents");
}

export async function getIncident(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}`);
}

export async function getCourtroom(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/courtroom`);
}

export async function getContainment(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/containment`);
}

export async function getPrivacyProof(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/privacy-proof`);
}

export async function getSimulation(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/simulation`);
}

export async function getCitations(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/citations`);
}

export async function getReport(id: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(id)}/report`, {
    method: "POST",
  });
}

export async function getSystemOverview() {
  return fetchJson<any>("/system/overview");
}

export async function getSystemMerkle() {
  return fetchJson<any>("/system/merkle");
}

export async function getSystemManifest() {
  return fetchJson<any>("/system/manifest");
}

export async function postContainmentAction(
  incidentId: string,
  ruleId: string,
  action: "APPROVE" | "DEPLOY" | "REVIEW",
  target: string
) {
  return fetchJson<any>("/containment/apply", {
    method: "POST",
    body: JSON.stringify({ incident_id: incidentId, rule_id: ruleId, action, target }),
  });
}

export async function queryCopilot(incidentId: string, query: string, tab: string) {
  return fetchJson<any>(`/incidents/${encodeURIComponent(incidentId)}/copilot`, {
    method: "POST",
    body: JSON.stringify({ query, tab }),
  });
}
