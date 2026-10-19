// Single data-access layer. UI code never calls fetch() directly.
// Shapes are defined in docs/API_CONTRACT.md. Mock and real backend must return identical shapes.
import { USE_MOCK, API_BASE } from '../config.js';

async function http(path, opts = {}) {
  const token = localStorage.getItem('evigraph_token');
  const res = await fetch(API_BASE + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${path}`);
  return res.json();
}

// Convert ISO timestamps to minute offsets from incident start (what the 3D timeline needs).
function normalize(inc) {
  const t0 = Date.parse(inc.start);
  const off = iso => (Date.parse(iso) - t0) / 60000;
  return {
    ...inc,
    durationMin: Math.max(1, off(inc.end)),
    stages: [...inc.stages].sort((a, b) => a.order - b.order).map(s => ({ ...s, t0: off(s.start), t1: off(s.end) })),
  };
}

export async function listIncidents() {            // GET /incidents
  if (USE_MOCK) return (await import('./mock.js')).mockList();
  return http('/incidents');
}
export async function getIncident(id) {            // GET /incidents/{id}
  const raw = USE_MOCK ? (await import('./mock.js')).mockIncident(id) : await http(`/incidents/${encodeURIComponent(id)}`);
  return normalize(raw);
}
export async function getReport(id) {              // POST /incidents/{id}/report
  if (USE_MOCK) return (await import('./mock.js')).mockReport(id);
  return http(`/incidents/${encodeURIComponent(id)}/report`, { method: 'POST' });
}
