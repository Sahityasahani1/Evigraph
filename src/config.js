export const USE_MOCK = import.meta.env.VITE_USE_MOCK !== 'false';
export const API_BASE = import.meta.env.VITE_API_BASE || '/api';

// Keyed by the tactic name the backend sends in stage.tactic (TRD 3.5 / PRD FR-5.2).
export const TACTIC_COLORS = {
  'Reconnaissance': 0x4cc9f0,
  'Credential Access': 0xf9c74f,
  'Initial Access': 0xf9c74f,
  'Lateral Movement': 0xf8961e,
  'Command and Control': 0xb388ff,
  'Exfiltration': 0xff4d6d,
};
export const colorOf = tactic => TACTIC_COLORS[tactic] ?? 0x9fb4e6;
export const css = n => '#' + n.toString(16).padStart(6, '0');
