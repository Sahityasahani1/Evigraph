// Icons are path strings so the same data draws inline SVG (HTML) and Path2D (3D labels).
const C = (x, y, r) => `M${x - r} ${y}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const R = (x, y, w, h) => `M${x} ${y}h${w}v${h}h${-w}z`;
export const ICONS = {
  hex: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', C(12, 12, 2.5)],
  scout: [C(12, 12, 9), C(12, 12, 4), 'M12 12L19 5'],
  key: [C(8, 15, 4), 'M11 12l9-9M16 7l3 3'],
  spread: [C(5, 12, 2.5), C(19, 5, 2.5), C(19, 19, 2.5), 'M7.5 11l9-5M7.5 13l9 5'],
  phone: ['M12 12v9M8 21h8', C(12, 10, 2), 'M7.5 5.5a6.5 6.5 0 0 0 0 9M16.5 5.5a6.5 6.5 0 0 1 0 9'],
  steal: ['M12 16V4M7 9l5-5 5 5', 'M4 16v4h16v-4'],
  skull: ['M12 3a8 8 0 0 0-5 14v3h10v-3a8 8 0 0 0-5-14z', C(9, 11, 1.5), C(15, 11, 1.5), 'M10 20v-2M14 20v-2'],
  server: [R(3, 4, 18, 6), R(3, 14, 18, 6), C(7, 7, 0.7), C(7, 17, 0.7)],
  db: ['M5 6a7 3 0 1 0 14 0a7 3 0 1 0-14 0', 'M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6', 'M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3'],
  laptop: [R(5, 5, 14, 10), 'M3 19h18'],
  folder: ['M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'],
  globe: [C(12, 12, 9), 'M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18'],
  home: ['M4 11l8-7 8 7v9H4z', 'M10 20v-5h4v5'],
  report: ['M6 3h9l4 4v14H6z', 'M9 12h7M9 16h7'],
  lock: [R(5, 11, 14, 9), 'M8 11V8a4 4 0 0 1 8 0v3'],
  scale: ['M12 4v16M6 20h12M5 7h14', 'M5 7l-3 7a3 3 0 0 0 6 0z', 'M19 7l-3 7a3 3 0 0 0 6 0z'],
  shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'],
  help: [C(12, 12, 9), 'M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7', 'M12 17v.1'],
  sun: [C(12, 12, 4), 'M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2'],
  moon: ['M20 14A8 8 0 0 1 10 4a8 8 0 1 0 10 10z'],
  eye: ['M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z', C(12, 12, 3)],
  bulb: ['M9 18h6M10 21h4M12 3a6 6 0 0 0-4 10c1 1 1 2 1 3h6c0-1 0-2 1-3a6 6 0 0 0-4-10z'],
  play: ['M7 5l12 7-12 7z'],
  pause: ['M8 5v14M16 5v14'],
  prev: ['M6 5v14M18 5L9 12l9 7z'],
  next: ['M18 5v14M6 5l9 7-9 7z'],
  copy: [R(9, 9, 11, 11), 'M5 15V5h10'],
  check: ['M5 12l5 5 9-10'],
};
export const icon = (name, size = 18) =>
  `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${(ICONS[name] || ICONS.help).map(d => `<path d="${d}"/>`).join('')}</svg>`;
export function roleIcon(h = {}) {
  const r = (h.role || '').toLowerCase();
  if (r.includes('attacker')) return 'skull';
  if (r.includes('database')) return 'db';
  if (r.includes('file')) return 'folder';
  if (r.includes('workstation')) return 'laptop';
  if (h.zone === 'EXTERNAL') return 'globe';
  return 'server';
}
