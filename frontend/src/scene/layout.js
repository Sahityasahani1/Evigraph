export const ZONE_ORDER = ['EXTERNAL', 'DMZ', 'INTERNAL'];

const NODE_RADIUS = 1.1;
const LABEL_HALF_WIDTH = 3.1;
const LABEL_HALF_HEIGHT = 0.7;
const LABEL_Y = 2.2;
const X_SPACING = 7.5;
const Z_SPACING = 6;
const ZONE_GAP = 4;
const MIN_ZONE_WIDTH = 10;
const MIN_ZONE_DEPTH = 10;
const ZONE_HEIGHT = 8;

/** Compute host and zone bounds together so visual regions always contain their graph elements. */
export function layoutIncident(hosts = []) {
  const byZone = new Map(ZONE_ORDER.map(zone => [zone, []]));
  for (const host of hosts) (byZone.get(host.zone) ?? byZone.get('INTERNAL')).push(host);

  const zones = [];
  const positions = {};
  let cursorX = 0;

  for (const name of ZONE_ORDER) {
    const list = byZone.get(name);
    const columns = Math.max(1, Math.ceil(Math.sqrt(list.length)));
    const rows = Math.max(1, Math.ceil(list.length / columns));
    const width = Math.max(MIN_ZONE_WIDTH, (columns - 1) * X_SPACING + 2 * (LABEL_HALF_WIDTH + 1));
    const depth = Math.max(MIN_ZONE_DEPTH, (rows - 1) * Z_SPACING + 2 * (NODE_RADIUS + 1));
    const centerX = cursorX + width / 2;
    zones.push({ name, x: centerX, width, height: ZONE_HEIGHT, depth });

    list.forEach((host, i) => {
      const col = i % columns;
      const row = Math.floor(i / columns);
      positions[host.id] = [
        centerX + (col - (columns - 1) / 2) * X_SPACING,
        0,
        (row - (rows - 1) / 2) * Z_SPACING,
      ];
    });
    cursorX += width + ZONE_GAP;
  }

  const minX = zones[0].x - zones[0].width / 2;
  const maxX = zones.at(-1).x + zones.at(-1).width / 2;
  const maxDepth = Math.max(...zones.map(zone => zone.depth));
  const bounds = {
    min: [minX, -ZONE_HEIGHT / 2, -maxDepth / 2],
    max: [maxX, ZONE_HEIGHT / 2 + 1 + LABEL_HALF_HEIGHT, maxDepth / 2],
  };
  const center = [
    (bounds.min[0] + bounds.max[0]) / 2,
    (bounds.min[1] + bounds.max[1]) / 2,
    (bounds.min[2] + bounds.max[2]) / 2,
  ];
  return {
    positions,
    zones,
    bounds,
    center,
  };
}

/** Return a conservative camera distance that fits the bounds with a small margin. */
export function fitDistance(bounds, verticalFovDegrees = 50, aspect = 1, margin = 1.15) {
  const center = bounds.min.map((value, i) => (value + bounds.max[i]) / 2);
  const radius = Math.hypot(...bounds.max.map((value, i) => Math.max(value - center[i], center[i] - bounds.min[i])));
  const verticalHalfFov = verticalFovDegrees * Math.PI / 360;
  const horizontalHalfFov = Math.atan(Math.tan(verticalHalfFov) * Math.max(aspect, 0.01));
  return Math.max(12, radius * margin / Math.sin(Math.min(verticalHalfFov, horizontalHalfFov)));
}

export const GRAPH_LABEL_BOUNDS = { halfWidth: LABEL_HALF_WIDTH, y: LABEL_Y, halfHeight: LABEL_HALF_HEIGHT };
