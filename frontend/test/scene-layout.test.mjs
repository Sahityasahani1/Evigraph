import assert from 'node:assert/strict';
import test from 'node:test';
import { mockIncident } from '../src/api/mock.js';
import { fitDistance, GRAPH_LABEL_BOUNDS, layoutIncident } from '../src/scene/layout.js';

test('prepared INC-0009 hosts and labels fit inside their calculated network zones', () => {
  const incident = mockIncident('INC-0009');
  const layout = layoutIncident(incident.hosts);

  for (const zone of layout.zones) {
    const hosts = incident.hosts.filter(host => host.zone === zone.name || (zone.name === 'INTERNAL' && !['EXTERNAL', 'DMZ'].includes(host.zone)));
    for (const host of hosts) {
      const [x, y, z] = layout.positions[host.id];
      assert.ok(x - GRAPH_LABEL_BOUNDS.halfWidth >= zone.x - zone.width / 2, `${host.id} label exceeds ${zone.name} left edge`);
      assert.ok(x + GRAPH_LABEL_BOUNDS.halfWidth <= zone.x + zone.width / 2, `${host.id} label exceeds ${zone.name} right edge`);
      assert.ok(y - 1.1 >= -zone.height / 2 && y + 2.2 + GRAPH_LABEL_BOUNDS.halfHeight <= zone.height / 2, `${host.id} node or label exceeds ${zone.name} vertical bounds`);
      assert.ok(z - 1.1 >= -zone.depth / 2 && z + 1.1 <= zone.depth / 2, `${host.id} node exceeds ${zone.name} depth`);
    }
  }

  assert.equal(layout.zones.length, 3);
  assert.deepEqual(layout.zones.map(zone => zone.name), ['EXTERNAL', 'DMZ', 'INTERNAL']);
  assert.ok(layout.zones[0].x < layout.zones[1].x && layout.zones[1].x < layout.zones[2].x);
});

test('fit distance frames all calculated zone bounds for portrait and landscape viewports', () => {
  const layout = layoutIncident(mockIncident('INC-0009').hosts);
  for (const aspect of [0.75, 16 / 9, 2.4]) {
    const distance = fitDistance(layout.bounds, 50, aspect);
    const halfExtents = layout.bounds.max.map((value, i) => (value - layout.bounds.min[i]) / 2);
    const radius = Math.hypot(...halfExtents);
    const halfVertical = 50 * Math.PI / 360;
    const halfHorizontal = Math.atan(Math.tan(halfVertical) * aspect);
    const limitingHalfFov = Math.min(halfVertical, halfHorizontal);
    assert.ok(distance * Math.sin(limitingHalfFov) >= radius * 1.14);
    assert.ok(layout.bounds.max[1] >= zoneLabelTop(layout.zones));
  }
});

function zoneLabelTop(zones) {
  return Math.max(...zones.map(zone => zone.height / 2 + 1 + GRAPH_LABEL_BOUNDS.halfHeight));
}
