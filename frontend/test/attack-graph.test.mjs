import assert from 'node:assert/strict';
import test from 'node:test';
import { mockIncident } from '../src/api/mock.js';
import { AttackGraph } from '../src/scene/AttackGraph.js';

function createGraph(incident = mockIncident('INC-0009')) {
  const listeners = {};
  const panelListeners = {};
  const viewport = { transform: '', setAttribute(name, value) { if (name === 'transform') this.transform = value; } };
  const container = {
    innerHTML: '',
    addEventListener(name, handler) { listeners[name] = handler; },
    closest(selector) {
      if (selector !== '.graph-panel') return null;
      return { addEventListener(name, handler) { panelListeners[name] = handler; } };
    },
    querySelector(selector) { return selector === '.graph-viewport' ? viewport : null; },
    querySelectorAll() { return []; },
    getBoundingClientRect() { return { width: 1000, height: 450 }; },
  };
  const graph = new AttackGraph(container, () => {});
  graph.setIncident(incident);
  return { graph, container, listeners, panelListeners, viewport };
}

test('INC-0009 zone bands, edges, and hosts share the transformed SVG viewport', () => {
  const { graph, container, viewport } = createGraph();
  const markup = container.innerHTML;
  const groupStart = markup.indexOf('<g class="graph-viewport">');
  const firstZone = markup.indexOf('<g class="zone-band">');
  const firstEdge = markup.indexOf('<g class="graph-alert-edge');
  const firstNode = markup.indexOf('<g class="graph-node');
  const groupEnd = markup.indexOf('</g>\n    </svg>', groupStart);

  assert.ok(groupStart >= 0 && groupStart < firstZone);
  assert.ok(firstZone < firstEdge && firstEdge < firstNode && firstNode < groupEnd);
  assert.equal((markup.match(/class="zone-band"/g) || []).length, 3);

  const positions = graph._layout(graph.data.hosts);
  const zoneBounds = { EXTERNAL: [24, 276], DMZ: [362, 638], INTERNAL: [724, 976] };
  for (const host of graph.data.hosts) {
    const [left, right] = zoneBounds[host.zone];
    const point = positions[host.id];
    assert.ok(point.x - 25 >= left && point.x + 25 <= right, `${host.id} node is inside its ${host.zone} zone`);
    assert.ok(point.y - 25 >= 22 && point.y + 57 <= 416, `${host.id} node and labels are inside the zone bounds`);
  }

  graph.zoom(1.2);
  assert.match(viewport.transform, /translate\([^)]*\) scale\(/);
  assert.equal(markup.slice(groupStart, groupEnd).includes('class="zone-band"'), true);
  assert.equal(markup.slice(groupStart, groupEnd).includes('class="graph-node"'), true);
});

test('Fit includes the complete zone frame and zoom stays anchored at the canvas center', () => {
  const { graph } = createGraph();
  graph.fit();
  const fitTransform = { ...graph.transform };
  const worldCenterBefore = {
    x: (500 - fitTransform.x) / fitTransform.scale,
    y: (225 - fitTransform.y) / fitTransform.scale,
  };
  const bounds = [24, 22, 976, 416];
  const transformed = {
    left: fitTransform.x + bounds[0] * fitTransform.scale,
    top: fitTransform.y + bounds[1] * fitTransform.scale,
    right: fitTransform.x + bounds[2] * fitTransform.scale,
    bottom: fitTransform.y + bounds[3] * fitTransform.scale,
  };
  assert.ok(transformed.left >= 0 && transformed.right <= 1000);
  assert.ok(transformed.top >= 0 && transformed.bottom <= 450);

  graph.zoom(1.2);
  const worldCenterAfter = {
    x: (500 - graph.transform.x) / graph.transform.scale,
    y: (225 - graph.transform.y) / graph.transform.scale,
  };
  assert.ok(Math.abs(worldCenterAfter.x - worldCenterBefore.x) < 1e-9);
  assert.ok(Math.abs(worldCenterAfter.y - worldCenterBefore.y) < 1e-9);
});

test('zoom, Fit, and Reset controls all update the shared graph transform', () => {
  const { graph, panelListeners, viewport, listeners } = createGraph();
  const clickAction = action => panelListeners.click({ target: { closest: () => ({ dataset: { graphAction: action } }) } });

  clickAction('zoom-in');
  assert.ok(graph.transform.scale > 1);
  assert.match(viewport.transform, /scale\(/);
  clickAction('zoom-out');
  assert.ok(graph.transform.scale < 1.01);
  clickAction('fit');
  assert.ok(graph.transform.scale < 1);
  clickAction('zoom-in');
  clickAction('reset');
  assert.deepEqual(graph.transform, { x: 0, y: 0, scale: 1 });

  let prevented = false;
  listeners.wheel({ deltaY: -1, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.ok(graph.transform.scale > 1);
});
