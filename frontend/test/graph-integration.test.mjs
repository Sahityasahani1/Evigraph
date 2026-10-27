import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mockIncident } from '../src/api/mock.js';
import { AttackGraph } from '../src/scene/AttackGraph.js';
import { NetworkScene } from '../src/scene/NetworkScene.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

test('frontend/index.html contains 2D/3D toggle button in graph controls', () => {
  const html = readFileSync(join(__dirname, '../index.html'), 'utf-8');
  assert.ok(html.includes('id="graphModeToggle"'), 'graphModeToggle button exists');
  assert.ok(html.includes('data-graph-action="toggle-mode"'), 'data-graph-action="toggle-mode" attribute is present');
  const controlsStart = html.indexOf('class="graph-controls"');
  const controlsEnd = html.indexOf('</div>', controlsStart);
  const controlsHtml = html.slice(controlsStart, controlsEnd);
  assert.ok(controlsHtml.includes('id="graphModeToggle"'), 'toggle button is inside graph-controls group');
});

test('frontend/src/styles.css contains rules for network-scene-canvas and graphModeToggle', () => {
  const css = readFileSync(join(__dirname, '../src/styles.css'), 'utf-8');
  assert.ok(css.includes('.network-scene-canvas'), '.network-scene-canvas is defined');
  assert.ok(css.includes('[data-graph-action="toggle-mode"]'), 'toggle-mode button styling is defined');
});

function createContainerMock(width = 1000, height = 450) {
  let innerHtml = '';
  const listeners = {};
  const panelListeners = {};
  const container = {
    clientWidth: width,
    clientHeight: height,
    get innerHTML() { return innerHtml; },
    set innerHTML(val) { innerHtml = val; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    appendChild() {},
    addEventListener(name, fn) { listeners[name] = fn; },
    removeEventListener(name) { delete listeners[name]; },
    getBoundingClientRect() {
      return { left: 0, top: 0, right: width, bottom: height, width, height };
    },
    closest(selector) {
      if (selector !== '.graph-panel') return null;
      return {
        addEventListener(name, fn) { panelListeners[name] = fn; },
        removeEventListener(name) { delete panelListeners[name]; },
      };
    },
  };
  return { container, listeners, panelListeners };
}

test('Both 2D AttackGraph and 3D NetworkScene adhere to the unified graph contract', () => {
  const incident = mockIncident('INC-0009');
  let selected2D = null, selected3D = null;

  const { container: container2D } = createContainerMock();
  const graph2D = new AttackGraph(container2D, s => { selected2D = s; });

  const { container: container3D } = createContainerMock();
  const graph3D = new NetworkScene(container3D, s => { selected3D = s; });

  for (const graph of [graph2D, graph3D]) {
    assert.equal(typeof graph.setIncident, 'function');
    assert.equal(typeof graph.setSelection, 'function');
    assert.equal(typeof graph.setReplay, 'function');
    assert.equal(typeof graph.zoom, 'function');
    assert.equal(typeof graph.fit, 'function');
    assert.equal(typeof graph.reset, 'function');

    // Feed real incident
    graph.setIncident(incident);

    // Test selection
    const testHost = incident.hosts[0].id;
    const testStage = incident.stages[0].stage_id;
    graph.setSelection({ host: testHost, stage: testStage });

    // Test replay
    graph.setReplay(testStage);
    graph.setReplay(null);

    // Test zoom/fit/reset controls
    graph.zoom(1.2);
    graph.zoom(0.84);
    graph.fit();
    graph.reset();

    if (typeof graph.dispose === 'function') {
      graph.dispose();
    }
  }
});

test('Graph mode switching cleans up previous instance and handles WebGL failure with 2D fallback', () => {
  const { container } = createContainerMock();
  const incident = mockIncident('INC-0009');
  let selectionCaptured = null;
  const onSelect = sel => { selectionCaptured = sel; };

  // Mode switching state simulation matching main.js initGraph logic
  let activeGraph = null;
  let activeMode = 'none';

  function switchGraph(mode, simulateWebGLError = false) {
    if (activeGraph) {
      if (typeof activeGraph.dispose === 'function') activeGraph.dispose();
      activeGraph = null;
      container.innerHTML = '';
    }

    if (mode === '3d') {
      try {
        if (simulateWebGLError) {
          throw new Error('Simulated WebGL Context Lost');
        }
        activeGraph = new NetworkScene(container, onSelect);
        activeMode = '3d';
      } catch {
        container.innerHTML = '';
        activeGraph = new AttackGraph(container, onSelect);
        activeMode = '2d';
      }
    } else {
      activeGraph = new AttackGraph(container, onSelect);
      activeMode = '2d';
    }

    activeGraph.setIncident(incident);
  }

  // 1. Switch to 3D
  switchGraph('3d', false);
  assert.equal(activeMode, '3d');
  assert.ok(activeGraph instanceof NetworkScene);
  assert.equal(activeGraph.stages.length, incident.stages.length);

  // 2. Switch to 2D cleanly
  switchGraph('2d', false);
  assert.equal(activeMode, '2d');
  assert.ok(activeGraph instanceof AttackGraph);

  // 3. Switch to 3D with simulated WebGL failure -> falls back to 2D
  switchGraph('3d', true);
  assert.equal(activeMode, '2d', 'Should safely fallback to 2d when WebGL fails');
  assert.ok(activeGraph instanceof AttackGraph);

  if (activeGraph?.dispose) activeGraph.dispose();
});

