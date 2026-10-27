import assert from 'node:assert/strict';
import test from 'node:test';
import { mockIncident } from '../src/api/mock.js';
import { NetworkScene } from '../src/scene/NetworkScene.js';

function createContainerMock(width = 1000, height = 450) {
  const listeners = {};
  const panelListeners = {};
  const container = {
    clientWidth: width,
    clientHeight: height,
    querySelector() { return null; },
    appendChild() {},
    addEventListener(name, fn) { listeners[name] = fn; },
    removeEventListener(name) { delete listeners[name]; },
    getBoundingClientRect() {
      return { left: 100, top: 50, right: 100 + width, bottom: 50 + height, width, height };
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

test('NetworkScene initializes with container dimensions and mounts cleanly', () => {
  const { container } = createContainerMock(960, 420);
  const scene = new NetworkScene(container);
  const size = scene._getSize();
  assert.equal(size.width, 960);
  assert.equal(size.height, 420);
  assert.equal(scene.camera.aspect, 960 / 420);
  scene.dispose();
});

test('NetworkScene.setIncident creates 3D nodes, edges, and fits camera using real incident data', () => {
  const { container } = createContainerMock();
  const scene = new NetworkScene(container);
  const incident = mockIncident('INC-0009');
  scene.setIncident(incident);

  assert.equal(Object.keys(scene.nodes).length, incident.hosts.length);
  assert.equal(scene.stages.length, incident.stages.length);
  assert.ok(scene.fitState);
  assert.ok(scene.cam.rad > 15);
  assert.ok(scene.pickables.length >= incident.hosts.length + incident.stages.length);

  // Validate node coordinates fit inside their respective zone positions
  for (const host of incident.hosts) {
    const nodeMesh = scene.nodes[host.id];
    assert.ok(nodeMesh, `Node mesh for host ${host.id} exists`);
    assert.equal(nodeMesh.userData.host, host.id);
  }

  // Validate edges
  for (const stage of incident.stages) {
    const edgeObj = scene.edges[stage.stage_id];
    assert.ok(edgeObj, `Edge for stage ${stage.stage_id} exists`);
    assert.equal(edgeObj.stage.stage_id, stage.stage_id);
  }

  scene.dispose();
});

test('NetworkScene mouse picking calculates NDC coordinates using container offset', () => {
  const { container } = createContainerMock(800, 400);
  // container rect: left: 100, top: 50, width: 800, height: 400
  const scene = new NetworkScene(container);

  // Center of container: x = 100 + 400 = 500, y = 50 + 200 = 250 -> NDC (0, 0)
  const centerPos = scene._getPointerPos({ clientX: 500, clientY: 250 });
  assert.ok(Math.abs(centerPos.x) < 1e-4, 'Center X should map to 0');
  assert.ok(Math.abs(centerPos.y) < 1e-4, 'Center Y should map to 0');

  // Top-left corner: x = 100, y = 50 -> NDC (-1, 1)
  const topLeftPos = scene._getPointerPos({ clientX: 100, clientY: 50 });
  assert.ok(Math.abs(topLeftPos.x - (-1)) < 1e-4, 'Top-left X should map to -1');
  assert.ok(Math.abs(topLeftPos.y - 1) < 1e-4, 'Top-left Y should map to 1');

  // Bottom-right corner: x = 900, y = 450 -> NDC (1, -1)
  const bottomRightPos = scene._getPointerPos({ clientX: 900, clientY: 450 });
  assert.ok(Math.abs(bottomRightPos.x - 1) < 1e-4, 'Bottom-right X should map to 1');
  assert.ok(Math.abs(bottomRightPos.y - (-1)) < 1e-4, 'Bottom-right Y should map to -1');

  scene.dispose();
});

test('NetworkScene selection and replay interface methods update visual state correctly', () => {
  const { container } = createContainerMock();
  const scene = new NetworkScene(container);
  const incident = mockIncident('INC-0009');
  scene.setIncident(incident);

  const targetHost = incident.hosts[0].id;
  const targetStage = incident.stages[0].stage_id;

  // setSelection
  scene.setSelection({ host: targetHost, stage: targetStage });
  assert.equal(scene.sel.host, targetHost);
  assert.equal(scene.nodes[targetHost].scale.x, 1.4);
  assert.equal(scene.edges[targetStage].line.material.opacity, 1.0);

  // setReplay
  scene.setReplay(targetStage);
  assert.equal(scene.replayStageId, targetStage);
  assert.equal(scene.edges[targetStage].line.material.opacity, 1.0);
  // Inactive stage edge opacity dims in replay
  if (incident.stages.length > 1) {
    const otherStage = incident.stages[1].stage_id;
    assert.equal(scene.edges[otherStage].line.material.opacity, 0.15);
  }

  // Clear replay
  scene.setReplay(null);
  assert.equal(scene.replayStageId, null);

  scene.dispose();
});

test('NetworkScene zoom, fit, and reset methods operate predictably', () => {
  const { container } = createContainerMock();
  const scene = new NetworkScene(container);
  const incident = mockIncident('INC-0009');
  scene.setIncident(incident);

  const initialRad = scene.cam.rad;
  scene.zoom(1.2); // Zoom in: distance decreases
  assert.ok(scene.cam.rad < initialRad);

  scene.zoom(0.84); // Zoom out: distance increases
  assert.ok(scene.cam.rad > initialRad * 0.95);

  scene.fit();
  assert.ok(Math.abs(scene.cam.rad - scene.fitState.rad) < 1e-3);

  scene.cam.th = 2.5;
  scene.cam.ph = 0.5;
  scene.reset();
  assert.equal(scene.cam.th, 0.7);
  assert.equal(scene.cam.ph, 1.2);

  scene.dispose();
});

test('NetworkScene rotates camera on empty space drag and selects without drag on node hit', () => {
  let selected = null;
  const { container } = createContainerMock();
  const scene = new NetworkScene(container, sel => { selected = sel; });
  const incident = mockIncident('INC-0009');
  scene.setIncident(incident);

  const initialTh = scene.cam.th;
  const initialPh = scene.cam.ph;

  // 1. Drag on empty space (raycaster finds nothing)
  scene._inputHandlers.onPointerDown({ clientX: 200, clientY: 200, button: 0 });
  assert.equal(scene.dragging, true, 'Dragging should start on empty space');
  assert.equal(scene.pendingPick, null, 'No object should be picked');

  scene._inputHandlers.onPointerMove({ clientX: 250, clientY: 230 });
  assert.notEqual(scene.cam.th, initialTh, 'Camera theta should rotate on horizontal drag');
  assert.notEqual(scene.cam.ph, initialPh, 'Camera phi should rotate on vertical drag');

  scene._inputHandlers.onPointerUp({});
  assert.equal(scene.dragging, false, 'Dragging should end on pointer up');

  // 2. Click on a host node (raycaster finds a pickable node)
  const targetHostId = incident.hosts[0].id;
  const targetNode = scene.nodes[targetHostId];

  // Mock raycaster to return the target host
  const origIntersect = scene.raycaster.intersectObjects;
  scene.raycaster.intersectObjects = () => [{ object: targetNode }];

  scene._inputHandlers.onPointerDown({ clientX: 300, clientY: 300, button: 0 });
  assert.equal(scene.dragging, false, 'Should NOT start a drag when clicking a node');
  assert.deepEqual(scene.pendingPick, { host: targetHostId, base: targetNode.userData.base });

  scene._inputHandlers.onPointerUp({});
  assert.deepEqual(selected, { host: targetHostId }, 'Selected callback should receive target host');
  assert.equal(scene.pendingPick, null, 'Pending pick should reset after selection');

  // Restore raycaster
  scene.raycaster.intersectObjects = origIntersect;

  // 3. Mouse wheel zoom
  const radBeforeWheel = scene.cam.rad;
  scene._inputHandlers.onWheel({ deltaY: 50, preventDefault() {} });
  assert.ok(scene.cam.rad > radBeforeWheel, 'Wheel down should zoom out (increase camera radius)');

  scene.dispose();
});

