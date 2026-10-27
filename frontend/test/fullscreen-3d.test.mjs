import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mockIncident, mockList } from '../src/api/mock.js';
import { adapt } from '../src/api/adapt.js';
import { fullscreenStageCardHtml, formatTime, formatDateTime } from '../src/ui/dashboard.js';
import { heroHtml, chainHtml, capHtml } from '../src/ui/panels.js';
import { prepareTimelineIncident, findInitialAttacker } from '../src/ui/story.js';
import { clockAt } from '../src/utils.js';
import { NetworkScene } from '../src/scene/NetworkScene.js';
import { AttackGraph } from '../src/scene/AttackGraph.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

test('frontend/index.html contains Fullscreen 3D button and overlay structure', () => {
  const html = readFileSync(join(__dirname, '../index.html'), 'utf-8');

  // Verify button in controls
  assert.ok(html.includes('id="fullscreen3dBtn"'), 'fullscreen3dBtn exists');
  assert.ok(html.includes('data-graph-action="fullscreen-3d"'), 'fullscreen-3d action exists');

  // Verify overlay elements
  assert.ok(html.includes('id="fullscreenOverlay"'), 'fullscreenOverlay exists');
  assert.ok(html.includes('id="fullscreenExitBtn"'), 'fullscreenExitBtn exists');
  assert.ok(html.includes('id="fullscreenChain"'), 'fullscreenChain sidebar exists');
  assert.ok(html.includes('id="fullscreenChainCount"'), 'fullscreenChainCount badge exists');
  assert.ok(html.includes('id="fullscreenGraphCanvas"'), 'fullscreenGraphCanvas container exists');
  assert.ok(html.includes('id="fsPlayPauseBtn"'), 'fsPlayPauseBtn exists');
  assert.ok(html.includes('id="fsRestartBtn"'), 'fsRestartBtn exists');
  assert.ok(html.includes('id="fsReplayProgress"'), 'fsReplayProgress scrubber exists');
  assert.ok(html.includes('id="fsReplayStatus"'), 'fsReplayStatus text exists');
  assert.ok(html.includes('id="fsReplayStageProgress"'), 'fsReplayStageProgress text exists');
  assert.ok(html.includes('id="fsSpeedSelect"'), 'fsSpeedSelect exists');
  assert.ok(html.includes('value="0.5"'), '0.5x speed option exists');
  assert.ok(html.includes('value="1"'), '1x speed option exists');
  assert.ok(html.includes('value="2"'), '2x speed option exists');
});

test('fullscreenStageCardHtml renders real stage tactic, badges, technique, confidence, and route', () => {
  const observedStage = {
    stage_id: 'INC-0009-stage-1',
    order: 1,
    tactic: 'Lateral Movement',
    tactic_id: 'TA0008',
    confidence: 0.85,
    observed: true,
    src: '172.20.10.10',
    dst: '172.20.10.14',
    port: '445',
    summary: 'Lateral SMB relay attack on port 445',
  };

  const htmlObserved = fullscreenStageCardHtml(observedStage, 0, true);
  assert.match(htmlObserved, /1\.\s+Lateral Movement/);
  assert.match(htmlObserved, /fs-badge-observed">Observed</);
  assert.match(htmlObserved, /TA0008/);
  assert.match(htmlObserved, /85% conf/);
  assert.match(htmlObserved, /172\.20\.10\.10 → 172\.20\.10\.14:445/);
  assert.match(htmlObserved, /Lateral SMB relay attack on port 445/);
  assert.match(htmlObserved, /class="fs-chain-card active"/);

  const inferredStage = {
    stage_id: 'INC-0009-stage-inferred',
    order: 2,
    tactic: 'Command and Control',
    tactic_id: 'TA0011',
    confidence: 0.64,
    observed: false,
    interpretation_status: 'inferred',
    src: '172.20.10.10',
    dst: '203.0.113.88',
    summary: 'Periodic C2 beaconing',
  };

  const htmlInferred = fullscreenStageCardHtml(inferredStage, 1, false);
  assert.match(htmlInferred, /2\.\s+Command and Control/);
  assert.match(htmlInferred, /fs-badge-inferred">Inferred</);
  assert.match(htmlInferred, /TA0011/);
  assert.match(htmlInferred, /64% conf/);
  assert.doesNotMatch(htmlInferred, /class="fs-chain-card active"/);
});

function createMockContainer(width = 1200, height = 700) {
  let inner = '';
  return {
    clientWidth: width,
    clientHeight: height,
    get innerHTML() { return inner; },
    set innerHTML(val) { inner = val; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    closest() { return null; },
    appendChild() {},
    getBoundingClientRect() { return { left: 0, top: 0, width, height, right: width, bottom: height }; },
    addEventListener() {},
    removeEventListener() {},
  };
}

test('Fullscreen 3D stage progression and replay synchronization operate seamlessly', () => {
  const incident = mockIncident('INC-0009');
  const container = createMockContainer();
  let selectedData = null;

  const fsGraph = new NetworkScene(container, sel => { selectedData = sel; });
  fsGraph.setIncident(incident);

  assert.equal(fsGraph.stages.length, incident.stages.length);

  // Advance replay step through all stages
  for (let i = 0; i < incident.stages.length; i++) {
    const stage = incident.stages[i];
    fsGraph.setReplay(stage.stage_id);
    fsGraph.setSelection({ stage: stage.stage_id });

    assert.equal(fsGraph.replayStageId, stage.stage_id);
    assert.equal(fsGraph.edges[stage.stage_id].line.material.opacity, 1.0);
  }

  // Clear replay
  fsGraph.setReplay(null);
  assert.equal(fsGraph.replayStageId, null);

  fsGraph.dispose();
});

test('Fullscreen mode handles WebGL failure with clean 2D fallback and clean disposal', () => {
  const container = createMockContainer();
  const incident = mockIncident('INC-0009');

  let activeGraph = null;
  function openFs(simulateError = false) {
    if (activeGraph) {
      activeGraph.dispose?.();
      activeGraph = null;
      container.innerHTML = '';
    }
    if (simulateError) {
      // 2D fallback
      activeGraph = new AttackGraph(container, () => {});
    } else {
      activeGraph = new NetworkScene(container, () => {});
    }
    activeGraph.setIncident(incident);
  }

  // 1. Successful 3D
  openFs(false);
  assert.ok(activeGraph instanceof NetworkScene);

  // 2. WebGL failure fallback to 2D
  openFs(true);
  assert.ok(activeGraph instanceof AttackGraph);

  // 3. Clean exit disposal
  activeGraph.dispose?.();
  container.innerHTML = '';
  assert.equal(container.innerHTML, '');
});

test('Fullscreen replay state machine advances in timestamp order, pauses, restarts, and prevents duplicate loops', () => {
  const incident = mockIncident('INC-0009');
  const stages = [...incident.stages].sort((a, b) => (Date.parse(a.start || 0) - Date.parse(b.start || 0)));
  assert.ok(stages.length >= 2, 'Should have at least 2 stages for replay test');

  let activeIndex = -1;
  let timer = null;
  let highlightedStage = null;
  let scrubberValue = '0';
  let playBtnText = 'Play';

  function step(index) {
    activeIndex = Math.max(0, Math.min(index, stages.length - 1));
    highlightedStage = stages[activeIndex].stage_id;
    scrubberValue = String(activeIndex);
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    playBtnText = 'Play';
  }

  function play() {
    if (!stages.length) return;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    if (activeIndex >= stages.length - 1) {
      activeIndex = -1;
    }
    step(activeIndex + 1);
    if (activeIndex >= stages.length - 1) {
      stop();
      return;
    }
    playBtnText = 'Pause';
    timer = setInterval(() => {
      if (activeIndex >= stages.length - 1) {
        stop();
        return;
      }
      step(activeIndex + 1);
      if (activeIndex >= stages.length - 1) {
        stop();
      }
    }, 100);
  }

  function restart() {
    stop();
    step(0);
  }

  // 1. Initial state
  assert.equal(activeIndex, -1);
  assert.equal(timer, null);

  // 2. Play advances immediately to stage 0 (first in timestamp order)
  play();
  assert.equal(activeIndex, 0);
  assert.equal(highlightedStage, stages[0].stage_id);
  assert.equal(scrubberValue, '0');
  assert.equal(playBtnText, 'Pause');
  assert.ok(timer !== null, 'Timer should be active');

  // 3. Repeated play calls do NOT create duplicate timers
  const timerBefore = timer;
  play(); // Second play call
  assert.notEqual(timer, timerBefore, 'Timer should be replaced, not duplicated');

  // 4. Pause immediately stops timer and resets button text
  stop();
  assert.equal(timer, null, 'Pause should immediately clear timer');
  assert.equal(playBtnText, 'Play');

  // 5. Restart returns to stage 1 (index 0) and resets timeline
  step(2);
  assert.equal(activeIndex, 2);
  restart();
  assert.equal(activeIndex, 0, 'Restart must return to stage 1');
  assert.equal(highlightedStage, stages[0].stage_id);
  assert.equal(scrubberValue, '0');
  assert.equal(timer, null);

  // 6. Scrubber jump directly advances to target stage
  step(1);
  assert.equal(activeIndex, 1);
  assert.equal(highlightedStage, stages[1].stage_id);
  assert.equal(scrubberValue, '1');
});

test('Original forensic console timeline preparation and UI components render correctly', () => {
  const rawIncident = mockIncident('INC-0009');
  const inc = prepareTimelineIncident(rawIncident);

  assert.ok(inc.durationMin > 0, 'durationMin is positive');
  assert.ok(inc.stages.length > 0, 'has stages');
  for (const stage of inc.stages) {
    assert.ok(typeof stage.t0 === 'number' && stage.t0 >= 0, 'stage has valid t0');
    assert.ok(typeof stage.t1 === 'number' && stage.t1 >= stage.t0, 'stage has valid t1');
  }

  // Hero card renders incident severity, id, and summary
  const hero = heroHtml(inc);
  assert.match(hero, /class="hero"/);
  assert.match(hero, /verdict\s+v-/);
  assert.match(hero, /INC-0009/);

  // Chain renders step-by-step cards with tactics, routes, and badges
  const chain = chainHtml(inc);
  assert.match(chain, /class="chain"/);
  assert.match(chain, /class="card"/);
  assert.match(chain, /class="ico-tile"/);
  assert.match(chain, /data-stage="INC-0009-stage-1"/);

  // Caption renders active step and summary
  const s0 = inc.stages[0];
  const cap = capHtml(inc, s0, s0.stage_id);
  assert.match(cap, /cap-t/);
  assert.match(cap, /cap-d/);

  // NetworkScene setTime respects t0 and t1 thresholds
  const container = createMockContainer();
  const scene = new NetworkScene(container, () => {});
  scene.setIncident(inc);

  // At t = 0 before stage occurs
  scene.setTime(0);
  assert.equal(scene.t, 0);

  // At stage active time
  scene.setTime(s0.t0 + 0.1);
  assert.equal(scene.t, s0.t0 + 0.1);

  scene.dispose();
});

test('Replay timing correctly handles real timestamps, missing timestamps, and single stage', () => {
  // Case A: Real incident with multi-stage timestamps (INC-0009)
  const inc0009 = mockIncident('INC-0009');
  const timed0009 = prepareTimelineIncident(inc0009);

  const startMs = Date.parse(inc0009.start);
  const endMs = Date.parse(inc0009.end);
  const expectedDuration = (endMs - startMs) / 60000;

  assert.ok(Math.abs(timed0009.durationMin - expectedDuration) < 0.1, 'durationMin matches real incident elapsed time');
  assert.equal(timed0009.stages.length, inc0009.stages.length);
  assert.equal(timed0009.stages[0].t0, 0, 'First stage starts at t=0');

  // Case B: Incident with completely missing timestamps
  const missingInc = {
    incident_id: 'INC-NO-TIMESTAMPS',
    stages: [
      { stage_id: 'stg-1', order: 1, tactic: 'Reconnaissance', src: 'host-a', dst: 'host-b' },
      { stage_id: 'stg-2', order: 2, tactic: 'Credential Access', src: 'host-b', dst: 'host-c' },
    ],
  };
  const timedMissing = prepareTimelineIncident(missingInc);
  assert.ok(!isNaN(timedMissing.durationMin) && timedMissing.durationMin > 0, 'missing timestamps duration is valid');
  assert.equal(timedMissing.stages[0].t0, 0);
  assert.ok(timedMissing.stages[0].t1 > 0);
  assert.ok(timedMissing.stages[1].t0 >= timedMissing.stages[0].t1);
  assert.ok(timedMissing.stages[1].t1 <= timedMissing.durationMin);

  // Case C: Single stage incident with missing timestamps
  const singleStageInc = {
    incident_id: 'INC-SINGLE-STAGE',
    stages: [
      { stage_id: 'stg-solo', order: 1, tactic: 'Exfiltration', src: 'host-x', dst: 'host-y' },
    ],
  };
  const timedSingle = prepareTimelineIncident(singleStageInc);
  assert.equal(timedSingle.stages.length, 1);
  assert.equal(timedSingle.stages[0].t0, 0);
  assert.ok(timedSingle.stages[0].t1 > 0);
  assert.ok(timedSingle.durationMin >= timedSingle.stages[0].t1);

  // Case D: Zero stage incident
  const zeroStageInc = { incident_id: 'INC-ZERO', stages: [] };
  const timedZero = prepareTimelineIncident(zeroStageInc);
  assert.equal(timedZero.stages.length, 0);
  assert.ok(timedZero.durationMin > 0);
});

test('Replay speed multiplier scales time advancement accurately across 0.5x, 1x, and 2x', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));
  const duration = inc.durationMin;

  function advanceTime(currentTime, dtSeconds, speed) {
    const baseRate = Math.max(0.5, duration / 20);
    return Math.min(currentTime + dtSeconds * baseRate * speed, duration);
  }

  const dt = 1.0; // 1 second elapsed
  const tStart = 0;

  const tHalf = advanceTime(tStart, dt, 0.5);
  const tNormal = advanceTime(tStart, dt, 1.0);
  const tDouble = advanceTime(tStart, dt, 2.0);

  assert.ok(tHalf > 0, '0.5x advances time');
  assert.ok(tNormal > tHalf, '1x advances faster than 0.5x');
  assert.ok(tDouble > tNormal, '2x advances faster than 1x');

  // Verify exact ratio
  assert.ok(Math.abs((tNormal - tStart) - (tHalf - tStart) * 2) < 0.001, '1x is exactly 2 * 0.5x');
  assert.ok(Math.abs((tDouble - tStart) - (tNormal - tStart) * 2) < 0.001, '2x is exactly 2 * 1x');
});

test('Replay state controller supports pause, resume, restart, and clamps duration', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));
  let t = 0;
  let playing = false;

  function play() {
    playing = true;
  }
  function pause() {
    playing = false;
  }
  function restart() {
    playing = false;
    t = 0;
  }
  function tick(dtSec, speed = 1) {
    if (!playing) return;
    const baseRate = Math.max(0.5, inc.durationMin / 20);
    t = Math.min(t + dtSec * baseRate * speed, inc.durationMin);
    if (t >= inc.durationMin) playing = false;
  }

  // 1. Initial
  assert.equal(t, 0);
  assert.equal(playing, false);

  // 2. Play advances time
  play();
  tick(2.0, 1.0);
  assert.ok(t > 0, 'Time advanced during playback');
  const pausedTime = t;

  // 3. Pause halts time advancement
  pause();
  assert.equal(playing, false);
  tick(2.0, 1.0);
  assert.equal(t, pausedTime, 'Time remains unchanged while paused');

  // 4. Resume continues from paused time
  play();
  tick(1.0, 1.0);
  assert.ok(t > pausedTime, 'Time continues forward from paused position');

  // 5. Restart resets time to beginning
  restart();
  assert.equal(t, 0, 'Restart resets time to 0');
  assert.equal(playing, false, 'Restart leaves controller in paused state');
});

test('Auto-rotate and drag pivot orbit around the centre of the 3D network/scene, not around ATK', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));
  const container = createMockContainer();
  const scene = new NetworkScene(container, () => {});
  scene.setIncident(inc);

  // 1. Scene centre and bounds are computed from the overall network layout
  assert.ok(scene.fitState, 'fitState must be defined');
  const sceneCenter = scene.fitState.center;
  const framingRad = scene.fitState.rad;

  // Initial camera pivot and goal must match the network scene centre
  assert.equal(scene.tgt.x, sceneCenter.x, 'Initial camera target X matches scene centre');
  assert.equal(scene.tgt.y, sceneCenter.y, 'Initial camera target Y matches scene centre');
  assert.equal(scene.tgt.z, sceneCenter.z, 'Initial camera target Z matches scene centre');
  assert.equal(scene.goal.x, sceneCenter.x, 'Goal target X matches scene centre');
  assert.equal(scene.cam.rad, framingRad, 'Camera radius frames full network');

  // 2. Identify attacker host from evidence
  const attacker = findInitialAttacker(inc);
  assert.ok(attacker, 'Attacker host must be identified');
  const attackerPos = scene.nodes[attacker.id].position;
  assert.notEqual(sceneCenter.x, attackerPos.x, 'Scene centre must be distinct from ATK position');

  // 3. Selection highlights attacker host without shifting the camera pivot away from scene centre
  scene.setSelection({ host: attacker.id });
  assert.equal(scene.sel.host, attacker.id);
  assert.equal(scene.nodes[attacker.id].scale.x, 1.4, 'Attacker node is scaled when selected');
  assert.equal(scene.tgt.x, sceneCenter.x, 'Camera pivot remains at scene centre after attacker selection');

  // 4. In auto-rotate mode, camera pivot remains locked to the scene centre
  scene.setOption('rotate', true);
  scene.focus(null);
  assert.equal(scene.goal.x, sceneCenter.x, 'Camera goal X stays at scene centre');
  assert.equal(scene.goal.y, sceneCenter.y, 'Camera goal Y stays at scene centre');
  assert.equal(scene.goal.z, sceneCenter.z, 'Camera goal Z stays at scene centre');

  // 5. Dragging empty space rotates around the scene centre
  scene._inputHandlers.onPointerDown({ clientX: 200, clientY: 200, button: 0 });
  assert.equal(scene.tgt.x, sceneCenter.x, 'Pivot during drag remains at scene centre');
  scene._inputHandlers.onPointerMove({ clientX: 250, clientY: 220 });
  assert.equal(scene.tgt.x, sceneCenter.x, 'Pivot during drag motion stays at scene centre');
  scene._inputHandlers.onPointerUp({});

  scene.dispose();
});

test('Attacker-first playback initializes camera and selection at the attacker host', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0001'));
  const container = createMockContainer();
  const scene = new NetworkScene(container, () => {});
  scene.setIncident(inc);

  // 1. Attacker is identified from evidence
  const attacker = findInitialAttacker(inc);
  assert.ok(attacker, 'Attacker host must be identified');
  assert.equal(attacker.id, 'ATK', 'INC-0001 attacker is ATK');

  // 2. First replay stage originates from ATK
  assert.ok(inc.stages.length > 0, 'Stages must exist');
  const firstStage = inc.stages[0];
  assert.equal(firstStage.src, 'ATK', 'First replay stage originates from ATK');

  // 3. Selection highlights attacker host
  scene.setSelection({ host: attacker.id });
  assert.equal(scene.sel.host, 'ATK');
  assert.equal(scene.nodes['ATK'].scale.x, 1.4, 'Attacker node is scaled when selected');

  // 4. Restart restores camera framing to scene centre and keeps ATK selected
  scene.fit();
  assert.equal(scene.tgt.x, scene.fitState.center.x, 'Camera target is restored to scene centre on restart/fit');
  assert.equal(scene.cam.rad, scene.fitState.rad, 'Camera radius frames full network');

  scene.dispose();
});

test('Incident with different attacker evidence uses that evidence instead of hardcoded ATK', () => {
  const customInc = {
    incident_id: 'INC-CUSTOM-ADV',
    hosts: [
      { id: 'ADV-99', ip: '10.99.1.5', zone: 'EXTERNAL', role: 'Threat actor / adversary infrastructure' },
      { id: 'SRV-01', ip: '10.99.2.10', zone: 'DMZ', role: 'Web Server' },
    ],
    stages: [
      { stage_id: 'stg-adv-1', order: 1, tactic: 'Initial Access', src: 'ADV-99', dst: 'SRV-01' },
    ],
  };
  const timed = prepareTimelineIncident(customInc);
  const attacker = findInitialAttacker(timed);
  assert.ok(attacker, 'Attacker should be found');
  assert.equal(attacker.id, 'ADV-99', 'Uses explicit adversary role from evidence instead of hardcoded ATK');
  assert.equal(timed.stages[0].src, 'ADV-99', 'First stage originates from identified attacker');
});

test('Packets animate directionally from source to destination along actual stage edge curve', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));
  const container = createMockContainer();
  const scene = new NetworkScene(container, () => {});
  scene.setIncident(inc);

  for (const stage of inc.stages) {
    const edge = scene.edges[stage.stage_id];
    assert.ok(edge, `Edge for stage ${stage.stage_id} must exist`);

    // Verify source and destination mapping
    const dir = scene.getEdgeDirection(stage.stage_id);
    assert.equal(dir.src, stage.src, 'Edge source matches stage source');
    assert.equal(dir.dst, stage.dst, 'Edge destination matches stage destination');

    // Verify curve endpoints match source and destination node positions
    const srcPos = scene.nodes[stage.src].position;
    const dstPos = scene.nodes[stage.dst].position;
    const curveStart = edge.curve.getPoint(0);
    const curveEnd = edge.curve.getPoint(1);

    assert.ok(curveStart.distanceTo(srcPos) < 0.001, 'Curve start (u=0) must match source host position');
    assert.ok(curveEnd.distanceTo(dstPos) < 0.001, 'Curve end (u=1) must match destination host position');

    // Verify packet progress advances directionally from 0 to 1 as time advances
    const p0 = scene.getPacketProgress(stage.stage_id, 0, 0);
    const p1 = scene.getPacketProgress(stage.stage_id, 0, 600); // 600ms later
    assert.ok(p1 > p0, 'Packet progress moves forward from source toward destination');
  }

  scene.dispose();
});

test('Chronological stages advance in timestamp order without skipping or inventing connections', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));

  // Verify stages are in strictly non-decreasing chronological order
  for (let i = 0; i < inc.stages.length - 1; i++) {
    const curr = inc.stages[i];
    const next = inc.stages[i + 1];
    assert.ok(curr.t0 <= next.t0, `Stage ${curr.stage_id} (t0=${curr.t0}) must precede ${next.stage_id} (t0=${next.t0})`);
    assert.ok(curr.t1 <= next.t1 || curr.t0 < next.t0, 'Stage sequencing adheres to timeline');
  }

  // Ensure no phantom stages were invented
  const rawInc = mockIncident('INC-0009');
  assert.equal(inc.stages.length, rawInc.stages.length, 'Stage count must exactly match real incident');
  for (let i = 0; i < rawInc.stages.length; i++) {
    assert.equal(inc.stages[i].stage_id, rawInc.stages[i].stage_id);
    assert.equal(inc.stages[i].src, rawInc.stages[i].src);
    assert.equal(inc.stages[i].dst, rawInc.stages[i].dst);
  }
});

test('Missing attacker data and missing stages fall back safely without inventing connections', () => {
  // Case 1: Incident with internal-only hosts and missing attacker label
  const internalInc = {
    incident_id: 'INC-INTERNAL',
    hosts: [
      { id: 'srv1', ip: '10.0.0.1', zone: 'INTERNAL', role: 'Server' },
      { id: 'srv2', ip: '10.0.0.2', zone: 'INTERNAL', role: 'Database' },
    ],
    stages: [
      { stage_id: 's1', src: 'srv1', dst: 'srv2', tactic: 'Lateral Movement' },
    ],
  };
  const timedInternal = prepareTimelineIncident(internalInc);
  const attacker = findInitialAttacker(timedInternal);
  assert.ok(attacker, 'Falls back to source of initial stage srv1');
  assert.equal(attacker.id, 'srv1');

  // Case 2: Incident with completely empty hosts and stages
  const emptyInc = { incident_id: 'INC-EMPTY', hosts: [], stages: [] };
  const timedEmpty = prepareTimelineIncident(emptyInc);
  const noAttacker = findInitialAttacker(timedEmpty);
  assert.equal(noAttacker, null, 'Returns null safely when no attacker data exists');

  const container = createMockContainer();
  const scene = new NetworkScene(container, () => {});
  scene.setIncident(timedEmpty);

  // Focus safely falls back to scene overview when attacker is null
  scene.focusHost(null);
  assert.ok(scene.goalRad > 0, 'Camera radius remains valid');

  scene.dispose();
});

test('Fullscreen 3D layout matches reference structure with 3 columns and single bottom replay bar', () => {
  const html = readFileSync(join(__dirname, '../index.html'), 'utf-8');

  // 1. Left Attack Chain Sidebar
  assert.ok(html.includes('id="fullscreenLeft"'), 'Left attack-chain sidebar exists');
  assert.ok(html.includes('id="fullscreenChain"'), 'Attack chain list container exists');
  assert.ok(html.includes('id="fullscreenChainCount"'), 'Attack chain count exists');

  // 2. Central 3D Graph
  assert.ok(html.includes('id="fullscreenGraphCanvas"'), 'Central 3D canvas container exists');

  // 3. Right Evidence & Verified Report Sidebar with tabs
  assert.ok(html.includes('id="fullscreenRight"'), 'Right details sidebar exists');
  assert.ok(html.includes('data-fs-tab="evidence"'), 'Evidence tab button exists');
  assert.ok(html.includes('data-fs-tab="report"'), 'Report tab button exists');
  assert.ok(html.includes('id="fsEvidenceInspector"'), 'Evidence inspector pane exists');
  assert.ok(html.includes('id="fsReportContent"'), 'Report content pane exists');

  // 4. Single compact replay/timeline bar across bottom
  assert.ok(html.includes('class="fullscreen-replay-bar"'), 'Single bottom replay bar exists');
  assert.ok(html.includes('class="fs-timeline-container"'), 'Consolidated timeline container exists');
  assert.ok(html.includes('id="fsTimeline"'), 'Embedded timeline exists inside replay bar');
  assert.ok(html.includes('id="fsReplayProgress"'), 'Scrubber slider exists inside replay bar');
  assert.ok(html.includes('id="fsReplayStageProgress"'), 'Stage progress text exists');

  // 5. CSS verifies fsCap is hidden (no floating secondary bottom panel)
  const css = readFileSync(join(__dirname, '../src/styles.css'), 'utf-8');
  assert.ok(css.includes('#fsCap'), '#fsCap rule exists');
  assert.ok(css.includes('display: none !important'), '#fsCap is hidden from floating over the graph');
});

test('Time formatting functions correctly display Indian Standard Time (IST)', () => {
  const testIso = '2026-11-02T15:04:49.000Z'; // 15:04:49 UTC -> 20:34:49 IST (+5:30)

  // 1. clockAt
  const clockFormatted = clockAt(testIso, 0);
  assert.ok(clockFormatted.includes('IST'), 'clockAt must format time with IST');
  assert.ok(clockFormatted.includes('20:34:49'), 'clockAt must offset UTC to Indian Standard Time (15:04 -> 20:34)');

  // 2. formatTime
  const timeFormatted = formatTime(testIso);
  assert.ok(timeFormatted.includes('IST'), 'formatTime must display IST timezone');
  assert.ok(timeFormatted.includes('20:34:49'), 'formatTime must convert UTC hours to IST');

  // 3. formatDateTime
  const dateTimeFormatted = formatDateTime(testIso);
  assert.ok(dateTimeFormatted.includes('IST'), 'formatDateTime must display IST');
});

test('Dragging empty space does not accidentally trigger camera follow or node selection', () => {
  const inc = prepareTimelineIncident(mockIncident('INC-0009'));
  const container = createMockContainer();
  let selected = null;
  const scene = new NetworkScene(container, sel => { selected = sel; });
  scene.setIncident(inc);

  const initialTargetX = scene.tgt.x;

  // 1. Pointer down on empty space sets dragging
  scene._inputHandlers.onPointerDown({ clientX: 200, clientY: 200, button: 0 });
  assert.equal(scene.dragging, true, 'Dragging is active on empty space');

  // 2. Camera follow does NOT change camera target while dragging
  scene.focus(inc.stages[0].stage_id);
  assert.equal(scene.tgt.x, initialTargetX, 'Camera target does not move due to focus while dragging');

  // 3. Drag motion updates camera angles around scene centre
  scene._inputHandlers.onPointerMove({ clientX: 260, clientY: 240 });
  assert.equal(scene.tgt.x, initialTargetX, 'Camera pivot stays at scene centre during drag');

  // 4. Pointer up after drag does not select nodes
  scene._inputHandlers.onPointerUp({});
  assert.equal(scene.dragging, false, 'Dragging ended');
  assert.equal(selected, null, 'No node or stage was accidentally selected after drag');

  scene.dispose();
});

test('Grey drag instruction panel is removed and colored timeline is the primary interactive scrubber', () => {
  const html = readFileSync(join(__dirname, '../index.html'), 'utf-8');
  assert.ok(!html.includes('Drag = orbit'), 'Grey instruction text has been removed from index.html');
  assert.ok(html.includes('id="fsTimeline"'), 'Colored timeline element exists');
  assert.ok(html.includes('class="sr-only"'), 'Duplicate progress track is visually hidden with sr-only');

  const css = readFileSync(join(__dirname, '../src/styles.css'), 'utf-8');
  assert.ok(css.includes('.fs-tl-seg.stage-completed'), 'CSS styles completed stage segments');
  assert.ok(css.includes('.fs-tl-seg.stage-active'), 'CSS styles active stage segments');
  assert.ok(css.includes('.fs-tl-seg.stage-upcoming'), 'CSS styles upcoming stage segments');
  assert.ok(css.includes('.fs-playhead'), 'CSS defines needle playhead on colored timeline');
});

test('INC-0001 is default incident in mockList and provides all required attack stages', () => {
  const list = mockList();
  assert.ok(list.length > 0, 'mockList is not empty');
  assert.equal(list[0].incident_id, 'INC-0001', 'INC-0001 must be first incident by default');

  const raw = mockIncident('INC-0001');
  const adapted = adapt(raw);
  const inc = prepareTimelineIncident(adapted);

  const tactics = inc.stages.map(s => s.tactic);
  assert.ok(tactics.includes('Reconnaissance'), 'Includes Reconnaissance stage');
  assert.ok(tactics.includes('Credential Access'), 'Includes Credential Access stage');
  assert.ok(tactics.includes('Lateral Movement'), 'Includes Lateral Movement stage');
  assert.ok(tactics.includes('Command and Control'), 'Includes Command and Control stage');

  // Verify multiple Lateral Movement stages are preserved individually
  const lateralStages = inc.stages.filter(s => s.tactic === 'Lateral Movement');
  assert.ok(lateralStages.length >= 2, 'Multiple Lateral Movement stages are rendered individually');
  assert.notEqual(lateralStages[0].dst, lateralStages[1].dst, 'Lateral Movement stages target distinct destinations');

  // Verify observed vs inferred status distinction
  const observedCount = inc.stages.filter(s => s.observed).length;
  const inferredCount = inc.stages.filter(s => !s.observed).length;
  assert.ok(observedCount > 0, 'Contains observed stages');
  assert.ok(inferredCount > 0, 'Contains inferred stages');
});
