import * as THREE from 'three';
import { colorOf } from '../config.js';
import { ICONS, roleIcon } from '../ui/icons.js';
import { STATUS } from '../ui/story.js';
import { fitDistance, layoutIncident } from './layout.js';

const ZONE_LABEL = {
  EXTERNAL: ['INTERNET', 'outside, not trusted'],
  DMZ: ['DMZ', 'public-facing servers'],
  INTERNAL: ['INTERNAL', 'private network'],
};
const BASE = { EXTERNAL: 0xff5d6c, DMZ: 0x52e0a0, INTERNAL: 0x6fa8ff };

function sprite(w, h, sx, sy) {
  if (typeof document === 'undefined') {
    const s = new THREE.Object3D();
    s.scale.set(sx, sy, 1);
    return { s, cv: null, tex: null };
  }
  const cv = document.createElement('canvas');
  cv.width = w;
  cv.height = h;
  const tex = new THREE.CanvasTexture(cv);
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
  s.scale.set(sx, sy, 1);
  return { s, cv, tex };
}

function zoneLabel(name) {
  const { s, cv } = sprite(440, 90, 7.8, 1.6);
  if (!cv) return s;
  const g = cv.getContext('2d');
  if (!g) return s;
  const labelInfo = ZONE_LABEL[name] || [name, ''];
  g.textAlign = 'center';
  g.lineJoin = 'round';
  g.strokeStyle = 'rgba(5,10,25,.9)';
  g.lineWidth = 6;
  g.font = 'bold 30px system-ui';
  g.strokeText(labelInfo[0], 220, 36);
  g.fillStyle = '#e6e0ff';
  g.fillText(labelInfo[0], 220, 36);
  g.font = '20px system-ui';
  g.strokeText(labelInfo[1], 220, 68);
  g.fillStyle = '#b3a9d6';
  g.fillText(labelInfo[1], 220, 68);
  if (s.material?.map) s.material.map.needsUpdate = true;
  return s;
}

function drawHost(cv, h, status) {
  if (!cv) return;
  const g = cv.getContext('2d');
  if (!g) return;
  const statusInfo = STATUS[status] || STATUS.safe;
  const col = status === 'safe' ? '#a79fc4' : statusInfo.col;
  g.clearRect(0, 0, cv.width, cv.height);
  g.fillStyle = 'rgba(14,10,26,.92)';
  g.beginPath();
  if (typeof g.roundRect === 'function') g.roundRect(4, 4, 432, 88, 18);
  else g.rect(4, 4, 432, 88);
  g.fill();
  g.lineWidth = 3;
  g.strokeStyle = status === 'safe' ? 'rgba(150,140,190,.5)' : col;
  g.stroke();
  g.save();
  g.translate(18, 22);
  g.scale(2.2, 2.2);
  g.lineWidth = 1.6;
  g.lineCap = 'round';
  g.lineJoin = 'round';
  g.strokeStyle = col;
  const iconPaths = ICONS[roleIcon(h)] || ICONS.help;
  if (typeof Path2D !== 'undefined') {
    iconPaths.forEach(d => g.stroke(new Path2D(d)));
  }
  g.restore();
  g.textAlign = 'left';
  g.fillStyle = '#fff';
  g.font = 'bold 30px system-ui';
  g.fillText(h.id || h.ip || 'Host', 82, 44);
  g.font = '20px system-ui';
  g.fillStyle = '#a79fc4';
  g.fillText(h.ip || 'IP unavailable', 82, 74);
  if (status !== 'safe') {
    g.textAlign = 'right';
    g.font = 'bold 20px system-ui';
    g.fillStyle = col;
    g.fillText(statusInfo.label, 424, 74);
  }
}

function createRenderer(canvas) {
  if (canvas && typeof document !== 'undefined') {
    try {
      const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
      renderer.setPixelRatio(Math.min(typeof devicePixelRatio !== 'undefined' ? devicePixelRatio : 1, 2));
      return renderer;
    } catch {
      // Fallback for headless environments without WebGL
    }
  }
  return {
    setSize() {},
    setPixelRatio() {},
    render() {},
    dispose() {},
  };
}

/** 3D network view. Owns rendering; real data in via setIncident, events out via callbacks. */
export class NetworkScene {
  constructor(containerOrCanvas, optionsOrOnSelect = {}) {
    let onSelect, onHover;
    if (typeof optionsOrOnSelect === 'function') {
      onSelect = optionsOrOnSelect;
      onHover = () => {};
    } else {
      onSelect = optionsOrOnSelect.onSelect || (() => {});
      onHover = optionsOrOnSelect.onHover || (() => {});
    }
    this.onSelect = onSelect;
    this.onHover = onHover;

    let container, canvas;
    if (typeof HTMLCanvasElement !== 'undefined' && containerOrCanvas instanceof HTMLCanvasElement) {
      canvas = containerOrCanvas;
      container = canvas.parentElement || canvas;
    } else if (containerOrCanvas && typeof containerOrCanvas.querySelector === 'function') {
      container = containerOrCanvas;
      canvas = container.querySelector('canvas');
      if (!canvas && typeof document !== 'undefined') {
        canvas = document.createElement('canvas');
        canvas.className = 'network-scene-canvas';
        canvas.style.width = '100%';
        canvas.style.height = '100%';
        canvas.style.display = 'block';
        container.appendChild(canvas);
      }
    } else {
      container = containerOrCanvas;
      canvas = containerOrCanvas;
    }
    this.container = container;
    this.canvas = canvas;

    this.opt = { benign: true, packets: true, rotate: true, follow: true };
    this.t = 0;
    this.sel = null;
    this.selection = null;
    this.replayStageId = null;
    this.nodes = {};
    this.edges = {};
    this.pickables = [];
    this.labels = {};
    this.status = {};
    this.stages = [];
    this.data = null;
    this.cam = { th: 0.7, ph: 1.2, rad: 38 };
    this.tgt = new THREE.Vector3();
    this.goal = new THREE.Vector3();
    this.goalRad = null;

    this.renderer = createRenderer(this.canvas);
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(50, 1, 0.1, 300);
    this.scene.add(new THREE.AmbientLight(0xffffff, 1.6));
    const key = new THREE.PointLight(0x9d7bff, 2, 0);
    key.position.set(0, 20, 10);
    this.scene.add(key);

    this.zoneGroup = new THREE.Group();
    this.scene.add(this.zoneGroup);
    const initialTheme = (typeof document !== 'undefined' && document.documentElement?.dataset?.theme) || 'dark';
    this.setTheme(initialTheme);
    this.dyn = new THREE.Group();
    this.scene.add(this.dyn);

    this.raycaster = new THREE.Raycaster();
    this.raycaster.params.Line.threshold = 0.5;

    this._bindInput(this.canvas || this.container);
    this._bindPanelControls();

    this._onResize = () => this._resize();
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      window.addEventListener('resize', this._onResize);
    }
    if (typeof ResizeObserver !== 'undefined' && this.container && typeof this.container.getBoundingClientRect === 'function') {
      this.resizeObserver = new ResizeObserver(() => this._resize());
      this.resizeObserver.observe(this.container);
    }
    this._resize();

    this.last = typeof performance !== 'undefined' ? performance.now() : Date.now();
    if (typeof requestAnimationFrame !== 'undefined') {
      this.raf = requestAnimationFrame(n => this._loop(n));
    }
  }

  _getSize() {
    if (this.container && typeof this.container.getBoundingClientRect === 'function') {
      const rect = this.container.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        return { width: rect.width, height: rect.height };
      }
    }
    if (this.canvas && typeof this.canvas.getBoundingClientRect === 'function') {
      const rect = this.canvas.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        return { width: rect.width, height: rect.height };
      }
    }
    const w = this.container?.clientWidth || this.canvas?.clientWidth || 1000;
    const h = this.container?.clientHeight || this.canvas?.clientHeight || 450;
    return { width: Math.max(w, 100), height: Math.max(h, 100) };
  }

  _resize() {
    const { width, height } = this._getSize();
    if (this.renderer && typeof this.renderer.setSize === 'function') {
      this.renderer.setSize(width, height, false);
    }
    if (this.camera) {
      this.camera.aspect = width / height;
      this.camera.updateProjectionMatrix();
    }
    if (this.bounds && this.camera) {
      this.fitDistance = fitDistance(this.bounds, this.camera.fov, this.camera.aspect);
    }
  }

  _getPointerPos(e) {
    const target = this.canvas || this.container;
    if (!target || typeof target.getBoundingClientRect !== 'function') {
      return { x: 0, y: 0 };
    }
    const rect = target.getBoundingClientRect();
    const width = rect.width || 1;
    const height = rect.height || 1;
    return {
      x: ((e.clientX - rect.left) / width) * 2 - 1,
      y: -((e.clientY - rect.top) / height) * 2 + 1,
    };
  }

  _zones(zones) {
    for (const child of this.zoneGroup.children) {
      child.geometry?.dispose();
      if (Array.isArray(child.material)) child.material.forEach(material => material.dispose());
      else child.material?.dispose();
    }
    this.zoneGroup.clear();
    for (const { name, width, height, depth, x } of zones) {
      const geo = new THREE.BoxGeometry(width, height, depth);
      const m = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ color: name === 'EXTERNAL' ? 0x7a2a3a : 0x5b3fb0, transparent: true, opacity: 0.09 }));
      m.position.x = x;
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo), new THREE.LineBasicMaterial({ color: name === 'EXTERNAL' ? 0xc0506a : 0x7c5cf0, transparent: true, opacity: 0.4 }));
      edges.position.x = x;
      const l = zoneLabel(name);
      l.position.set(x, height / 2 + 1, 0);
      this.zoneGroup.add(m, edges, l);
    }
  }

  setTheme(theme) {
    if (this.grid) {
      this.scene.remove(this.grid);
      this.grid.geometry?.dispose();
      if (Array.isArray(this.grid.material)) this.grid.material.forEach(m => m.dispose());
      else this.grid.material?.dispose();
    }
    const light = theme === 'light';
    this.grid = new THREE.GridHelper(60, 30, light ? 0xb8a98a : 0x2c2248, light ? 0xd9cfb4 : 0x17102a);
    this.grid.position.y = -6;
    this.scene.add(this.grid);
  }

  setIncident(inc) {
    this.data = inc;
    this.dyn.clear();
    this.nodes = {};
    this.edges = {};
    this.pickables = [];
    this.labels = {};
    this.status = {};
    this.sel = null;
    this.selection = null;
    this.replayStageId = null;

    if (!inc || !inc.hosts || !inc.hosts.length) {
      this.stages = [];
      return;
    }

    const layout = layoutIncident(inc.hosts);
    this._zones(layout.zones);
    this.bounds = layout.bounds;
    const { width, height } = this._getSize();
    const aspect = width / height;
    const fov = this.camera?.fov ?? 50;
    this.fitState = {
      center: new THREE.Vector3(...layout.center),
      rad: fitDistance(layout.bounds, fov, aspect),
    };
    this.cam.rad = this.fitState.rad;
    this.tgt.copy(this.fitState.center);
    this.goal.copy(this.fitState.center);
    this.goalRad = this.fitState.rad;

    const pos = layout.positions;
    for (const h of inc.hosts) {
      const geo = h.role?.toLowerCase().includes('database') ? new THREE.CylinderGeometry(0.9, 0.9, 1.4, 20)
        : h.zone === 'EXTERNAL' ? new THREE.OctahedronGeometry(1.1) : new THREE.IcosahedronGeometry(0.9, 1);
      const col = BASE[h.zone] ?? 0x6fa8ff;
      const m = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({ color: col, emissive: col, emissiveIntensity: 0.3, roughness: 0.4 }));
      m.position.set(...pos[h.id]);
      m.userData = { host: h.id, base: col };
      const { s, cv, tex } = sprite(440, 96, 6.2, 1.35);
      drawHost(cv, h, 'safe');
      if (tex) tex.needsUpdate = true;
      s.position.set(pos[h.id][0], pos[h.id][1] + 2.2, pos[h.id][2]);
      this.dyn.add(m, s);
      this.nodes[h.id] = m;
      this.pickables.push(m);
      this.labels[h.id] = { cv, tex, h };
      this.status[h.id] = 'safe';
    }

    (inc.stages ?? []).forEach(s => this._edge(s.stage_id, s.src, s.dst, 2 + ((s.order || 1) % 3), colorOf(s.tactic), s, false));
    (inc.background ?? []).forEach((b, i) => this._edge('bg' + i, b.src, b.dst, -1.5, 0x6b6190, null, true));
    this.stages = inc.stages ?? [];
  }

  _edge(id, a, b, bend, color, stage, benign) {
    const A = this.nodes[a]?.position, B = this.nodes[b]?.position;
    if (!A || !B) return;
    const M = A.clone().add(B).multiplyScalar(0.5);
    M.y += bend;
    M.z += bend * 0.4;
    const curve = new THREE.QuadraticBezierCurve3(A, M, B);
    const line = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints(curve.getPoints(40)),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: benign ? 0.2 : 0.75 })
    );
    line.userData = { stage: id };
    const packets = Array.from({ length: benign ? 2 : 7 }, () => {
      const p = new THREE.Mesh(new THREE.SphereGeometry(benign ? 0.1 : 0.17, 8, 8), new THREE.MeshBasicMaterial({ color }));
      p.visible = false;
      this.dyn.add(p);
      return p;
    });
    this.dyn.add(line);
    if (!benign) this.pickables.push(line);
    this.edges[id] = { curve, line, packets, stage, benign, src: a, dst: b };
  }

  setTime(t) { this.t = t; }

  setSelection(sel) {
    this.sel = sel;
    this.selection = sel;
    for (const [id, m] of Object.entries(this.nodes)) {
      const isSelected = sel?.host === id;
      m.scale.setScalar(isSelected ? 1.4 : 1.0);
      if (m.material) {
        m.material.emissiveIntensity = isSelected ? 0.8 : (this.status[id] === 'safe' ? 0.3 : 0.6);
      }
    }
    for (const [id, e] of Object.entries(this.edges)) {
      if (e.benign) continue;
      const isSelected = sel?.stage === id;
      if (isSelected) {
        e.line.material.opacity = 1.0;
        e.packets.forEach(p => { p.visible = true; p.scale.setScalar(1.6); });
      }
    }
  }

  setReplay(stageId) {
    this.replayStageId = stageId;
    if (!stageId) {
      this.setSelection(this.sel);
      return;
    }
    const stage = this.stages?.find(item => (item.stage_id || '') === stageId);
    for (const [id, e] of Object.entries(this.edges)) {
      if (e.benign) continue;
      const isActive = id === stageId;
      e.line.material.opacity = isActive ? 1.0 : 0.15;
      e.packets.forEach(p => {
        p.visible = isActive;
        p.scale.setScalar(isActive ? 1.8 : 1.0);
      });
    }
    for (const [id, m] of Object.entries(this.nodes)) {
      const isEndpoint = stage && (stage.src === id || stage.dst === id);
      m.scale.setScalar(isEndpoint ? 1.35 : 1.0);
      if (m.material) {
        m.material.emissiveIntensity = isEndpoint ? 0.9 : 0.25;
      }
    }
  }

  zoom(factor) {
    if (!factor || factor <= 0) return;
    this.goalRad = null;
    const minRad = 10;
    const maxRad = Math.max(70, (this.fitState?.rad || 40) * 2.2);
    this.cam.rad = Math.max(minRad, Math.min(maxRad, this.cam.rad / factor));
  }

  fit() {
    if (!this.fitState) return this.reset();
    const { width, height } = this._getSize();
    const aspect = width / height;
    const fov = this.camera?.fov ?? 50;
    if (this.bounds) {
      this.fitState.rad = fitDistance(this.bounds, fov, aspect);
    }
    this.goal.copy(this.fitState.center);
    this.goalRad = this.fitState.rad;
    this.cam.rad = this.fitState.rad;
    this.tgt.copy(this.fitState.center);
  }

  reset() {
    this.cam.th = 0.7;
    this.cam.ph = 1.2;
    if (this.fitState) {
      this.tgt.copy(this.fitState.center);
      this.goal.copy(this.fitState.center);
      this.cam.rad = this.fitState.rad;
      this.goalRad = this.fitState.rad;
    } else {
      this.tgt.set(0, 0, 0);
      this.goal.set(0, 0, 0);
      this.cam.rad = 38;
      this.goalRad = 38;
    }
  }

  setOption(k, v) { this.opt[k] = v; if (k === 'follow' && !v) this.focus(null, true); }

  setStatus(map) {
    for (const [id, st] of Object.entries(map)) {
      const m = this.nodes[id], l = this.labels[id];
      if (!m || this.status[id] === st) continue;
      this.status[id] = st;
      const col = st === 'safe' ? m.userData.base : new THREE.Color(STATUS[st].col).getHex();
      m.material.color.set(col);
      m.material.emissive.set(col);
      drawHost(l.cv, l.h, st);
      if (l.tex) l.tex.needsUpdate = true;
    }
  }

  focus(targetId, force = false) {
    if (this.dragging) return;
    if (!this.opt.follow && !force) return;
    if (this.opt.rotate && !force) {
      this.goal.copy(this.fitState?.center ?? this.tgt);
      this.goalRad = this.fitState?.rad ?? 36;
      return;
    }
    if (!targetId) {
      this.goal.copy(this.fitState?.center ?? this.tgt);
      this.goalRad = this.fitState?.rad ?? 36;
      return;
    }
    const node = this.nodes[targetId];
    if (node) {
      this.goal.copy(node.position);
      this.goalRad = 20;
      return;
    }
    const e = this.edges[targetId];
    if (e) {
      this.goal.copy(e.curve.getPoint(0.5));
      this.goalRad = 24;
      return;
    }
    this.goal.copy(this.fitState?.center ?? this.tgt);
    this.goalRad = this.fitState?.rad ?? 36;
  }

  focusHost(hostId, instant = false) {
    if (this.dragging) return;
    if (!hostId) return this.focus(null);
    const node = this.nodes[hostId];
    if (!node) return this.focus(hostId);
    if (this.opt.rotate) {
      this.goal.copy(this.fitState?.center ?? this.tgt);
      this.goalRad = this.fitState?.rad ?? 36;
      return;
    }
    this.goal.copy(node.position);
    this.goalRad = 20;
    if (instant) {
      this.tgt.copy(node.position);
      this.cam.rad = 20;
    }
  }

  getEdgeDirection(stageId) {
    const e = this.edges[stageId];
    if (!e) return null;
    return { src: e.src, dst: e.dst };
  }

  getPacketProgress(stageId, packetIndex = 0, n = 0) {
    const e = this.edges[stageId];
    if (!e || !e.packets.length) return null;
    const speed = 1200;
    return ((n / speed + packetIndex / e.packets.length) % 1 + 1) % 1;
  }

  _hover(e) {
    if (!this.raycaster || !this.camera) return;
    const pos = this._getPointerPos(e);
    this.raycaster.setFromCamera(new THREE.Vector2(pos.x, pos.y), this.camera);
    const u = this.raycaster.intersectObjects(this.pickables)[0]?.object.userData;
    this.onHover(!u ? null : u.host ? { host: u.host } : { stage: u.stage }, e.clientX, e.clientY);
  }

  _bindInput(c) {
    if (!c) return;
    let drag = null, moved = 0;
    this.pendingPick = null;

    const onPointerDown = e => {
      if (e.button !== undefined && e.button !== 0) return;
      this.onHover(null);

      const pos = this._getPointerPos(e);
      this.raycaster.setFromCamera(new THREE.Vector2(pos.x, pos.y), this.camera);
      const hit = this.raycaster.intersectObjects(this.pickables)[0];

      moved = 0;
      if (hit) {
        // Potential click on a host or edge (do not start drag unless user moves mouse)
        this.pendingPick = hit.object.userData;
        drag = null;
        this.dragging = false;
        this._pickStart = [e.clientX, e.clientY];
        return;
      }

      // Left-click and drag on empty graph space rotates camera
      this.pendingPick = null;
      this._pickStart = null;
      drag = [e.clientX, e.clientY];
      moved = 0;
      this.dragging = true;
      if (this.fitState) {
        this.tgt.copy(this.fitState.center);
        this.goal.copy(this.fitState.center);
      }
      try {
        c.setPointerCapture?.(e.pointerId);
      } catch {}
    };

    const onPointerMove = e => {
      if (!drag) {
        if (this.pendingPick && this._pickStart) {
          const dist = Math.hypot(e.clientX - this._pickStart[0], e.clientY - this._pickStart[1]);
          if (dist > 5) {
            // Drag motion cancels accidental selection
            this.pendingPick = null;
            this._pickStart = null;
          }
        }
        this._hover(e);
        return;
      }
      const dx = e.clientX - drag[0], dy = e.clientY - drag[1];
      moved += Math.abs(dx) + Math.abs(dy);
      if (this.fitState) {
        this.tgt.copy(this.fitState.center);
        this.goal.copy(this.fitState.center);
      }
      this.cam.th -= dx * 0.006;
      this.cam.ph = Math.max(0.2, Math.min(2.9, this.cam.ph - dy * 0.006));
      drag = [e.clientX, e.clientY];
    };

    const onWheel = e => {
      this.goalRad = null;
      const minRad = 10;
      const maxRad = Math.max(70, (this.fitState?.rad || 40) * 2.2);
      this.cam.rad = Math.max(minRad, Math.min(maxRad, this.cam.rad + e.deltaY * 0.03));
      e.preventDefault?.();
    };

    const onPointerUp = e => {
      if (this.pendingPick) {
        const u = this.pendingPick;
        this.pendingPick = null;
        this.onSelect(u.host ? { host: u.host } : { stage: u.stage });
        return;
      }

      if (drag) {
        try {
          if (c.hasPointerCapture?.(e.pointerId)) {
            c.releasePointerCapture?.(e.pointerId);
          }
        } catch {}
        drag = null;
        this.dragging = false;
        if (moved <= 5) {
          this.onSelect(null);
        }
      }
    };

    const onPointerCancel = e => {
      this.pendingPick = null;
      drag = null;
      this.dragging = false;
    };

    c.addEventListener?.('pointerdown', onPointerDown);
    c.addEventListener?.('pointermove', onPointerMove);
    c.addEventListener?.('wheel', onWheel, { passive: false });
    c.addEventListener?.('pointerup', onPointerUp);
    c.addEventListener?.('pointercancel', onPointerCancel);

    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      window.addEventListener('pointerup', onPointerUp);
      window.addEventListener('pointercancel', onPointerCancel);
    }

    c.onpointerdown = onPointerDown;
    c.onpointermove = onPointerMove;
    c.onwheel = onWheel;
    c.onpointerup = onPointerUp;
    c.onpointercancel = onPointerCancel;

    this._inputHandlers = { onPointerDown, onPointerMove, onWheel, onPointerUp, onPointerCancel, element: c };
  }

  _bindPanelControls() {
    if (this.container?.closest) {
      const panel = this.container.closest('.graph-panel');
      if (panel) {
        this._onPanelClick = event => {
          const action = event.target?.closest?.('[data-graph-action]')?.dataset?.graphAction;
          if (action === 'zoom-in') this.zoom(1.2);
          if (action === 'zoom-out') this.zoom(0.84);
          if (action === 'fit') this.fit();
          if (action === 'reset') this.reset();
        };
        panel.addEventListener('click', this._onPanelClick);
      }
    }
  }

  _loop(n) {
    const dt = Math.min((n - this.last) / 1000, 0.1);
    this.last = n;
    const c = this.cam;
    const k = 1 - Math.exp(-dt * 2.5);
    if (this.opt.rotate && this.fitState) {
      this.goal.copy(this.fitState.center);
      if (this.goalRad == null || this.goalRad < this.fitState.rad) {
        this.goalRad = this.fitState.rad;
      }
    }
    if (this.opt.rotate && !this.dragging) c.th += dt * 0.08;
    this.tgt.lerp(this.goal, k);
    if (this.goalRad != null) c.rad += (this.goalRad - c.rad) * k;
    this.camera.position.set(
      this.tgt.x + c.rad * Math.sin(c.ph) * Math.sin(c.th),
      this.tgt.y + c.rad * Math.cos(c.ph),
      this.tgt.z + c.rad * Math.sin(c.ph) * Math.cos(c.th)
    );
    this.camera.lookAt(this.tgt);

    const sel = this.sel;
    const replayId = this.replayStageId;

    for (const [id, e] of Object.entries(this.edges)) {
      if (e.benign) {
        e.line.visible = this.opt.benign;
        e.packets.forEach((p, i) => {
          p.visible = this.opt.benign && this.opt.packets;
          p.position.copy(e.curve.getPoint((n / 4000 + i / 2) % 1));
        });
        continue;
      }
      const isReplayActive = replayId != null && replayId === id;
      const picked = sel?.stage === id;
      const s = e.stage;
      const inferred = s?.observed === false || s?.interpretation_status === 'inferred';

      let opacity = inferred ? 0.35 : 0.75;
      if (replayId != null) {
        opacity = isReplayActive ? 1.0 : 0.15;
      } else if (this.t != null && s && s.t0 != null) {
        const active = this.t >= s.t0 && this.t <= s.t1;
        const seen = this.t >= s.t0;
        opacity = active ? 1.0 : seen ? (picked ? 0.9 : (inferred ? 0.35 : 0.6)) : (picked ? 0.5 : 0.05);
      } else if (picked) {
        opacity = 1.0;
      }
      e.line.material.opacity = opacity;

      const isTimeActive = this.t != null && s && s.t0 != null && this.t >= s.t0 && this.t <= s.t1;
      const showPackets = replayId != null
        ? isReplayActive
        : (this.t != null && s && s.t0 != null)
        ? (isTimeActive && this.opt.packets)
        : (this.opt.packets && (picked || !inferred));

      e.packets.forEach((p, i) => {
        p.visible = showPackets;
        if (showPackets) {
          const speed = (isReplayActive || isTimeActive) ? 1200 : 2000;
          const fraction = ((n / speed + i / e.packets.length) % 1 + 1) % 1;
          p.position.copy(e.curve.getPoint(fraction));
          const taper = 0.75 + 0.5 * fraction;
          p.scale.setScalar((picked || isReplayActive || isTimeActive ? 1.6 : 1) * taper);
        }
      });
    }

    for (const [id, m] of Object.entries(this.nodes)) {
      const st = this.status[id] || 'safe';
      const isReplayEndpoint = replayId != null && this.stages?.some(s => (s.stage_id === replayId) && (s.src === id || s.dst === id));
      const isTimeEndpoint = this.t != null && this.stages?.some(s => s.t0 != null && this.t >= s.t0 && this.t <= s.t1 && (s.src === id || s.dst === id));
      const isSelected = sel?.host === id;

      if (m.material) {
        if (isReplayEndpoint || isTimeEndpoint) {
          m.material.emissiveIntensity = 0.8 + 0.2 * Math.sin(n / 200);
        } else if (isSelected) {
          m.material.emissiveIntensity = 0.8;
        } else {
          m.material.emissiveIntensity = st === 'safe' ? 0.3 : 0.7 + 0.3 * Math.sin(n / (st === 'stolen' ? 150 : 260));
        }
      }
      m.rotation.y += dt * 0.6;
      m.scale.setScalar(isSelected || isReplayEndpoint || isTimeEndpoint ? 1.4 : 1);
    }

    this.renderer.render(this.scene, this.camera);
    if (typeof requestAnimationFrame !== 'undefined') {
      this.raf = requestAnimationFrame(x => this._loop(x));
    }
  }

  dispose() {
    if (this.raf && typeof cancelAnimationFrame !== 'undefined') {
      cancelAnimationFrame(this.raf);
      this.raf = null;
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    if (typeof removeEventListener !== 'undefined' && this._onResize) {
      removeEventListener('resize', this._onResize);
      this._onResize = null;
    }
    if (this._onPanelClick && this.container?.closest) {
      const panel = this.container.closest('.graph-panel');
      panel?.removeEventListener('click', this._onPanelClick);
      this._onPanelClick = null;
    }
    if (this._inputHandlers) {
      const { onPointerDown, onPointerMove, onWheel, onPointerUp, onPointerCancel, element } = this._inputHandlers;
      element.removeEventListener?.('pointerdown', onPointerDown);
      element.removeEventListener?.('pointermove', onPointerMove);
      element.removeEventListener?.('wheel', onWheel);
      element.removeEventListener?.('pointerup', onPointerUp);
      element.removeEventListener?.('pointercancel', onPointerCancel);
      if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
        window.removeEventListener('pointerup', onPointerUp);
        window.removeEventListener('pointercancel', onPointerCancel);
      }
      element.onpointerdown = null;
      element.onpointermove = null;
      element.onwheel = null;
      element.onpointerup = null;
      element.onpointercancel = null;
      this._inputHandlers = null;
    } else if (this.canvas) {
      this.canvas.onpointerdown = null;
      this.canvas.onpointermove = null;
      this.canvas.onwheel = null;
      this.canvas.onpointerup = null;
      this.canvas.onpointercancel = null;
    }
    if (this.zoneGroup) {
      for (const child of this.zoneGroup.children) {
        child.geometry?.dispose();
        if (Array.isArray(child.material)) child.material.forEach(m => m.dispose());
        else child.material?.dispose();
      }
    }
    if (this.dyn) {
      for (const child of this.dyn.children) {
        child.geometry?.dispose();
        if (Array.isArray(child.material)) child.material.forEach(m => m.dispose());
        else child.material?.dispose();
      }
    }
    if (this.grid) {
      this.grid.geometry?.dispose();
      if (Array.isArray(this.grid.material)) this.grid.material.forEach(m => m.dispose());
      else this.grid.material?.dispose();
    }
    this.renderer?.dispose();
  }
}
