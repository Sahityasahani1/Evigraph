import * as THREE from 'three';
import { colorOf } from '../config.js';
import { ICONS, roleIcon } from '../ui/icons.js';
import { STATUS } from '../ui/story.js';
import { fitDistance, layoutIncident } from './layout.js';

const ZONE_LABEL = { EXTERNAL: ['INTERNET', 'outside, not trusted'], DMZ: ['DMZ', 'public-facing servers'], INTERNAL: ['INTERNAL', 'private network'] };
const BASE = { EXTERNAL: 0xff5d6c, DMZ: 0x52e0a0, INTERNAL: 0x6fa8ff };

function sprite(w, h, sx, sy) {
  const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
  const tex = new THREE.CanvasTexture(cv);
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
  s.scale.set(sx, sy, 1); return { s, cv, tex };
}
function zoneLabel(name) {
  const { s, cv } = sprite(440, 90, 7.8, 1.6), g = cv.getContext('2d');
  g.textAlign = 'center'; g.lineJoin = 'round'; g.strokeStyle = 'rgba(5,10,25,.9)'; g.lineWidth = 6;
  g.font = 'bold 30px system-ui'; g.strokeText(ZONE_LABEL[name][0], 220, 36); g.fillStyle = '#e6e0ff'; g.fillText(ZONE_LABEL[name][0], 220, 36);
  g.font = '20px system-ui'; g.strokeText(ZONE_LABEL[name][1], 220, 68); g.fillStyle = '#b3a9d6'; g.fillText(ZONE_LABEL[name][1], 220, 68);
  s.material.map.needsUpdate = true; return s;
}
function drawHost(cv, h, status) {
  const g = cv.getContext('2d'), col = status === 'safe' ? '#a79fc4' : STATUS[status].col;
  g.clearRect(0, 0, cv.width, cv.height);
  g.fillStyle = 'rgba(14,10,26,.92)'; g.beginPath(); g.roundRect ? g.roundRect(4, 4, 432, 88, 18) : g.rect(4, 4, 432, 88); g.fill();
  g.lineWidth = 3; g.strokeStyle = status === 'safe' ? 'rgba(150,140,190,.5)' : col; g.stroke();
  g.save(); g.translate(18, 22); g.scale(2.2, 2.2); g.lineWidth = 1.6; g.lineCap = 'round'; g.lineJoin = 'round'; g.strokeStyle = col;
  ICONS[roleIcon(h)].forEach(d => g.stroke(new Path2D(d))); g.restore();
  g.textAlign = 'left'; g.fillStyle = '#fff'; g.font = 'bold 30px system-ui'; g.fillText(h.id, 82, 44);
  g.font = '20px system-ui'; g.fillStyle = '#a79fc4'; g.fillText(h.ip, 82, 74);
  if (status !== 'safe') { g.textAlign = 'right'; g.font = 'bold 20px system-ui'; g.fillStyle = col; g.fillText(STATUS[status].label, 424, 74); }
}

/** 3D network view. Owns rendering only; data in via setIncident/setTime/setStatus, events out via callbacks. */
export class NetworkScene {
  constructor(canvas, { onSelect, onHover = () => {} }) {
    this.onSelect = onSelect; this.onHover = onHover;
    this.opt = { benign: true, packets: true, rotate: true, follow: true };
    this.t = 0; this.sel = null; this.nodes = {}; this.edges = {}; this.pickables = []; this.labels = {}; this.status = {};
    this.cam = { th: 0.7, ph: 1.2, rad: 38 }; this.tgt = new THREE.Vector3(); this.goal = new THREE.Vector3(); this.goalRad = null;

    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(50, 1, 0.1, 300);
    this.scene.add(new THREE.AmbientLight(0xffffff, 1.6));
    const key = new THREE.PointLight(0x9d7bff, 2, 0); key.position.set(0, 20, 10); this.scene.add(key);
    this.zoneGroup = new THREE.Group(); this.scene.add(this.zoneGroup);
    this.setTheme(document.documentElement.dataset.theme || 'dark');
    this.dyn = new THREE.Group(); this.scene.add(this.dyn);

    this.raycaster = new THREE.Raycaster(); this.raycaster.params.Line.threshold = 0.5;
    this._bindInput(canvas);
    addEventListener('resize', () => this._resize()); this._resize();
    this.last = performance.now(); this.raf = requestAnimationFrame(n => this._loop(n));
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
      const l = zoneLabel(name); l.position.set(x, height / 2 + 1, 0);
      this.zoneGroup.add(m, edges, l);
    }
  }

  setTheme(theme) {
    if (this.grid) { this.scene.remove(this.grid); this.grid.geometry.dispose(); }
    const light = theme === 'light';
    this.grid = new THREE.GridHelper(60, 30, light ? 0xb8a98a : 0x2c2248, light ? 0xd9cfb4 : 0x17102a);
    this.grid.position.y = -6; this.scene.add(this.grid);
  }

  setIncident(inc) {
    this.dyn.clear(); this.nodes = {}; this.edges = {}; this.pickables = []; this.labels = {}; this.status = {}; this.sel = null;
    const layout = layoutIncident(inc.hosts);
    this._zones(layout.zones);
    this.bounds = layout.bounds;
    this.fit = {
      center: new THREE.Vector3(...layout.center),
      rad: fitDistance(layout.bounds, this.camera.fov, innerWidth / innerHeight),
    };
    this.cam.rad = this.fit.rad;
    this.tgt.copy(this.fit.center);
    this.goal.copy(this.fit.center);
    this.goalRad = this.fit.rad;
    const pos = layout.positions;
    for (const h of inc.hosts) {
      const geo = h.role?.toLowerCase().includes('database') ? new THREE.CylinderGeometry(0.9, 0.9, 1.4, 20)
        : h.zone === 'EXTERNAL' ? new THREE.OctahedronGeometry(1.1) : new THREE.IcosahedronGeometry(0.9, 1);
      const col = BASE[h.zone] ?? 0x6fa8ff;
      const m = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({ color: col, emissive: col, emissiveIntensity: 0.3, roughness: 0.4 }));
      m.position.set(...pos[h.id]); m.userData = { host: h.id, base: col };
      const { s, cv, tex } = sprite(440, 96, 6.2, 1.35); drawHost(cv, h, 'safe'); tex.needsUpdate = true;
      s.position.set(pos[h.id][0], pos[h.id][1] + 2.2, pos[h.id][2]);
      this.dyn.add(m, s); this.nodes[h.id] = m; this.pickables.push(m); this.labels[h.id] = { cv, tex, h }; this.status[h.id] = 'safe';
    }
    inc.stages.forEach(s => this._edge(s.stage_id, s.src, s.dst, 2 + (s.order % 3), colorOf(s.tactic), s, false));
    inc.background?.forEach((b, i) => this._edge('bg' + i, b.src, b.dst, -1.5, 0x6b6190, null, true));
    this.stages = inc.stages;
  }

  _edge(id, a, b, bend, color, stage, benign) {
    const A = this.nodes[a]?.position, B = this.nodes[b]?.position; if (!A || !B) return;
    const M = A.clone().add(B).multiplyScalar(0.5); M.y += bend; M.z += bend * 0.4;
    const curve = new THREE.QuadraticBezierCurve3(A, M, B);
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(40)),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: benign ? 0.2 : 0 }));
    line.userData = { stage: id };
    const packets = Array.from({ length: benign ? 2 : 7 }, () => {
      const p = new THREE.Mesh(new THREE.SphereGeometry(benign ? 0.1 : 0.17, 8, 8), new THREE.MeshBasicMaterial({ color }));
      p.visible = false; this.dyn.add(p); return p;
    });
    this.dyn.add(line); if (!benign) this.pickables.push(line);
    this.edges[id] = { curve, line, packets, stage, benign };
  }

  setTime(t) { this.t = t; }
  setSelection(sel) { this.sel = sel; }
  setOption(k, v) { this.opt[k] = v; if (k === 'follow' && !v) this.focus(null, true); }

  setStatus(map) {
    for (const [id, st] of Object.entries(map)) {
      const m = this.nodes[id], l = this.labels[id]; if (!m || this.status[id] === st) continue;
      this.status[id] = st;
      const col = st === 'safe' ? m.userData.base : new THREE.Color(STATUS[st].col).getHex();
      m.material.color.set(col); m.material.emissive.set(col);
      drawHost(l.cv, l.h, st); l.tex.needsUpdate = true;
    }
  }

  // Fly the camera to the connection being explained (or back to the overview).
  focus(stageId, force = false) {
    if (!this.opt.follow && !force) return;
    const e = stageId && this.edges[stageId];
    if (!e) { this.goal.copy(this.fit?.center ?? this.tgt); this.goalRad = this.fit?.rad ?? 36; return; }
    this.goal.copy(e.curve.getPoint(0.5)); this.goalRad = 24;
  }

  _hover(e) {
    this.raycaster.setFromCamera(new THREE.Vector2((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1), this.camera);
    const u = this.raycaster.intersectObjects(this.pickables)[0]?.object.userData;
    const hidden = u?.stage && this.t < (this.edges[u.stage]?.stage.t0 ?? 0);
    this.onHover(!u || hidden ? null : u.host ? { host: u.host } : { stage: u.stage }, e.clientX, e.clientY);
  }

  _bindInput(c) {
    let drag = null, moved = 0;
    c.onpointerdown = e => { this.onHover(null); drag = [e.clientX, e.clientY]; moved = 0; c.setPointerCapture(e.pointerId); this.dragging = true; };
    c.onpointermove = e => {
      if (!drag) { this._hover(e); return; }
      const dx = e.clientX - drag[0], dy = e.clientY - drag[1]; moved += Math.abs(dx) + Math.abs(dy);
      this.cam.th -= dx * 0.006; this.cam.ph = Math.max(0.2, Math.min(2.9, this.cam.ph - dy * 0.006)); drag = [e.clientX, e.clientY];
    };
    c.onwheel = e => { this.goalRad = null; this.cam.rad = Math.max(12, Math.min(Math.max(70, this.fit?.rad * 1.5 || 70), this.cam.rad + e.deltaY * 0.03)); e.preventDefault(); };
    c.onpointerup = e => {
      drag = null; this.dragging = false; if (moved > 5) return;
      this.raycaster.setFromCamera(new THREE.Vector2((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1), this.camera);
      const hit = this.raycaster.intersectObjects(this.pickables)[0]; if (!hit) { this.onSelect(null); return; }
      const u = hit.object.userData; this.onSelect(u.host ? { host: u.host } : { stage: u.stage });
    };
  }

  _resize() { this.renderer.setSize(innerWidth, innerHeight); this.camera.aspect = innerWidth / innerHeight; this.camera.updateProjectionMatrix(); }

  _loop(n) {
    const dt = Math.min((n - this.last) / 1000, 0.1); this.last = n;
    const c = this.cam, k = 1 - Math.exp(-dt * 2.5);
    if (this.opt.rotate && !this.dragging) c.th += dt * 0.08;
    this.tgt.lerp(this.goal, k); if (this.goalRad != null) c.rad += (this.goalRad - c.rad) * k;
    this.camera.position.set(this.tgt.x + c.rad * Math.sin(c.ph) * Math.sin(c.th), this.tgt.y + c.rad * Math.cos(c.ph), this.tgt.z + c.rad * Math.sin(c.ph) * Math.cos(c.th));
    this.camera.lookAt(this.tgt);
    const t = this.t, sel = this.sel;
    for (const [id, e] of Object.entries(this.edges)) {
      if (e.benign) {
        e.line.visible = this.opt.benign;
        e.packets.forEach((p, i) => { p.visible = this.opt.benign && this.opt.packets; p.position.copy(e.curve.getPoint((n / 4000 + i / 2) % 1)); });
        continue;
      }
      const s = e.stage, active = t >= s.t0 && t <= s.t1, seen = t >= s.t0, picked = sel?.stage === id;
      e.line.material.opacity = active ? 1 : seen ? (picked ? 0.9 : 0.4) : (picked ? 0.5 : 0.03);
      e.packets.forEach((p, i) => {
        p.visible = active && this.opt.packets; p.scale.setScalar(picked ? 1.6 : 1);
        if (active) p.position.copy(e.curve.getPoint((n / 1500 + i / e.packets.length) % 1));
      });
    }
    for (const [id, m] of Object.entries(this.nodes)) {
      const st = this.status[id];
      m.material.emissiveIntensity = st === 'safe' ? 0.3 : 0.7 + 0.3 * Math.sin(n / (st === 'stolen' ? 150 : 260));
      m.rotation.y += dt * 0.6; m.scale.setScalar(sel?.host === id ? 1.4 : 1);
    }
    this.renderer.render(this.scene, this.camera);
    this.raf = requestAnimationFrame(x => this._loop(x));
  }

  dispose() { cancelAnimationFrame(this.raf); this.renderer.dispose(); }
}
