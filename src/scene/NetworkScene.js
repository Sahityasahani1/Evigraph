import * as THREE from 'three';
import { colorOf } from '../config.js';

const ZONE_X = { EXTERNAL: -17, DMZ: -7, INTERNAL: 3 };
const ZONE_BOX = { EXTERNAL: [0.3, 10, 16, -17.5], DMZ: [0.3, 10, 10, -7.5], INTERNAL: [13, 10, 14, 7.5] };

function label(text, color = '#dbe6ff') {
  const cv = document.createElement('canvas'); cv.width = 256; cv.height = 64;
  const g = cv.getContext('2d'); g.font = 'bold 30px system-ui'; g.textAlign = 'center'; g.fillStyle = color; g.fillText(text, 128, 42);
  const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(cv), transparent: true, depthTest: false }));
  s.scale.set(5, 1.25, 1); return s;
}

/** 3D network view. Owns rendering only; data in via setIncident/setTime, events out via onSelect. */
export class NetworkScene {
  constructor(canvas, { onSelect }) {
    this.onSelect = onSelect;
    this.opt = { benign: true, packets: true, rotate: true };
    this.t = 0; this.sel = null; this.nodes = {}; this.edges = {}; this.pickables = [];
    this.cam = { th: 0.7, ph: 1.2, rad: 38 };

    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(50, 1, 0.1, 300);
    this.scene.add(new THREE.AmbientLight(0xffffff, 1.6));
    const key = new THREE.PointLight(0x88aaff, 2, 0); key.position.set(0, 20, 10); this.scene.add(key);
    const grid = new THREE.GridHelper(60, 30, 0x24345c, 0x131c33); grid.position.y = -6; this.scene.add(grid);
    this._zones();
    this.dyn = new THREE.Group(); this.scene.add(this.dyn);

    this.raycaster = new THREE.Raycaster(); this.raycaster.params.Line.threshold = 0.5;
    this._bindInput(canvas);
    addEventListener('resize', () => this._resize()); this._resize();
    this.last = performance.now(); this.raf = requestAnimationFrame(n => this._loop(n));
  }

  _zones() {
    for (const [name, [w, h, d, x]] of Object.entries(ZONE_BOX)) {
      const geo = new THREE.BoxGeometry(w, h, d);
      const m = new THREE.Mesh(geo, new THREE.MeshBasicMaterial({ color: name === 'EXTERNAL' ? 0x7a2a3a : 0x2a4a8a, transparent: true, opacity: 0.08 }));
      m.position.x = x;
      const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo), new THREE.LineBasicMaterial({ color: 0x3b5aa0, transparent: true, opacity: 0.35 }));
      edges.position.x = x;
      const l = label(name + (name === 'EXTERNAL' ? ' (untrusted)' : '')); l.position.set(x, 6.2, 0);
      this.scene.add(m, edges, l);
    }
  }

  _layout(hosts) {
    const byZone = {};
    hosts.forEach(h => { (byZone[h.zone] ||= []).push(h); });
    const pos = {};
    for (const [z, list] of Object.entries(byZone)) list.forEach((h, i) => {
      const a = i * 2.4, r = 1.5 + i * 0.7;
      pos[h.id] = [(ZONE_X[z] ?? 0) + (z === 'INTERNAL' ? (i % 3) * 4 : 0), Math.sin(a) * r * 1.2, Math.cos(a) * r];
    });
    return pos;
  }

  setIncident(inc) {
    this.dyn.clear(); this.nodes = {}; this.edges = {}; this.pickables = []; this.sel = null;
    const pos = this._layout(inc.hosts);
    for (const h of inc.hosts) {
      const geo = h.role?.toLowerCase().includes('database') ? new THREE.CylinderGeometry(0.9, 0.9, 1.4, 20)
        : h.zone === 'EXTERNAL' ? new THREE.OctahedronGeometry(1.1) : new THREE.IcosahedronGeometry(0.9, 1);
      const col = h.zone === 'EXTERNAL' ? 0xff5d6c : h.zone === 'DMZ' ? 0x52e0a0 : 0x6fa8ff;
      const m = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({ color: col, emissive: col, emissiveIntensity: 0.3, roughness: 0.4 }));
      m.position.set(...pos[h.id]); m.userData = { host: h.id };
      const l = label(h.id); l.position.set(pos[h.id][0], pos[h.id][1] + 1.9, pos[h.id][2]);
      this.dyn.add(m, l); this.nodes[h.id] = m; this.pickables.push(m);
    }
    inc.stages.forEach(s => this._edge(s.stage_id, s.src, s.dst, 2 + (s.order % 3), colorOf(s.tactic), s, false));
    inc.background?.forEach((b, i) => this._edge('bg' + i, b.src, b.dst, -1.5, 0x5a6a8c, null, true));
    this.stages = inc.stages;
  }

  _edge(id, a, b, bend, color, stage, benign) {
    const A = this.nodes[a]?.position, B = this.nodes[b]?.position; if (!A || !B) return;
    const M = A.clone().add(B).multiplyScalar(0.5); M.y += bend; M.z += bend * 0.4;
    const curve = new THREE.QuadraticBezierCurve3(A, M, B);
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(40)),
      new THREE.LineBasicMaterial({ color, transparent: true, opacity: benign ? 0.18 : 0 }));
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
  setOption(k, v) { this.opt[k] = v; }

  _bindInput(c) {
    let drag = null, moved = 0;
    c.onpointerdown = e => { drag = [e.clientX, e.clientY]; moved = 0; c.setPointerCapture(e.pointerId); this.dragging = true; };
    c.onpointermove = e => {
      if (!drag) return;
      const dx = e.clientX - drag[0], dy = e.clientY - drag[1]; moved += Math.abs(dx) + Math.abs(dy);
      this.cam.th -= dx * 0.006; this.cam.ph = Math.max(0.2, Math.min(2.9, this.cam.ph - dy * 0.006)); drag = [e.clientX, e.clientY];
    };
    c.onwheel = e => { this.cam.rad = Math.max(12, Math.min(70, this.cam.rad + e.deltaY * 0.03)); e.preventDefault(); };
    c.onpointerup = e => {
      drag = null; this.dragging = false; if (moved > 5) return;
      this.raycaster.setFromCamera(new THREE.Vector2((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1), this.camera);
      const hit = this.raycaster.intersectObjects(this.pickables)[0]; if (!hit) return;
      const u = hit.object.userData; this.onSelect(u.host ? { host: u.host } : { stage: u.stage });
    };
  }

  _resize() { this.renderer.setSize(innerWidth, innerHeight); this.camera.aspect = innerWidth / innerHeight; this.camera.updateProjectionMatrix(); }

  _loop(n) {
    const dt = Math.min((n - this.last) / 1000, 0.1); this.last = n;
    const c = this.cam; if (this.opt.rotate && !this.dragging) c.th += dt * 0.08;
    this.camera.position.set(c.rad * Math.sin(c.ph) * Math.sin(c.th), c.rad * Math.cos(c.ph), c.rad * Math.sin(c.ph) * Math.cos(c.th));
    this.camera.lookAt(-1, 0, 0);
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
      const hot = this.stages?.some(s => (s.src === id || s.dst === id) && t >= s.t0);
      m.material.emissiveIntensity = hot ? 0.9 + 0.3 * Math.sin(n / 250) : 0.3;
      m.rotation.y += dt * 0.6; m.scale.setScalar(sel?.host === id ? 1.4 : 1);
    }
    this.renderer.render(this.scene, this.camera);
    this.raf = requestAnimationFrame(x => this._loop(x));
  }

  dispose() { cancelAnimationFrame(this.raf); this.renderer.dispose(); }
}
