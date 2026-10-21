import { esc } from '../utils.js';

const WIDTH = 1000;
const HEIGHT = 450;
const ZONE_X = { EXTERNAL: 150, DMZ: 500, INTERNAL: 850 };
const ZONE_BANDS = [
  { zone: 'EXTERNAL', left: 24, right: 276 },
  { zone: 'DMZ', left: 362, right: 638 },
  { zone: 'INTERNAL', left: 724, right: 976 },
];
const ZONE_TOP = 22;
const ZONE_BOTTOM = 416;
const NODE_TOP_INSET = 60;
const NODE_BOTTOM_INSET = 58;
const ZONE_NAMES = { EXTERNAL: 'EXTERNAL', DMZ: 'DMZ', INTERNAL: 'INTERNAL' };
const TACTIC_COLORS = {
  Reconnaissance: '#42c2d8',
  'Initial Access': '#e1ad51',
  'Credential Access': '#e1ad51',
  'Lateral Movement': '#e58b50',
  'Command and Control': '#8e9df2',
  Exfiltration: '#e87979',
  'Exfil & Impact': '#e87979',
};

export class AttackGraph {
  constructor(container, onSelect) {
    this.container = container;
    this.onSelect = onSelect;
    this.transform = { x: 0, y: 0, scale: 1 };
    this.data = null;
    this.selection = null;
    this._bind();
  }

  setIncident(incident) {
    this.data = incident;
    this.selection = null;
    this.transform = { x: 0, y: 0, scale: 1 };
    this.render();
  }

  setSelection(selection) {
    this.selection = selection;
    this.container.querySelectorAll('[data-host]').forEach(node => {
      node.classList.toggle('selected', selection?.host === node.dataset.host);
      node.setAttribute('aria-pressed', String(selection?.host === node.dataset.host));
    });
    this.container.querySelectorAll('[data-stage]').forEach(edge => {
      edge.classList.toggle('selected', selection?.stage === edge.dataset.stage);
      edge.setAttribute('aria-pressed', String(selection?.stage === edge.dataset.stage));
    });
  }

  setReplay(stageId) {
    this.container.querySelectorAll('.replay-current, .replay-host').forEach(item => {
      item.classList.remove('replay-current', 'replay-host');
    });
    const stage = this.data?.stages?.find(item => (item.stage_id || '') === stageId);
    if (!stage || stage.observed === false || stage.interpretation_status === 'inferred') return;
    const edge = [...this.container.querySelectorAll('[data-stage]')].find(item => item.dataset.stage === stageId);
    if (!edge) return;
    edge.classList.add('replay-current');
    [stage.src, stage.dst].forEach(hostId => {
      const node = [...this.container.querySelectorAll('[data-host]')].find(item => item.dataset.host === hostId);
      node?.classList.add('replay-host');
    });
  }

  render() {
    const incident = this.data;
    if (!incident) {
      this.container.innerHTML = '<div class="graph-empty">Graph data is unavailable for this incident.</div>';
      return;
    }
    const hosts = incident.hosts ?? [];
    const stages = incident.stages ?? [];
    if (!hosts.length) {
      this.container.innerHTML = '<div class="graph-empty">The incident API returned no host topology. Graph relationships cannot be rendered for this incident.</div>';
      return;
    }
    const positions = this._layout(hosts);
    const zoneBands = ZONE_BANDS.map(({ zone, left, right }) => `<g class="zone-band">
      <rect x="${left}" y="${ZONE_TOP}" width="${right - left}" height="${ZONE_BOTTOM - ZONE_TOP}" rx="15"></rect>
      <text x="${(left + right) / 2}" y="48">${ZONE_NAMES[zone]}</text>
    </g>`).join('');

    const backgroundEdges = (incident.background ?? []).map((edge, index) =>
      this._edgeMarkup(edge, `background-${index}`, positions, true),
    ).join('');
    const alertEdges = stages.map((stage, index) => this._edgeMarkup(stage, stage.stage_id || `stage-${index}`, positions, false)).join('');
    const nodes = hosts.map(host => this._nodeMarkup(host, positions[host.id])).join('');
    this.container.innerHTML = `<svg class="graph-canvas" viewBox="0 0 ${WIDTH} ${HEIGHT}" role="group" aria-label="Communication graph for ${esc(incident.incident_id)}">
      <defs><marker id="path-arrow" markerWidth="9" markerHeight="7" refX="8" refY="3.5" orient="auto"><path d="M0,0 L9,3.5 L0,7 z"></path></marker></defs>
      <g class="graph-viewport">${zoneBands}${backgroundEdges}${alertEdges}${nodes}</g>
    </svg>`;
    this._applyTransform();
    this.setSelection(this.selection);
  }

  _layout(hosts) {
    const groups = { EXTERNAL: [], DMZ: [], INTERNAL: [] };
    for (const host of hosts) (groups[host.zone] ?? groups.INTERNAL).push(host);
    const positions = {};
    for (const [zone, group] of Object.entries(groups)) {
      const available = ZONE_BOTTOM - NODE_BOTTOM_INSET - (ZONE_TOP + NODE_TOP_INSET);
      const gap = Math.min(86, available / Math.max(1, group.length - 1));
      const total = (group.length - 1) * gap;
      const start = (ZONE_TOP + NODE_TOP_INSET + ZONE_BOTTOM - NODE_BOTTOM_INSET) / 2 - total / 2;
      group.forEach((host, index) => { positions[host.id] = { x: ZONE_X[zone], y: start + index * gap }; });
    }
    return positions;
  }

  _edgeMarkup(edge, id, positions, background) {
    const source = positions[edge.src], target = positions[edge.dst];
    if (!source || !target) return '';
    const offset = background ? 0 : ((Number(edge.order) || 1) % 2 ? -13 : 13);
    const midX = (source.x + target.x) / 2 + offset;
    const midY = (source.y + target.y) / 2 - offset;
    const path = `M ${source.x} ${source.y} Q ${midX} ${midY} ${target.x} ${target.y}`;
    if (background) return `<path class="graph-background-edge" d="${path}" aria-hidden="true"></path>`;
    const color = TACTIC_COLORS[edge.tactic] || '#5bb8c8';
    const inferred = edge.interpretation_status === 'inferred' || edge.observed === false;
    const label = `${edge.tactic || 'Activity'} from ${edge.src} to ${edge.dst}${edge.port ? ` on port ${edge.port}` : ''}${edge.tactic_id ? `, ${edge.tactic_id}` : ''}`;
    return `<g class="graph-alert-edge ${inferred ? 'inferred' : 'observed'}" data-stage="${esc(id)}" tabindex="0" role="button" aria-pressed="false" aria-label="${esc(label)}" style="--edge-color:${color}">
      <path class="edge-hitarea" d="${path}"></path><path class="edge-line" d="${path}" marker-end="url(#path-arrow)"></path>
      <title>${esc(label)}</title></g>`;
  }

  _nodeMarkup(host, point) {
    if (!point) return '';
    const label = `${host.id || host.ip || 'Host'} · ${host.ip || 'address not provided'} · ${host.role || 'role not provided'}`;
    return `<g class="graph-node" data-host="${esc(host.id)}" tabindex="0" role="button" aria-pressed="false" aria-label="${esc(label)}" transform="translate(${point.x} ${point.y})">
      <circle class="node-halo" r="25"></circle><circle class="node-core" r="18"></circle>
      <text class="node-name" x="0" y="42">${esc(host.id || host.ip || 'Host')}</text>
      <text class="node-address" x="0" y="57">${esc(host.ip || 'IP unavailable')}</text><title>${esc(label)}</title>
    </g>`;
  }

  _bind() {
    this.container.addEventListener('click', event => {
      const node = event.target.closest('[data-host]');
      const edge = event.target.closest('[data-stage]');
      if (node) this.onSelect({ host: node.dataset.host });
      else if (edge) this.onSelect({ stage: edge.dataset.stage });
    });
    this.container.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const target = event.target.closest('[data-host],[data-stage]');
      if (!target) return;
      event.preventDefault();
      this.onSelect(target.dataset.host ? { host: target.dataset.host } : { stage: target.dataset.stage });
    });
    this.container.addEventListener('wheel', event => {
      event.preventDefault();
      this.zoom(event.deltaY < 0 ? 1.12 : 0.89);
    }, { passive: false });
    this.container.addEventListener('pointerdown', event => {
      if (event.target.closest('[data-host],[data-stage]')) return;
      this.drag = { x: event.clientX, y: event.clientY, tx: this.transform.x, ty: this.transform.y };
      event.preventDefault();
    });
    this.container.addEventListener('pointermove', event => {
      if (!this.drag) return;
      const rect = this.container.getBoundingClientRect();
      this.transform.x = this.drag.tx + (event.clientX - this.drag.x) * WIDTH / Math.max(rect.width, 1);
      this.transform.y = this.drag.ty + (event.clientY - this.drag.y) * HEIGHT / Math.max(rect.height, 1);
      this._applyTransform();
    });
    const stopDragging = () => { this.drag = null; };
    this.container.addEventListener('pointerup', stopDragging);
    this.container.addEventListener('pointercancel', stopDragging);
    this.container.closest('.graph-panel')?.addEventListener('click', event => {
      const action = event.target.closest('[data-graph-action]')?.dataset.graphAction;
      if (action === 'zoom-in') this.zoom(1.2);
      if (action === 'zoom-out') this.zoom(0.84);
      if (action === 'fit') this.fit();
      if (action === 'reset') this.reset();
    });
    this.container.addEventListener('keydown', event => {
      if (event.target.closest('[data-host],[data-stage]')) return;
      if (event.key === '+' || event.key === '=') this.zoom(1.2);
      if (event.key === '-') this.zoom(0.84);
      if (event.key === '0') this.fit();
    });
  }

  zoom(factor) {
    const previousScale = this.transform.scale;
    this.transform.scale = Math.max(0.55, Math.min(2.4, previousScale * factor));
    const actualFactor = this.transform.scale / previousScale;
    this.transform.x = WIDTH / 2 - (WIDTH / 2 - this.transform.x) * actualFactor;
    this.transform.y = HEIGHT / 2 - (HEIGHT / 2 - this.transform.y) * actualFactor;
    this._applyTransform();
  }

  fit() {
    if (!this.data?.hosts?.length) return this.reset();
    const minX = Math.min(...ZONE_BANDS.map(zone => zone.left));
    const maxX = Math.max(...ZONE_BANDS.map(zone => zone.right));
    const padding = 36;
    const scale = Math.min(1, (WIDTH - padding * 2) / (maxX - minX), (HEIGHT - padding * 2) / (ZONE_BOTTOM - ZONE_TOP));
    const centerX = (minX + maxX) / 2;
    const centerY = (ZONE_TOP + ZONE_BOTTOM) / 2;
    this.transform = {
      x: WIDTH / 2 - centerX * scale,
      y: HEIGHT / 2 - centerY * scale,
      scale,
    };
    this._applyTransform();
  }

  reset() {
    this.transform = { x: 0, y: 0, scale: 1 };
    this._applyTransform();
  }

  _applyTransform() {
    const viewport = this.container.querySelector('.graph-viewport');
    if (viewport) viewport.setAttribute('transform', `translate(${this.transform.x} ${this.transform.y}) scale(${this.transform.scale})`);
  }
}
