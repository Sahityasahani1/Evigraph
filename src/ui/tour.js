const STEPS = [
  { sel: null, t: 'Welcome', d: 'This screen replays a cyber attack on a network, step by step. A 30-second tour shows how to read it.' },
  { sel: '#mapzone', t: 'The network map', d: 'Each shape is a computer. Glass boxes are network zones. Glowing lines are attack traffic. Colors show how badly a machine is affected.' },
  { sel: '#left', t: 'The story', d: 'Each numbered card is one step the attacker took, in plain language. Click one to see the proof.' },
  { sel: '#bottom', t: 'Replay', d: 'Press Replay. The camera follows the attack and a caption explains each step.' },
  { sel: '#right', t: 'The proof', d: 'Click anything on the map or in the story to see the evidence behind it.' },
  { sel: '#rail', t: 'Your controls', d: 'Open the verified report, change the theme, or reopen this tour. Use Beginner / Analyst at the top to change the wording.' },
];
export function startTour() {
  if (document.getElementById('tour')) return;
  const o = document.createElement('div'); o.id = 'tour';
  o.innerHTML = '<div class="spot"></div><div class="tcard"></div>';  let i = 0;
  const done = () => { localStorage.setItem('evigraph_toured', '1'); o.remove(); };
  const draw = () => {
    const s = STEPS[i], spot = o.querySelector('.spot'), card = o.querySelector('.tcard');
    const r = s.sel ? document.querySelector(s.sel)?.getBoundingClientRect() : null;
    o.classList.toggle('center', !r);
    if (r) Object.assign(spot.style, { display: 'block', left: r.left - 6 + 'px', top: r.top - 6 + 'px', width: r.width + 12 + 'px', height: r.height + 12 + 'px' });
    else spot.style.display = 'none';
    card.innerHTML = `<b>${s.t}</b><p>${s.d}</p><div class="trow"><span class="mu">${i + 1} / ${STEPS.length}</span><span class="grow"></span><button data-t="skip">Skip</button><button class="on" data-t="next">${i === STEPS.length - 1 ? 'Done' : 'Next'}</button></div>`;
    const w = card.offsetWidth, h = card.offsetHeight; let L, T;
    if (!r) { L = (innerWidth - w) / 2; T = (innerHeight - h) / 2; }
    else if (r.height < 150) { L = (innerWidth - w) / 2; T = r.top - h - 16; }
    else if (r.left < innerWidth / 3 && r.width < innerWidth / 2) { L = r.right + 16; T = r.top + 24; }
    else if (r.left > innerWidth / 2) { L = r.left - w - 16; T = r.top + 24; }
    else { L = r.left + (r.width - w) / 2; T = r.top + 24; }
    card.style.left = Math.max(8, Math.min(L, innerWidth - w - 8)) + 'px';
    card.style.top = Math.max(8, Math.min(T, innerHeight - h - 8)) + 'px';
  };
  o.onclick = e => { const b = e.target.dataset?.t; if (b === 'skip' || (b === 'next' && i === STEPS.length - 1)) done(); else if (b === 'next') { i++; draw(); } };
  draw();
}
