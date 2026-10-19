import { TIPS } from './tips.js';
import { esc } from '../utils.js';

const el = document.createElement('div');
el.id = 'tip';
document.body.appendChild(el);

export function showTip(html, x, y) {
  el.innerHTML = html; el.classList.add('on');
  el.style.left = Math.max(8, Math.min(x + 14, innerWidth - el.offsetWidth - 10)) + 'px';
  el.style.top = Math.max(8, Math.min(y + 14, innerHeight - el.offsetHeight - 10)) + 'px';
}
export const hideTip = () => el.classList.remove('on');
const tipHtml = ([t, what, why]) => `<b>${esc(t)}</b><div>${esc(what)}</div><div class="why">Why it matters: ${esc(why)}</div>`;

// One delegated listener for every element with data-tip. The 3D canvas manages its own hover.
export function initTips() {
  document.addEventListener('mousemove', e => {
    const host = e.target.closest?.('[data-tip]'), tip = host && TIPS[host.dataset.tip];
    if (tip) showTip(tipHtml(tip), e.clientX, e.clientY);
    else if (e.target.id !== 'scene') hideTip();
  });
}
