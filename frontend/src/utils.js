// Everything derived from traffic is untrusted (TRD design principle 5): always escape before innerHTML.
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const clockAt = (startIso, minutes) =>
  new Date(Date.parse(startIso) + minutes * 60000).toISOString().slice(11, 19) + ' UTC';
