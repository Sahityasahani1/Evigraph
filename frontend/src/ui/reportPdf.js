// Dependency-free PDF writer for investigation reports.
//
// The PDF is assembled from the same normalized incident + report objects the
// JSON and Markdown exports use, so its contents always come from the live
// investigation payload (never hardcoded case text). We emit a plain PDF 1.4
// document with uncompressed text streams and the standard Helvetica fonts.

const PAGE_WIDTH = 595.28;
const PAGE_HEIGHT = 841.89;
const MARGIN = 48;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const BOTTOM = 54;

const FONTS = {
  body: 'F1',
  bold: 'F2',
};

// Map common Unicode punctuation to ASCII so the WinAnsi text stream stays valid.
const ASCII_MAP = {
  '\u2013': '-', '\u2014': '-', '\u2018': "'", '\u2019': "'",
  '\u201c': '"', '\u201d': '"', '\u2026': '...', '\u2022': '-',
  '\u2192': '->', '\u2190': '<-', '\u00a0': ' ', '\u2265': '>=',
  '\u2264': '<=', '\u00d7': 'x', '\u2713': 'ok', '\u2714': 'ok',
};

function toPrintable(value) {
  return String(value ?? '')
    .replace(/[\u2013\u2014\u2018\u2019\u201c\u201d\u2026\u2022\u2192\u2190\u00a0\u2265\u2264\u00d7\u2713\u2714]/g,
      ch => ASCII_MAP[ch] ?? '?')
    .replace(/\r\n?/g, '\n')
    .replace(/[\t\f\v]/g, ' ')
    // WinAnsi can encode Latin-1; anything else is replaced rather than corrupting the stream.
    .replace(/[^\x20-\x7e\xa0-\xff\n]/g, '?');
}

function escapePdf(text) {
  return toPrintable(text)
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

const charWidth = () => 0.5; // conservative average for Helvetica at any size

function wrapLine(text, size, bold, maxWidth = CONTENT_WIDTH) {
  const limit = Math.max(12, Math.floor(maxWidth / (size * charWidth())));
  const paragraphs = toPrintable(text).split('\n');
  const lines = [];
  for (const paragraph of paragraphs) {
    const words = paragraph.split(/\s+/).filter(Boolean);
    if (!words.length) {
      lines.push('');
      continue;
    }
    let current = '';
    for (const word of words) {
      if (!current) {
        current = word;
      } else if ((current.length + 1 + word.length) <= limit) {
        current += ` ${word}`;
      } else {
        lines.push(current);
        current = word;
      }
      // Long tokens (hashes, URLs) are hard-wrapped.
      while (current.length > limit) {
        lines.push(current.slice(0, limit));
        current = current.slice(limit);
      }
    }
    if (current) lines.push(current);
  }
  return lines.map(line => ({ text: line, size, bold, gap: size + 4 }));
}

function heading(text, level) {
  const size = level === 1 ? 17 : level === 2 ? 12.5 : 10;
  return [{ text: '', size: 4, bold: false, gap: level === 1 ? 6 : 8 }]
    .concat(wrapLine(text, size, true).map(line => ({ ...line, gap: size + 5 })));
}

function body(text, { bold = false, size = 9.5 } = {}) {
  return wrapLine(text, size, bold).map(line => ({ ...line, gap: size + 4.5 }));
}

function labelValue(label, value) {
  const text = `${label}: ${value === undefined || value === null || value === '' ? 'not provided' : value}`;
  return body(text, { size: 9.5 });
}

const fmt = value => {
  if (value === undefined || value === null || value === '') return 'not provided';
  if (typeof value === 'number') return String(value);
  return String(value);
};

const isoShort = value => {
  if (!value) return 'not provided';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
};

function alertTotal(incident) {
  const direct = incident?.total_alerts ?? incident?.alert_count;
  if (direct !== undefined && direct !== null && direct !== '') return direct;
  const stages = incident?.stages ?? [];
  const sum = stages.reduce((total, stage) => total + (Number(stage.alerts ?? stage.alert_count) || 0), 0);
  return sum || undefined;
}

const unique = values => [...new Set(values.filter(value => value !== undefined && value !== null && value !== ''))];

const preview = (values, limit = 6) => {
  const list = unique(values).map(String);
  if (!list.length) return '';
  return list.length > limit ? `${list.slice(0, limit).join(', ')} and ${list.length - limit} more` : list.join(', ');
};

const SERVICE_BY_PORT = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL',
  1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-alt',
};

function hostRoleLookup(report) {
  const roles = new Map();
  const groups = report?.host_roles ?? {};
  const add = (key, label) => {
    (Array.isArray(groups[key]?.hosts) ? groups[key].hosts : [])
      .forEach(host => roles.set(String(host), label));
  };
  add('compromised', 'compromised');
  add('infra', 'attacker infrastructure');
  add('attackers', 'attacker');
  add('victims', 'victim/target');
  return roles;
}

function recoveryBlocks(incident, report) {
  const inc = incident ?? {};
  const r = report ?? {};
  const stages = Array.isArray(inc.stages) ? inc.stages : [];
  const hosts = (Array.isArray(inc.hosts) ? inc.hosts : [])
    .map(host => (typeof host === 'string' ? { id: host, ip: host } : host));
  const sentences = Array.isArray(r.sentences) ? r.sentences : [];
  const recovery = r.recovery ?? {};
  const roleLookup = hostRoleLookup(r);
  const hostRole = host => host.role || roleLookup.get(String(host.id)) || roleLookup.get(String(host.ip)) || 'role not verified';

  const tactics = unique(stages.map(stage => stage.tactic));
  const behaviors = unique(stages.map(stage => stage.behavior));
  const stageEndpoints = unique(stages.flatMap(stage => [stage.src, stage.dst]));
  const unknownEndpoints = stageEndpoints.filter(value => !hosts.some(host => String(host.id) === String(value) || String(host.ip) === String(value)));

  const attackType = tactics.length
    ? `${tactics.join(', ')}${behaviors.length ? ` (${behaviors.join(', ')})` : ''}`
    : 'Not available - no attack stages were returned';

  const whatHappened = r.summary
    || r.factual_summary
    || (stages.length ? `${alertTotal(inc) ?? 'An unknown number of'} alerts were grouped into ${stages.length} stage(s).` : '');
  const stageChain = stages.length
    ? stages.map((stage, index) => {
      const route = [stage.src, stage.dst].filter(Boolean).join(' -> ');
      const port = stage.port ? `:${stage.port}` : '';
      const label = stage.behavior || stage.tactic || `stage ${index + 1}`;
      return `${index + 1}) ${label}: ${route}${port}${stage.observed === false ? ' (inferred)' : ''}`;
    }).join('; ')
    : '';
  const howAttack = stageChain
    ? `Observed stage sequence: ${stageChain}.`
    : 'Not available - the report did not include an ordered stage sequence.';

  const ports = unique(stages.map(stage => stage.port));
  const services = ports.length
    ? ports.map(port => {
      const name = SERVICE_BY_PORT[Number(port)];
      return name ? `${name} (port ${port})` : `port ${port} (service not verified)`;
    }).join(', ')
    : 'Not available - no destination ports were recorded';

  const evidenceFlows = unique(stages.flatMap(stage => (
    Array.isArray(stage.evidence) ? stage.evidence.map(item => item?.flow_id ?? item) : []
  )).concat(sentences.flatMap(sentence => sentence?.evidence_ids ?? [])));
  const stageEvidenceText = evidenceFlows.length
    ? `${evidenceFlows.length} flow record(s) are cited across ${stages.length || 1} stage(s).`
    : 'No flow-level evidence was returned for the affected stages.';
  const impactText = r.impact || r.impact_assessment
    || 'Not verified - this report records observed network activity but does not confirm data loss, malware installation, or system damage.';

  const roleOf = host => host.role || roleLookup.get(String(host.id)) || roleLookup.get(String(host.ip)) || '';
  const compromised = hosts.filter(host => /compromis/i.test(roleOf(host))).map(host => host.id || host.ip);
  const victims = hosts.filter(host => /victim|target/i.test(roleOf(host))).map(host => host.id || host.ip);
  const hostileSources = unique(hosts
    .filter(host => /attacker|infra/i.test(roleOf(host)))
    .map(host => host.id || host.ip)
    .concat(stages
      .filter(stage => {
        const srcHost = hosts.find(host => String(host.id) === String(stage.src) || String(host.ip) === String(stage.src));
        return srcHost && (/attacker|infra/i.test(roleOf(srcHost))
          || String(srcHost.zone ?? '').toUpperCase() === 'EXTERNAL');
      })
      .map(stage => stage.src)));

  const isolationTargets = unique([...compromised, ...victims]);
  const isolationText = isolationTargets.length
    ? `Consider isolating ${preview(isolationTargets, 8)} until their integrity is verified.`
    : 'Review the hosts listed in section 5.2 and isolate any system confirmed as compromised before cleanup begins.';

  const blockText = hostileSources.length
    ? `Consider blocking ${preview(hostileSources)} at the perimeter or host firewall, after confirming these are not shared or business-critical addresses.`
    : 'The attack source could not be identified from the returned data; blocking is not advised until it is confirmed.';

  const removalTargets = compromised.length ? preview(compromised, 8) : 'the affected hosts after isolation';
  const performed = Array.isArray(recovery.performed) ? recovery.performed : [];
  const unknown = Array.isArray(recovery.unknown) ? recovery.unknown : [];

  const blocks = [];
  blocks.push(...heading('5. Attack recovery and recommendations', 2));
  blocks.push(...body('This section is generated from the investigation data above. It separates what EviGraph detected and recorded from recommended recovery actions. EviGraph does not isolate systems, block attackers, remove malware, or restore systems automatically.', { size: 9 }));

  blocks.push(...heading('5.1 Attack summary', 3));
  blocks.push(...labelValue('Attack type', attackType));
  blocks.push(...labelValue('What happened', whatHappened || 'Not available'));
  blocks.push(...labelValue('How the attack occurred', howAttack));
  blocks.push(...labelValue('Attack stages', stages.length ? `${stages.length} stage(s) in the sequence below` : 'Not available'));
  if (!stages.length) {
    blocks.push(...body('No attack stages were returned for this incident.', { size: 9 }));
  } else {
    stages.forEach((stage, index) => {
      const route = [stage.src, stage.dst].filter(Boolean).join(' -> ');
      const port = stage.port ? `:${stage.port}` : '';
      const when = [stage.start || stage.t0, stage.end || stage.t1].filter(Boolean).map(isoShort).join(' - ');
      const observed = stage.observed === false ? 'inferred' : 'observed';
      blocks.push(...body(`${index + 1}. ${fmt(stage.tactic)}${stage.behavior ? ` / ${stage.behavior}` : ''} - ${route}${port} | ${when || 'time not available'} | ${observed}`, { size: 9 }));
    });
  }

  blocks.push(...heading('5.2 Affected systems', 3));
  if (!hosts.length && !unknownEndpoints.length) {
    blocks.push(...body('No affected hosts were returned for this incident. Impact: Not verified.', { size: 9 }));
  } else {
    hosts.forEach(host => {
      const incoming = stages.filter(stage => String(stage.dst) === String(host.id) || String(stage.dst) === String(host.ip)).length;
      const outgoing = stages.filter(stage => String(stage.src) === String(host.id) || String(stage.src) === String(host.ip)).length;
      const parts = [
        fmt(host.id),
        host.ip && host.ip !== host.id ? `IP ${host.ip}` : '',
        `role ${hostRole(host)}`,
        host.zone ? `zone ${host.zone}` : '',
        `stages as source ${outgoing}, as destination ${incoming}`,
        'impact Not verified',
      ].filter(Boolean);
      blocks.push(...body(`- ${parts.join(' | ')}`, { size: 9 }));
    });
    unknownEndpoints.forEach(endpoint => {
      blocks.push(...body(`- ${endpoint} | role not verified | not listed in incident hosts`, { size: 9 }));
    });
  }
  blocks.push(...labelValue('Services involved', services));
  blocks.push(...labelValue('Evidence about impact', stageEvidenceText));
  blocks.push(...labelValue('Confirmed impact or damage', impactText));
  if (compromised.length) {
    blocks.push(...labelValue('Possibly compromised hosts', preview(compromised, 8)));
  }
  if (victims.length) {
    blocks.push(...labelValue('Hosts receiving attack traffic', preview(victims, 8)));
  }

  blocks.push(...heading('5.3 Recovery recommendations', 3));
  blocks.push(...body('Recommended order. Each action is a recommendation and is not performed by EviGraph.', { size: 9 }));
  blocks.push(...body('1. Identify affected systems: review the hosts listed in section 5.2 and confirm which ones were actually compromised. Host identification is supported by this investigation; damage assessment is Not verified.', { size: 9 }));
  blocks.push(...body(`2. Isolate affected systems where appropriate: ${isolationText} Recommended - not performed.`, { size: 9 }));
  blocks.push(...body(`3. Block the attack source where appropriate: ${blockText} Recommended - not performed.`, { size: 9 }));
  blocks.push(...body(`4. Remove the threat: remove malicious changes or persistence from ${removalTargets}. Removal method and scope: Not verified. Not performed.`, { size: 9 }));
  blocks.push(...body('5. Restore affected systems: restore from a known-good backup or rebuild after cleanup. Backup availability: Not available. Restoration: Not performed.', { size: 9 }));
  blocks.push(...body('6. Verify systems are safe: re-scan the restored hosts, confirm expected services, and check for remaining malicious activity. Verification outcome: Not verified.', { size: 9 }));
  blocks.push(...body('7. Monitor for another attack: keep watching the affected hosts and the identified sources for repeat activity. Monitoring status: Unknown.', { size: 9 }));

  blocks.push(...heading('5.4 Recovery status', 3));
  blocks.push(...body('Actions performed and verified:', { bold: true, size: 9.5 }));
  if (performed.length) {
    performed.forEach(item => blocks.push(...body(`- ${typeof item === 'string' ? item : fmt(item?.action ?? item?.description ?? JSON.stringify(item))}`, { size: 9 })));
  } else {
    blocks.push(...body('- None recorded. This investigation report contains no evidence that isolation, blocking, malware removal, restoration, or safety verification was performed.', { size: 9 }));
  }
  blocks.push(...body('Recommended actions not yet performed:', { bold: true, size: 9.5 }));
  blocks.push(...body('- The seven recovery steps in section 5.3, including isolation, source blocking, threat removal, restoration, verification, and monitoring.', { size: 9 }));
  blocks.push(...body('Status unknown:', { bold: true, size: 9.5 }));
  if (unknown.length) {
    unknown.forEach(item => blocks.push(...body(`- ${typeof item === 'string' ? item : fmt(item?.item ?? item?.question ?? JSON.stringify(item))}`, { size: 9 })));
  } else {
    blocks.push(...body('- Whether affected hosts are still compromised: Not verified.', { size: 9 }));
    blocks.push(...body('- Whether malicious changes remain: Not verified.', { size: 9 }));
    blocks.push(...body('- Whether a clean backup exists: Not available.', { size: 9 }));
    blocks.push(...body('- Whether the attack source is blocked outside EviGraph: Unknown.', { size: 9 }));
    blocks.push(...body('- Whether post-recovery monitoring is active: Unknown.', { size: 9 }));
  }

  blocks.push(...heading('5.5 EviGraph capabilities', 3));
  blocks.push(...body('EviGraph supports attack detection, investigation, affected-host identification, evidence collection, and reporting. It produces this report from recorded investigation data. It does not perform containment, threat removal, or system restoration, and it makes no claim that these actions occurred.', { size: 9 }));

  return blocks;
}

function reportBlocks(incident, report) {
  const inc = incident ?? {};
  const r = report ?? {};
  const incidentsId = r.incident_id || inc.incident_id || 'Unknown';
  const footer = r.footer ?? {};
  const provenance = r.provenance ?? {};
  const sentences = Array.isArray(r.sentences) ? r.sentences : [];
  const rejected = Array.isArray(r.rejected_findings) ? r.rejected_findings : [];
  const stages = Array.isArray(inc.stages) ? inc.stages : [];
  const hosts = Array.isArray(inc.hosts) ? inc.hosts : [];
  const validation = r.validation ?? {};

  const blocks = [];
  blocks.push(...heading('EviGraph - Forensic Investigation Report', 1));
  blocks.push(...body(`Incident ${incidentsId}`, { bold: true, size: 11 }));

  const summary = r.summary
    || (r.summary_withheld_reason ? `Summary withheld: ${r.summary_withheld_reason}` : '')
    || r.factual_summary
    || 'No executive summary was returned for this report.';

  blocks.push(...heading('1. Executive summary', 2));
  blocks.push(...body(summary));

  blocks.push(...heading('2. Incident overview', 2));
  const start = inc.start || provenance.start;
  const end = inc.end || provenance.end;
  blocks.push(...labelValue('Status', inc.status));
  blocks.push(...labelValue('Risk score', incident?.score !== undefined ? Number(inc.score).toFixed(4) : undefined));
  blocks.push(...labelValue('Start', isoShort(start)));
  blocks.push(...labelValue('End', isoShort(end)));
  blocks.push(...labelValue('Total alerts', alertTotal(inc)));
  blocks.push(...labelValue('Affected hosts', hosts.length || undefined));
  blocks.push(...labelValue('Attack stages', stages.length || undefined));
  blocks.push(...labelValue('Inference source',
    r.investigation_job_id || provenance.inference_source || inc.inference_source));
  blocks.push(...labelValue('Investigation job', r.investigation_job_id || inc.investigation_job_id));
  blocks.push(...labelValue('Detector',
    provenance.detector_label || provenance.detector || inc.detector_label || inc.detector));
  blocks.push(...labelValue('Report ID', r.report_id));
  blocks.push(...labelValue('Reasoning status', r.reasoning_status));

  if (validation && (validation.total !== undefined || validation.valid !== undefined)) {
    blocks.push(...labelValue('Claims verified',
      `${fmt(validation.valid)} of ${fmt(validation.total)} cited (${fmt(validation.rejected)} rejected)`));
  }

  blocks.push(...heading('3. Attack stages', 2));
  if (!stages.length) {
    blocks.push(...body('No attack stages were returned for this incident.'));
  } else {
    stages.forEach((stage, index) => {
      const stageId = stage.stage_id || stage.id || `stage-${index + 1}`;
      const routeText = [stage.src, stage.dst].filter(Boolean).join(' -> ');
      const ports = stage.port ? ` :${stage.port}` : '';
      const confidence = stage.confidence !== undefined ? ` | confidence ${Number(stage.confidence).toFixed(2)}` : '';
      const observed = stage.observed === undefined ? '' : ` | ${stage.observed ? 'observed evidence' : 'inferred'}`;
      blocks.push(...body(`${index + 1}. ${fmt(stage.tactic)} - ${fmt(stageId)}`, { bold: true, size: 9.5 }));
      blocks.push(...body(`   ${isoShort(stage.start || stage.t0)} - ${isoShort(stage.end || stage.t1)} | ${fmt(routeText)}${ports}${confidence}${observed}`, { size: 9 }));
      const detail = stage.summary || stage.behavior || stage.explanation;
      if (Array.isArray(detail)) {
        if (detail.length) blocks.push(...body(`   ${detail.map(String).join('; ')}`, { size: 9 }));
      } else if (detail) {
        blocks.push(...body(`   ${detail}`, { size: 9 }));
      }
    });
  }

  blocks.push(...heading('4. Affected hosts', 2));
  if (!hosts.length) {
    blocks.push(...body('No hosts were returned for this incident.'));
  } else {
    hosts.forEach(host => {
      const parts = [
        fmt(host.id),
        host.ip && host.ip !== host.id ? `IP ${host.ip}` : '',
        host.role ? `role ${host.role}` : '',
        host.zone ? `zone ${host.zone}` : '',
      ].filter(Boolean);
      blocks.push(...body(`- ${parts.join(' | ')}`, { size: 9 }));
    });
  }

  blocks.push(...recoveryBlocks(inc, r));

  blocks.push(...heading('6. Evidence-linked report claims', 2));
  blocks.push(...body('Every claim below is followed by its stage assignment and the flow evidence it cites.', { size: 9 }));
  if (!sentences.length) {
    blocks.push(...body('No evidence-linked claims were returned for this report.'));
  } else {
    sentences.forEach((sentence, index) => {
      const number = String(index + 1).padStart(2, '0');
      blocks.push(...body(`${number}. ${fmt(sentence.text)}`));
      const evidence = (sentence.evidence_ids ?? []).map(id => `[E:${id}]`).join(' ');
      const meta = [
        sentence.stage_id ? `Stage ${sentence.stage_id}` : '',
        sentence.technique_id ? `Technique ${sentence.technique_id}` : '',
        evidence ? `Evidence ${evidence}` : '',
      ].filter(Boolean).join(' | ');
      if (meta) blocks.push(...body(`   ${meta}`, { size: 8.5 }));
    });
  }

  blocks.push(...heading('7. Verification and rejected claims', 2));
  if (validation && (validation.total !== undefined || validation.valid !== undefined)) {
    blocks.push(...body(`Findings proposed: ${fmt(validation.total)}, accepted: ${fmt(validation.valid)}, rejected: ${fmt(validation.rejected)}.`));
  } else {
    blocks.push(...body('Verification details were not returned.'));
  }
  if (r.reasoning_error) blocks.push(...body(`Reasoning note: ${r.reasoning_error}`));
  if (!rejected.length) {
    blocks.push(...body('No rejected claims were returned.'));
  } else {
    rejected.forEach(item => {
      const claim = item?.finding?.claim ?? item?.claim ?? '';
      const problems = Array.isArray(item?.problems) ? item.problems.join('; ') : '';
      blocks.push(...body(`- Rejected: ${claim}${problems ? ` (${problems})` : ''}`, { size: 9 }));
    });
  }

  blocks.push(...heading('8. Provenance and integrity', 2));
  blocks.push(...labelValue('Input SHA-256', footer.input_sha256 || provenance.input_sha256 || inc.source_sha256));
  blocks.push(...labelValue('Merkle root', footer.merkle_root || provenance.merkle_root || inc.merkle_root));
  blocks.push(...labelValue('Merkle certificate', footer.merkle_certificate));
  blocks.push(...labelValue('Manifest ID', footer.manifest_id));
  blocks.push(...labelValue('ATT&CK version', footer.attack_version));
  blocks.push(...labelValue('Report generated', isoShort(new Date().toISOString())));

  blocks.push(...heading('Retrieval notice', 2));
  blocks.push(...body('ATT&CK candidate mappings in the source report are retrieval inferences, not confirmed adversary behaviour. Retrieval similarity is not confidence.', { size: 9 }));

  return blocks;
}

function paginate(blocks) {
  const pages = [];
  let lines = [];
  let y = PAGE_HEIGHT - MARGIN;
  for (const block of blocks) {
    if (y - block.gap < BOTTOM) {
      pages.push(lines);
      lines = [];
      y = PAGE_HEIGHT - MARGIN;
    }
    lines.push({ ...block, y });
    y -= block.gap;
  }
  pages.push(lines);
  return pages.length ? pages : [[]];
}

function contentStream(lines, pageNumber, pageCount) {
  const parts = [];
  for (const line of lines) {
    if (!line.text) continue;
    const font = line.bold ? FONTS.bold : FONTS.body;
    parts.push(`BT /${font} ${line.size.toFixed(2)} Tf 1 0 0 1 ${MARGIN.toFixed(2)} ${line.y.toFixed(2)} Tm (${escapePdf(line.text)}) Tj ET`);
  }
  parts.push(`BT /${FONTS.body} 8 Tf 1 0 0 1 ${MARGIN.toFixed(2)} 30 Tm (EviGraph report - page ${pageNumber} of ${pageCount}) Tj ET`);
  return parts.join('\n');
}

export function createReportPdf(incident, report) {
  if (!report || typeof report !== 'object' || !Object.keys(report).length) {
    throw new Error('Cannot export empty report');
  }
  const pages = paginate(reportBlocks(incident, report));
  const objects = [];

  // 1: catalog, 2: pages, 3/4: fonts, then page + content objects per page.
  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  const pageObjectNumbers = pages.map((_, index) => 5 + index * 2);
  objects.push(`<< /Type /Pages /Kids [${pageObjectNumbers.map(n => `${n} 0 R`).join(' ')}] /Count ${pages.length} >>`);
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');

  pages.forEach((lines, index) => {
    const pageNumber = index + 1;
    const stream = contentStream(lines, pageNumber, pages.length);
    const contentObjectNumber = 6 + index * 2;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] `
      + `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjectNumber} 0 R >>`
    );
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  let output = '%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(output.length);
    output += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });

  const xrefOffset = output.length;
  output += `xref\n0 ${objects.length + 1}\n`;
  output += '0000000000 65535 f \n';
  for (let i = 1; i < offsets.length; i += 1) {
    output += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  output += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

  const bytes = new Uint8Array(output.length);
  for (let i = 0; i < output.length; i += 1) bytes[i] = output.charCodeAt(i) & 0xff;
  return bytes;
}
