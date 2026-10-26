import { test } from 'node:test';
import assert from 'node:assert/strict';
import { containmentHtml } from '../src/ui/dashboard.js';

test('containmentHtml renders loading state', () => {
  const html = containmentHtml(null, 'loading');
  assert.match(html, /inline-loading/);
  assert.match(html, /Synthesizing surgical containment rules/);
});

test('containmentHtml renders error state with retry button', () => {
  const html = containmentHtml(null, 'error');
  assert.match(html, /report-error/);
  assert.match(html, /Containment recommendations unavailable/);
  assert.match(html, /data-retry-containment/);
});

test('containmentHtml displays detailed error message when errorMsg is supplied', () => {
  const html = containmentHtml(null, 'error', '404 Not Found for /incidents/INC-0009/countermeasures');
  assert.match(html, /404 Not Found/);
  assert.match(html, /data-retry-containment/);
});

test('containmentHtml renders empty state when no actions available', () => {
  const html = containmentHtml({ actions: [] }, 'loaded');
  assert.match(html, /empty-state/);
  assert.match(html, /No containment actions required or available/);
});

test('containmentHtml displays advisory notice banner and rules with blast radius and commands', () => {
  const sampleData = {
    incident_id: 'INC-0001',
    status: 'advisory',
    advisory_notice: 'Recommendations are strictly advisory. Commands must be manually reviewed and executed by authorized SOC operators.',
    containment_actions_count: 1,
    actions: [
      {
        rule_id: 'RULE-INC-0001-01',
        action_tier: 'Tier 1: Surgical Ingress Edge Severance',
        action_type: 'EDGE_DROP',
        target_attacker: '192.168.10.19',
        target_victim: '192.168.10.50',
        destination_port: 80,
        protocol: 'TCP',
        rationale: 'Blocks malicious ingress traffic from attacker.',
        victim_blast_radius: {
          blast_radius_score: 0.22,
          impact_level: 'LOW_COLLATERAL_IMPACT',
          recommended_approach: 'FULL_HOST_QUARANTINE_PERMISSIBLE',
        },
        synthesized_commands: {
          linux_iptables: 'iptables -I INPUT -s 192.168.10.19 -d 192.168.10.50 -p tcp --dport 80 -j DROP',
          windows_powershell: 'New-NetFirewallRule -DisplayName "EviGraph-Surgical-RULE-01" -Action Block',
        },
        verification_guidance: {
          linux_iptables: 'iptables -C INPUT -s 192.168.10.19 -d 192.168.10.50 -p tcp --dport 80 -j DROP 2>/dev/null',
        },
        rollback_guidance: {
          linux_iptables: 'iptables -D INPUT -s 192.168.10.19 -d 192.168.10.50 -p tcp --dport 80 -j DROP',
        },
      },
    ],
  };

  const html = containmentHtml(sampleData, 'loaded');

  // Must clearly state Advisory and operator authorization requirement
  assert.match(html, /Advisory Recommendations Only/);
  assert.match(html, /Commands must be manually reviewed/);

  // Must contain rule ID and blast radius
  assert.match(html, /RULE-INC-0001-01/);
  assert.match(html, /Blast: 0\.22/);
  assert.match(html, /LOW_COLLATERAL_IMPACT/);

  // Must render synthesized commands
  assert.match(html, /iptables -I INPUT/);
  assert.match(html, /New-NetFirewallRule/);

  // Must render rollback guidance
  assert.match(html, /Verification &amp; Rollback Guidance/);
  assert.match(html, /iptables -D INPUT/);
});

test('containmentHtml escapes malicious strings in rationale and commands', () => {
  const xssData = {
    incident_id: 'INC-XSS',
    advisory_notice: '<script>alert("xss")</script>',
    actions: [
      {
        rule_id: '<b id="evil">RULE</b>',
        rationale: '<img src=x onerror=alert(1)>',
        target_attacker: '10.0.0.1',
        target_victim: '10.0.0.2',
        destination_port: 443,
        synthesized_commands: {
          linux_iptables: 'iptables <script>',
        },
      },
    ],
  };

  const html = containmentHtml(xssData, 'loaded');
  assert.doesNotMatch(html, /<script>alert/);
  assert.doesNotMatch(html, /<img src=x onerror=alert\(1\)>/);
  assert.match(html, /&lt;script&gt;alert/);
});
