# Security Policy

EviGraph processes sensitive network telemetry and produces evidence artifacts intended for incident response, insurance, and legal review. Treat every output as **potentially discoverable**.

## Reporting a vulnerability

Do **not** open a public issue for security defects. Report to the maintainers through your private channel with:

- affected version/commit,
- reproduction steps,
- impact assessment,
- whether evidence integrity or confidentiality is affected.

Acknowledge within 3 business days; provide a remediation timeline after triage.

## Non-negotiable design rules

1. **Never fabricate assurance.** Missing proofs, hashes, verdicts, or artifacts must surface as `UNVERIFIED`, `404`, `INADMISSIBLE`, or an explicit error — never a green check.
2. **Fail closed.** Verification requires an expected root, a known scheme, and a bound `tree_size`/`leaf_index`.
3. **Separate keys from evidence.** Disclosure secrets, signing keys, and API keys are never serialized into certificates or shipped with bundles.
4. **No wildcard trust.** No `Access-Control-Allow-Origin: *` on forensic endpoints; no unauthenticated non-loopback bind.
5. **Treat telemetry as hostile.** Log fields, hostnames, and labels can contain prompt-injection payloads. They are data, never instructions.
6. **No autonomous containment.** Firewall/ACL plans require human approval, syntax validation, and a rollback plan.
7. **Least data.** Redact topology and service fingerprints by default; keep redaction keys under KMS/secret-manager custody.

## Local development

```powershell
copy .env.server.example .env
# set EVIGRAPH_API_KEY for anything beyond loopback
pip install -e ".[ml,api,agent,dev]"
python main.py --agent
python -m api.server
```

The server refuses to bind a non-loopback interface without `EVIGRAPH_API_KEY`.

## Supported versions

Security fixes land on the main branch. Pin a commit or release for production deployments and re-run `python -m unittest discover -s tests` plus the audit checklist in `docs/SECURITY_AUDIT.md` before rollout.
