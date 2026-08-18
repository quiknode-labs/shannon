// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Generates machine-readable findings index files from exploitation queue JSON.
 *
 * findings-index.json — emitted at the end of a normal scan. Gives consumers
 * (e.g. Coral) the stable findingId per finding so they can submit targeted
 * rescans without parsing markdown.
 *
 * rescan-findings-index.json — emitted at the end of a rescan. Contains a
 * verdict per submitted finding derived by comparing the post-rescan queue
 * against the original finding IDs: present → STILL_VULNERABLE, gone → FIXED,
 * queue missing → INCONCLUSIVE.
 */

import { fs, path } from 'zx';
import type { ActivityLogger } from '../types/activity-logger.js';
import type { VulnClass } from '../types/config.js';

// === Types ===

export interface FindingIndexEntry {
  findingId: string;
  vulnType: VulnClass;
  confidence: string;
  externally_exploitable: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  codeLocation: string;
}

export interface FindingsIndex {
  scanId: string;
  workspace: string;
  findings: FindingIndexEntry[];
}

export type RescanVerdict = 'FIXED' | 'STILL_VULNERABLE' | 'INCONCLUSIVE';

export interface RescanFindingResult {
  findingId: string;
  vulnType: VulnClass;
  verdict: RescanVerdict;
  evidence: string;
}

export interface RescanFindingsIndex {
  sourceWorkspace: string;
  rescanWorkspace: string;
  findings: RescanFindingResult[];
}

// === Internal helpers ===

interface RawFinding {
  ID: string;
  vulnerability_type: string;
  confidence: string;
  externally_exploitable: boolean;
  // Injection / XSS
  path?: string;
  sink_call?: string;
  sink_function?: string;
  // Auth / SSRF / Authz
  vulnerable_code_location?: string;
  source_endpoint?: string;
  endpoint?: string;
  [key: string]: unknown;
}

interface QueueDoc {
  vulnerabilities?: RawFinding[];
}

const QUEUE_FILES: Record<VulnClass, string> = {
  injection: 'injection_exploitation_queue.json',
  xss: 'xss_exploitation_queue.json',
  auth: 'auth_exploitation_queue.json',
  ssrf: 'ssrf_exploitation_queue.json',
  authz: 'authz_exploitation_queue.json',
};

/**
 * Pulls the agent's actual reasoning out of a still-vulnerable queue entry
 * instead of a generic "was re-identified" stub, so security can see whether
 * (and how) a recheck instruction was actually applied without opening the
 * full rescan report. Field names differ by vuln class (injection/xss write
 * mismatch_reason/witness_payload; auth/ssrf/authz write reason/guard_evidence/
 * minimal_witness) so both are tried; falls back to null if neither is present.
 */
function extractQueueEvidence(f: RawFinding): string | null {
  const reason = (f.reason ?? f.mismatch_reason) as string | undefined;
  const guard = f.guard_evidence as string | undefined;
  const witness = (f.minimal_witness ?? f.witness_payload) as string | undefined;

  const parts: string[] = [];
  if (reason) parts.push(reason);
  if (guard && guard !== reason) parts.push(`Guard: ${guard}`);
  if (witness) parts.push(`Reproduce: ${witness}`);
  return parts.length ? parts.join(' ') : null;
}

const REPORT_VERDICT_HEADER = /^###\s+([A-Z]+-VULN-\d+)\s*[—-]+\s*(FIXED|STILL_VULNERABLE|INCONCLUSIVE)\b/i;
const REPORT_EVIDENCE_BLOCK = /\*\*Evidence:\*\*\s*\n([\s\S]*?)(?:\n---|\n##|$)/i;

/**
 * Parses the report-rescan agent's own per-finding verdicts out of the final
 * rescan_verification_report.md. This is the authoritative source when
 * present: the report agent re-reads current source and reconciles evidence
 * across every exploit-rescan agent, whereas the exploitation-queue-diff
 * fallback below only holds up if an exploit agent reliably deletes its own
 * queue entry the moment it confirms a fix — which it does not always do,
 * so relying on the queue alone can report STILL_VULNERABLE for a finding
 * the report already concluded is FIXED.
 */
function parseReportVerdicts(reportMd: string): Map<string, { verdict: RescanVerdict; evidence: string }> {
  const results = new Map<string, { verdict: RescanVerdict; evidence: string }>();
  const sections = reportMd.split(/\n(?=###\s+[A-Z]+-VULN-\d+\s)/);
  for (const section of sections) {
    const header = REPORT_VERDICT_HEADER.exec(section);
    if (!header?.[1] || !header[2]) continue;
    const findingId = header[1];
    const verdict = header[2].toUpperCase() as RescanVerdict;
    const evidenceMatch = REPORT_EVIDENCE_BLOCK.exec(section);
    const evidence = evidenceMatch?.[1]
      ? evidenceMatch[1].trim().slice(0, 2000)
      : `Re-analysis verdict: ${verdict} — see full rescan report for detail.`;
    results.set(findingId, { verdict, evidence });
  }
  return results;
}

function deriveSeverity(confidence: string, externallyExploitable: boolean): FindingIndexEntry['severity'] {
  const conf = confidence.toLowerCase();
  if (externallyExploitable) {
    if (conf === 'high') return 'critical';
    if (conf === 'medium') return 'high';
    return 'medium';
  }
  if (conf === 'high') return 'medium';
  return 'low';
}

function extractCodeLocation(finding: RawFinding, vulnType: VulnClass): string {
  switch (vulnType) {
    case 'injection':
      return finding.path ?? finding.sink_call ?? '';
    case 'xss':
      return finding.path ?? finding.sink_function ?? '';
    case 'auth':
    case 'ssrf':
      return finding.vulnerable_code_location ?? finding.source_endpoint ?? '';
    case 'authz':
      return finding.vulnerable_code_location ?? finding.endpoint ?? '';
  }
}

async function readQueue(dir: string, vulnType: VulnClass): Promise<RawFinding[]> {
  const queuePath = path.join(dir, QUEUE_FILES[vulnType]);
  if (!(await fs.pathExists(queuePath))) return [];
  try {
    const doc = (await fs.readJson(queuePath)) as QueueDoc;
    return doc.vulnerabilities ?? [];
  } catch {
    return [];
  }
}

// === Public API ===

/**
 * Generate findings-index.json from all exploitation queue files.
 * Written to `{deliverablesDir}/findings-index.json`.
 */
export async function generateFindingsIndex(
  deliverablesDir: string,
  sessionId: string,
  logger: ActivityLogger,
): Promise<void> {
  const findings: FindingIndexEntry[] = [];

  for (const vulnType of Object.keys(QUEUE_FILES) as VulnClass[]) {
    const raw = await readQueue(deliverablesDir, vulnType);
    for (const f of raw) {
      findings.push({
        findingId: f.ID,
        vulnType,
        confidence: f.confidence,
        externally_exploitable: f.externally_exploitable,
        severity: deriveSeverity(f.confidence, f.externally_exploitable),
        title: f.vulnerability_type,
        codeLocation: extractCodeLocation(f, vulnType),
      });
    }
  }

  const index: FindingsIndex = { scanId: sessionId, workspace: sessionId, findings };
  const outPath = path.join(deliverablesDir, 'findings-index.json');
  await fs.writeFile(outPath, JSON.stringify(index, null, 2), 'utf8');
  logger.info(`findings-index.json: ${findings.length} finding(s) written`);
}

/**
 * Generate rescan-findings-index.json by comparing post-rescan queue files
 * against the original submitted finding IDs.
 *
 * Verdict logic:
 *   - Queue file exists and still contains the finding ID → STILL_VULNERABLE
 *   - Queue file exists but finding ID is gone → FIXED
 *   - Queue file missing for this class → INCONCLUSIVE
 */
export async function generateRescanFindingsIndex(
  deliverablesDir: string,
  sourceWorkspace: string,
  rescanWorkspace: string,
  rescanFindings: ReadonlyArray<{ findingId: string; vulnType: string }>,
  logger: ActivityLogger,
): Promise<void> {
  const results: RescanFindingResult[] = [];

  const reportPath = path.join(deliverablesDir, 'rescan_verification_report.md');
  let reportVerdicts = new Map<string, { verdict: RescanVerdict; evidence: string }>();
  if (await fs.pathExists(reportPath)) {
    try {
      reportVerdicts = parseReportVerdicts(await fs.readFile(reportPath, 'utf8'));
    } catch {
      // fall through to queue-diff for every finding
    }
  }

  // Group submitted findings by vulnType for efficient queue reads
  const byType = new Map<VulnClass, string[]>();
  for (const f of rescanFindings) {
    const cls = f.vulnType as VulnClass;
    if (!byType.has(cls)) byType.set(cls, []);
    byType.get(cls)!.push(f.findingId);
  }

  for (const [vulnType, ids] of byType) {
    const queuePath = path.join(deliverablesDir, QUEUE_FILES[vulnType]);
    const queueExists = await fs.pathExists(queuePath);

    let remaining = new Map<string, RawFinding>();
    if (queueExists) {
      try {
        const doc = (await fs.readJson(queuePath)) as QueueDoc;
        remaining = new Map((doc.vulnerabilities ?? []).map((v) => [v.ID, v]));
      } catch {
        // treat as inconclusive on parse failure
      }
    }

    for (const findingId of ids) {
      const fromReport = reportVerdicts.get(findingId);
      if (fromReport) {
        results.push({ findingId, vulnType, verdict: fromReport.verdict, evidence: fromReport.evidence });
        continue;
      }

      let verdict: RescanVerdict;
      let evidence: string;

      if (!queueExists) {
        verdict = 'INCONCLUSIVE';
        evidence = `Re-analysis queue for ${vulnType} was not produced. Manual review required.`;
      } else if (remaining.has(findingId)) {
        verdict = 'STILL_VULNERABLE';
        evidence =
          extractQueueEvidence(remaining.get(findingId) as RawFinding) ??
          `Finding ${findingId} was re-identified in the post-fix analysis queue. See exploitation evidence for proof.`;
      } else {
        verdict = 'FIXED';
        evidence = `Finding ${findingId} was not re-identified after the developer's fix. The vulnerability appears to be resolved.`;
      }

      results.push({ findingId, vulnType, verdict, evidence });
    }
  }

  const index: RescanFindingsIndex = { sourceWorkspace, rescanWorkspace, findings: results };
  const outPath = path.join(deliverablesDir, 'rescan-findings-index.json');
  await fs.writeFile(outPath, JSON.stringify(index, null, 2), 'utf8');

  const fixed = results.filter((r) => r.verdict === 'FIXED').length;
  const still = results.filter((r) => r.verdict === 'STILL_VULNERABLE').length;
  const inconclusive = results.filter((r) => r.verdict === 'INCONCLUSIVE').length;
  logger.info(`rescan-findings-index.json: ${fixed} FIXED, ${still} STILL_VULNERABLE, ${inconclusive} INCONCLUSIVE`);
}
