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

    let remainingIds = new Set<string>();
    if (queueExists) {
      try {
        const doc = (await fs.readJson(queuePath)) as QueueDoc;
        remainingIds = new Set((doc.vulnerabilities ?? []).map((v) => v.ID));
      } catch {
        // treat as inconclusive on parse failure
      }
    }

    for (const findingId of ids) {
      let verdict: RescanVerdict;
      let evidence: string;

      if (!queueExists) {
        verdict = 'INCONCLUSIVE';
        evidence = `Re-analysis queue for ${vulnType} was not produced. Manual review required.`;
      } else if (remainingIds.has(findingId)) {
        verdict = 'STILL_VULNERABLE';
        evidence = `Finding ${findingId} was re-identified in the post-fix analysis queue. See exploitation evidence for proof.`;
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
