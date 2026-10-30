/**
 * Original finding details for rescans.
 *
 * The rescan context only carries finding IDs, so agents had to find each
 * finding's description in the seeded queues themselves — and sometimes
 * didn't, verifying an unrelated issue under the same ID. setupRescanWorkspace
 * snapshots the original queue entries here, and every rescan prompt gets them
 * inline.
 */

import { fs, path } from 'zx';

export const ORIGINAL_FINDINGS_FILE = 'rescan_original_findings.json';

const MAX_ENTRY_CHARS = 6_000;

export interface OriginalFinding {
  readonly vulnType: string;
  readonly entry: { ID: string; [key: string]: unknown };
}

/** Snapshot the original queue entries; the vuln agents rewrite the queues themselves. */
export async function writeOriginalFindings(deliverablesPath: string, findings: OriginalFinding[]): Promise<void> {
  await fs.writeFile(path.join(deliverablesPath, ORIGINAL_FINDINGS_FILE), JSON.stringify(findings, null, 2), 'utf8');
}

/** Append the original finding details to the rescan context, when a snapshot exists. */
export async function withOriginalFindings(rescanContext: string, deliverablesPath: string): Promise<string> {
  const file = path.join(deliverablesPath, ORIGINAL_FINDINGS_FILE);
  if (!(await fs.pathExists(file))) {
    return rescanContext;
  }

  let findings: OriginalFinding[];
  try {
    findings = JSON.parse(await fs.readFile(file, 'utf8')) as OriginalFinding[];
  } catch {
    return rescanContext;
  }
  if (findings.length === 0) {
    return rescanContext;
  }

  const lines: string[] = [
    rescanContext,
    'ORIGINAL FINDINGS',
    '=================',
    'These are the findings exactly as the prior scan recorded them. Verify THESE issues —',
    'the vulnerable location, sink and missing defense described here — and nothing else.',
    'Do not substitute a different issue that happens to share an ID or a category.',
    '',
  ];
  for (const f of findings) {
    let detail = JSON.stringify(f.entry, null, 2);
    if (detail.length > MAX_ENTRY_CHARS) {
      detail = `${detail.slice(0, MAX_ENTRY_CHARS)}\n… (truncated)`;
    }
    lines.push(`[${f.entry.ID}] (${f.vulnType})`);
    lines.push(detail);
    lines.push('');
  }
  return lines.join('\n');
}
