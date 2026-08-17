/**
 * Temporal workflow introspection — status queries and termination, scoped to
 * this checkout's Temporal instance. Runs `temporal` via `docker exec` against
 * the instance's own container, since the bundled CLI image already has it.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { temporalContainerName } from './docker.js';

export type WorkflowStatus = 'running' | 'completed' | 'failed' | 'timed_out' | 'terminated' | 'canceled' | 'unknown';

export interface WorkflowStatusResult {
  status: WorkflowStatus;
  failureMessage?: string;
}

const STATUS_MAP: Record<string, WorkflowStatus> = {
  WORKFLOW_EXECUTION_STATUS_RUNNING: 'running',
  WORKFLOW_EXECUTION_STATUS_COMPLETED: 'completed',
  WORKFLOW_EXECUTION_STATUS_FAILED: 'failed',
  WORKFLOW_EXECUTION_STATUS_TIMED_OUT: 'timed_out',
  WORKFLOW_EXECUTION_STATUS_TERMINATED: 'terminated',
  WORKFLOW_EXECUTION_STATUS_CANCELED: 'canceled',
};

/**
 * Reads the workflow ID Shannon recorded for a workspace. Fresh runs record
 * `originalWorkflowId`; resumed runs append to `resumeAttempts` and the latest
 * entry is the live one.
 */
export function readWorkflowId(workspacesDir: string, workspace: string): string | null {
  const sessionPath = path.join(workspacesDir, workspace, 'session.json');
  if (!fs.existsSync(sessionPath)) return null;
  try {
    const session = JSON.parse(fs.readFileSync(sessionPath, 'utf-8'));
    const resumeAttempts: { workflowId: string }[] = session.session?.resumeAttempts ?? [];
    return resumeAttempts.at(-1)?.workflowId ?? session.session?.originalWorkflowId ?? null;
  } catch {
    return null;
  }
}

/**
 * Queries Temporal directly for a workflow's real status — the source of
 * truth for whether a run has actually failed, rather than inferring it from
 * side effects (e.g. a deliverable file never appearing).
 */
export function describeWorkflow(instanceId: string, workflowId: string): WorkflowStatusResult {
  let raw: string;
  try {
    raw = execFileSync(
      'docker',
      [
        'exec',
        temporalContainerName(instanceId),
        'temporal',
        'workflow',
        'describe',
        '--address',
        'localhost:7233',
        '--workflow-id',
        workflowId,
        '-o',
        'json',
      ],
      { stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf-8' },
    );
  } catch {
    return { status: 'unknown' };
  }

  try {
    const parsed = JSON.parse(raw);
    const status = STATUS_MAP[parsed.workflowExecutionInfo?.status] ?? 'unknown';
    const failure = parsed.closeEvent?.workflowExecutionFailedEventAttributes?.failure;
    const failureMessage: string | undefined = failure ? (failure.cause?.message ?? failure.message) : undefined;
    return { status, ...(failureMessage && { failureMessage }) };
  } catch {
    return { status: 'unknown' };
  }
}

/**
 * Best-effort: tell Temporal a workflow is done. Without this, a workflow
 * whose worker died (container stopped, crashed, etc.) sits at RUNNING
 * forever, endlessly rescheduling activities against a task queue nobody is
 * listening on (observed: an activity still retrying — attempt 2 of a
 * maximum 50 — days after its worker container was stopped).
 */
export function terminateWorkflow(instanceId: string, workflowId: string, reason: string): void {
  try {
    execFileSync(
      'docker',
      [
        'exec',
        temporalContainerName(instanceId),
        'temporal',
        'workflow',
        'terminate',
        '--address',
        'localhost:7233',
        '--workflow-id',
        workflowId,
        '--reason',
        reason,
      ],
      { stdio: 'ignore' },
    );
  } catch {
    // Best-effort — workflow may already be closed, or Temporal may be unreachable.
  }
}
