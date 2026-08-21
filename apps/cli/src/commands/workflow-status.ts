/**
 * `shannon workflow-status` command — query a workspace's live Temporal
 * status. Prints a single-line JSON object so it's easy for other tools
 * (e.g. Coral) to parse; run it directly for a quick human check too.
 */

import { getInstanceId } from '../docker.js';
import { getWorkspacesDir } from '../home.js';
import { describeWorkflow, readWorkflowId } from '../temporal.js';

export function workflowStatus(workspace: string): void {
  const workflowId = readWorkflowId(getWorkspacesDir(), workspace);
  if (!workflowId) {
    console.log(
      JSON.stringify({ status: 'unknown', reason: 'no session.json / workflow ID found for this workspace' }),
    );
    return;
  }

  const result = describeWorkflow(getInstanceId(), workflowId);
  console.log(JSON.stringify({ workflowId, ...result }));
}
