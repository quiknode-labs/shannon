/**
 * `shannon stop` command — stop workers and infrastructure.
 */

import * as p from '@clack/prompts';
import { getInstanceId, stopInfra, stopWorker, stopWorkers } from '../docker.js';
import { getWorkspacesDir } from '../home.js';
import { readWorkflowId, terminateWorkflow } from '../temporal.js';

export async function stop(clean: boolean, workspace?: string): Promise<void> {
  // Scoped stop: only this one workspace's worker, never infra or other
  // concurrently-running scans.
  if (workspace) {
    const instanceId = getInstanceId();

    // Stopping the container alone leaves the workflow at RUNNING in Temporal
    // forever — it just keeps rescheduling activities against a task queue
    // nobody is listening on. Tell Temporal explicitly first.
    const workflowId = readWorkflowId(getWorkspacesDir(), workspace);
    if (workflowId) terminateWorkflow(instanceId, workflowId, 'Stopped via shannon stop');

    const stopped = stopWorker(instanceId, workspace);
    if (!stopped) console.error(`No running worker found for workspace "${workspace}".`);
    return;
  }

  if (clean) {
    const confirmed = await p.confirm({
      message: 'This will stop all running scans and remove the Temporal data. Continue?',
    });
    if (p.isCancel(confirmed) || !confirmed) {
      p.cancel('Aborted.');
      process.exit(0);
    }
  }

  const instanceId = getInstanceId();
  stopWorkers(instanceId);
  stopInfra(clean, instanceId);
}
