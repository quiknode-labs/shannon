/**
 * `shannon status` command — show running workers and Temporal health.
 */

import { getInstanceId, isTemporalReady, listRunningWorkers } from '../docker.js';

export function status(): void {
  const instanceId = getInstanceId();

  // 1. Temporal health
  const temporalUp = isTemporalReady(instanceId);
  console.log(`Temporal: ${temporalUp ? 'running' : 'not running'}`);
  if (temporalUp) {
    console.log('  Web UI: http://localhost:8233');
  }
  console.log('');

  // 2. Running workers
  const workers = listRunningWorkers(instanceId);
  if (workers) {
    console.log('Workers:');
    console.log(workers);
  } else {
    console.log('Workers: none running');
  }
}
