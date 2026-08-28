/**
 * `shannon rescan` command — re-verify specific findings after developer fixes.
 *
 * Reads the source workspace URL from session.json so Coral does not need to
 * supply it separately. Creates a new workspace named
 * `{source}-rescan-{n}` and runs the targeted re-verification pipeline.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ensureImage, ensureInfra, getInstanceId, randomSuffix, spawnWorker, workerNamePrefix } from '../docker.js';
import { buildEnvFlags, loadEnv, validateCredentials } from '../env.js';
import { getCredentialsPath, getWorkspacesDir, initHome } from '../home.js';
import { isLocal } from '../mode.js';
import { resolveRepo } from '../paths.js';

export interface RescanArgs {
  sourceWorkspace: string;
  repo: string;
  findingsFile: string;
  output?: string;
  skipGitCheck: boolean;
  debug: boolean;
  version: string;
}

/** Return the next unused rescan index for a given source workspace. */
function nextRescanIndex(workspacesDir: string, sourceWorkspace: string): number {
  let n = 1;
  while (fs.existsSync(path.join(workspacesDir, `${sourceWorkspace}-rescan-${n}`))) {
    n++;
  }
  return n;
}

export async function rescan(args: RescanArgs): Promise<void> {
  // 1. Initialize state directories and load env
  initHome();
  loadEnv();

  // 2. Validate credentials
  const creds = validateCredentials();
  if (!creds.valid) {
    console.error(`ERROR: ${creds.error}`);
    process.exit(1);
  }

  // 3. Read source workspace URL from session.json
  const workspacesDir = getWorkspacesDir();
  const sessionPath = path.join(workspacesDir, args.sourceWorkspace, 'session.json');
  if (!fs.existsSync(sessionPath)) {
    console.error(`ERROR: Source workspace not found: ${args.sourceWorkspace}`);
    console.error(`Expected: ${sessionPath}`);
    process.exit(1);
  }

  let webUrl: string;
  try {
    const session = JSON.parse(fs.readFileSync(sessionPath, 'utf-8')) as { session: { webUrl: string } };
    webUrl = session.session.webUrl;
  } catch {
    console.error(`ERROR: Could not read session.json for workspace ${args.sourceWorkspace}`);
    process.exit(1);
  }

  // 4. Read and validate findings file
  if (!fs.existsSync(args.findingsFile)) {
    console.error(`ERROR: Findings file not found: ${args.findingsFile}`);
    process.exit(1);
  }

  let findingsJson: string;
  try {
    findingsJson = fs.readFileSync(args.findingsFile, 'utf-8').trim();
    JSON.parse(findingsJson); // validate
  } catch {
    console.error('ERROR: Findings file must contain valid JSON');
    process.exit(1);
  }

  // 5. Resolve paths
  const repo = resolveRepo(args.repo);
  const outputDir = args.output ? path.resolve(args.output) : undefined;
  if (outputDir) fs.mkdirSync(outputDir, { recursive: true });

  // 6. Generate rescan workspace name and create directories
  const rescanWorkspace = `${args.sourceWorkspace}-rescan-${nextRescanIndex(workspacesDir, args.sourceWorkspace)}`;
  const workspacePath = path.join(workspacesDir, rescanWorkspace);
  fs.mkdirSync(workspacePath, { recursive: true });
  fs.chmodSync(workspacePath, 0o777);
  for (const dir of ['deliverables', 'scratchpad', '.playwright-cli', '.playwright']) {
    const dirPath = path.join(workspacePath, dir);
    fs.mkdirSync(dirPath, { recursive: true });
    fs.chmodSync(dirPath, 0o777);
  }

  // 7. Pre-create overlay mount points (:ro mounts can't auto-create them)
  const shannonDir = path.join(repo.hostPath, '.shannon');
  for (const dir of ['deliverables', 'scratchpad', '.playwright-cli']) {
    fs.mkdirSync(path.join(shannonDir, dir), { recursive: true });
  }
  fs.mkdirSync(path.join(repo.hostPath, '.playwright'), { recursive: true });

  // 8. Ensure image and start infra
  const instanceId = getInstanceId();
  ensureImage(args.version);
  await ensureInfra(instanceId);

  const credentialsPath = getCredentialsPath();
  const hasCredentials = fs.existsSync(credentialsPath);
  if (hasCredentials) {
    process.env.GOOGLE_APPLICATION_CREDENTIALS = '/app/credentials/google-sa-key.json';
  }

  // 9. Resolve prompts directory (local mode only)
  const promptsDir = isLocal()
    ? path.join(process.env.SHANNON_REPO_DIR ?? process.cwd(), 'apps/worker/prompts')
    : undefined;

  // 10. Write findings payload into the workspace so the worker reads it from disk
  // (avoids passing large/special-character JSON through Docker's arg vector)
  const payloadPath = path.join(workspacePath, 'rescan-payload.json');
  fs.writeFileSync(payloadPath, findingsJson, 'utf-8');
  const containerPayloadPath = `/app/workspaces/${rescanWorkspace}/rescan-payload.json`;

  // 11. Spawn worker container
  const suffix = randomSuffix();
  const taskQueue = `shannon-${suffix}`;
  const containerName = `${workerNamePrefix(instanceId)}${suffix}`;

  console.log(`\n  Source workspace: ${args.sourceWorkspace}`);
  console.log(`  Rescan workspace: ${rescanWorkspace}`);
  console.log(`  Target:           ${webUrl}`);
  console.log(`  Repository:       ${repo.hostPath}\n`);

  const proc = spawnWorker({
    version: args.version,
    url: webUrl,
    repo,
    workspacesDir,
    taskQueue,
    containerName,
    instanceId,
    envFlags: buildEnvFlags(instanceId),
    workspace: rescanWorkspace,
    rescanFindingsFile: containerPayloadPath,
    sourceWorkspace: args.sourceWorkspace,
    ...(hasCredentials && { credentials: credentialsPath }),
    ...(promptsDir && { promptsDir }),
    ...(outputDir && { outputDir }),
    ...(args.skipGitCheck && { skipGitCheck: true }),
    ...(args.debug && { debug: true }),
  });

  const dockerExitCode = await new Promise<number>((resolve) => {
    proc.once('exit', (code) => resolve(code ?? 1));
    proc.once('error', (err) => {
      console.error(`Failed to start worker: ${err.message}`);
      resolve(1);
    });
  });

  if (dockerExitCode !== 0) {
    process.exit(1);
  }

  // 11. Poll for workflow registration
  const sessionJsonPath = path.join(workspacesDir, rescanWorkspace, 'session.json');
  process.stdout.write('Waiting for rescan workflow to start...');
  let workflowId = '';
  let started = false;
  let attempts = 0;

  const pollInterval = setInterval(() => {
    attempts++;
    if (attempts > 60) {
      clearInterval(pollInterval);
      process.stdout.write('\n');
      console.error('Timeout waiting for workflow to start');
      process.exit(1);
    }

    try {
      const session = JSON.parse(fs.readFileSync(sessionJsonPath, 'utf-8'));
      if (session.session?.originalWorkflowId) {
        clearInterval(pollInterval);
        started = true;
        workflowId = session.session.originalWorkflowId;
        process.stdout.write('\r\x1b[K');
        const logsCmd = isLocal()
          ? `./shannon logs ${rescanWorkspace}`
          : `npx @keygraph/shannon logs ${rescanWorkspace}`;
        console.log(`  Workflow:   ${workflowId}`);
        console.log(`  Logs:       ${logsCmd}`);
        console.log(`  Output:     ${workspacePath}/\n`);
      }
    } catch {
      // session.json not yet written
    }
    process.stdout.write('.');
  }, 2000);

  let cleaned = false;
  const cleanup = (): void => {
    if (cleaned || started) return;
    cleaned = true;
    clearInterval(pollInterval);
    console.log(`\nStopping worker ${containerName}...`);
    try {
      execFileSync('docker', ['stop', containerName], { stdio: 'pipe' });
    } catch {
      // Container may have already exited
    }
  };

  process.on('SIGINT', () => {
    cleanup();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });
  process.on('exit', cleanup);
}
