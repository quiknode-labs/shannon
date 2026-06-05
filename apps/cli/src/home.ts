/**
 * Shannon state directory management.
 *
 * Local mode (cloned repo): uses ./workspaces/, ./credentials/
 * NPX mode: uses ~/.shannon/workspaces/, ~/.shannon/
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getMode } from './mode.js';

const SHANNON_HOME = path.join(os.homedir(), '.shannon');

/** Repo root directory — set by the ./shannon entry point so paths resolve correctly regardless of caller CWD. */
function getRepoDir(): string {
  return process.env.SHANNON_REPO_DIR ?? process.cwd();
}

export function getConfigFile(): string {
  return path.join(SHANNON_HOME, 'config.toml');
}

export function getWorkspacesDir(): string {
  if (process.env.SHANNON_WORKSPACES_DIR) {
    return path.resolve(process.env.SHANNON_WORKSPACES_DIR);
  }
  return getMode() === 'local'
    ? path.join(getRepoDir(), 'workspaces')
    : path.join(SHANNON_HOME, 'workspaces');
}

/**
 * Resolve the Vertex credentials file path.
 *
 * Checks GOOGLE_APPLICATION_CREDENTIALS env var first (may be set by TOML resolver),
 * then falls back to mode-appropriate default location.
 */
export function getCredentialsPath(): string {
  const envPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (envPath && fs.existsSync(envPath)) return path.resolve(envPath);

  if (getMode() === 'local') {
    return path.join(getRepoDir(), 'credentials', 'google-sa-key.json');
  }

  return path.join(SHANNON_HOME, 'google-sa-key.json');
}

/**
 * Initialize state directories.
 * Local mode: creates ./workspaces/ and ./credentials/ inside the Shannon repo.
 * NPX mode: creates ~/.shannon/workspaces/
 */
export function initHome(): void {
  if (getMode() === 'local') {
    fs.mkdirSync(path.join(getRepoDir(), 'workspaces'), { recursive: true });
    fs.mkdirSync(path.join(getRepoDir(), 'credentials'), { recursive: true });
  } else {
    fs.mkdirSync(path.join(SHANNON_HOME, 'workspaces'), { recursive: true });
  }
}
