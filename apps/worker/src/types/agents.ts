// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent type definitions
 */

/**
 * List of all agents in execution order.
 * Used for iteration during resume state checking.
 */
export const ALL_AGENTS = [
  'pre-recon',
  'recon',
  'injection-vuln',
  'xss-vuln',
  'auth-vuln',
  'ssrf-vuln',
  'authz-vuln',
  'prompt_injection-vuln',
  'plugin_design-vuln',
  'info_disclosure-vuln',
  'output_handling-vuln',
  'prompt_leakage-vuln',
  'vector_weaknesses-vuln',
  'unbounded_consumption-vuln',
  'crypto_failures-vuln',
  'security_misconfiguration-vuln',
  'insecure_deserialization-vuln',
  'injection-exploit',
  'xss-exploit',
  'auth-exploit',
  'ssrf-exploit',
  'authz-exploit',
  'prompt_injection-exploit',
  'plugin_design-exploit',
  'info_disclosure-exploit',
  'output_handling-exploit',
  'prompt_leakage-exploit',
  'vector_weaknesses-exploit',
  'unbounded_consumption-exploit',
  'crypto_failures-exploit',
  'security_misconfiguration-exploit',
  'insecure_deserialization-exploit',
  'report',
] as const;

/** Agents used in the targeted rescan pipeline (re-verification after developer fixes). */
export const RESCAN_AGENTS = [
  'injection-vuln-rescan',
  'xss-vuln-rescan',
  'auth-vuln-rescan',
  'ssrf-vuln-rescan',
  'authz-vuln-rescan',
  'prompt_injection-vuln-rescan',
  'plugin_design-vuln-rescan',
  'info_disclosure-vuln-rescan',
  'output_handling-vuln-rescan',
  'prompt_leakage-vuln-rescan',
  'vector_weaknesses-vuln-rescan',
  'unbounded_consumption-vuln-rescan',
  'crypto_failures-vuln-rescan',
  'security_misconfiguration-vuln-rescan',
  'insecure_deserialization-vuln-rescan',
  'injection-exploit-rescan',
  'xss-exploit-rescan',
  'auth-exploit-rescan',
  'ssrf-exploit-rescan',
  'authz-exploit-rescan',
  'prompt_injection-exploit-rescan',
  'plugin_design-exploit-rescan',
  'info_disclosure-exploit-rescan',
  'output_handling-exploit-rescan',
  'prompt_leakage-exploit-rescan',
  'vector_weaknesses-exploit-rescan',
  'unbounded_consumption-exploit-rescan',
  'crypto_failures-exploit-rescan',
  'security_misconfiguration-exploit-rescan',
  'insecure_deserialization-exploit-rescan',
  'report-rescan',
] as const;

export type RescanAgentName = (typeof RESCAN_AGENTS)[number];

/**
 * Agent name type derived from ALL_AGENTS and RESCAN_AGENTS.
 * This ensures type safety and prevents drift between type and array.
 */
export type AgentName = (typeof ALL_AGENTS)[number] | RescanAgentName;

export type PlaywrightSession =
  | 'agent1'
  | 'agent2'
  | 'agent3'
  | 'agent4'
  | 'agent5'
  | 'agent6'
  | 'agent7'
  | 'agent8'
  | 'agent9'
  | 'agent10'
  | 'agent11'
  | 'agent12'
  | 'agent13'
  | 'agent14'
  | 'agent15';

import type { ActivityLogger } from './activity-logger.js';

export type AgentValidator = (sourceDir: string, logger: ActivityLogger) => Promise<boolean>;

export type AgentStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'rolled-back';

export interface AgentDefinition {
  name: AgentName;
  displayName: string;
  prerequisites: AgentName[];
  promptTemplate: string;
  deliverableFilename: string;
  modelTier?: 'small' | 'medium' | 'large';
}

/**
 * Vulnerability types supported by the pipeline.
 */
export type VulnType =
  | 'injection'
  | 'xss'
  | 'auth'
  | 'ssrf'
  | 'authz'
  | 'prompt_injection'
  | 'plugin_design'
  | 'info_disclosure'
  | 'output_handling'
  | 'prompt_leakage'
  | 'vector_weaknesses'
  | 'unbounded_consumption'
  | 'crypto_failures'
  | 'security_misconfiguration'
  | 'insecure_deserialization';

/**
 * Decision returned by queue validation for exploitation phase.
 */
export interface ExploitationDecision {
  shouldExploit: boolean;
  shouldRetry: boolean;
  vulnerabilityCount: number;
  vulnType: VulnType;
}
