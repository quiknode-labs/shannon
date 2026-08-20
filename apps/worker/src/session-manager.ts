// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from 'zx';

import { validateQueueAndDeliverable } from './services/queue-validation.js';
import type { ActivityLogger } from './types/activity-logger.js';
import type { AgentDefinition, AgentName, AgentValidator, PlaywrightSession, VulnType } from './types/index.js';

// Agent definitions according to PRD
export const AGENTS: Readonly<Record<AgentName, AgentDefinition>> = Object.freeze({
  'pre-recon': {
    name: 'pre-recon',
    displayName: 'Pre-recon agent',
    prerequisites: [],
    promptTemplate: 'pre-recon-code',
    deliverableFilename: 'pre_recon_deliverable.md',
    modelTier: 'large',
  },
  recon: {
    name: 'recon',
    displayName: 'Recon agent',
    prerequisites: ['pre-recon'],
    promptTemplate: 'recon',
    deliverableFilename: 'recon_deliverable.md',
  },
  'injection-vuln': {
    name: 'injection-vuln',
    displayName: 'Injection vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-injection',
    deliverableFilename: 'injection_analysis_deliverable.md',
  },
  'xss-vuln': {
    name: 'xss-vuln',
    displayName: 'XSS vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-xss',
    deliverableFilename: 'xss_analysis_deliverable.md',
  },
  'auth-vuln': {
    name: 'auth-vuln',
    displayName: 'Auth vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-auth',
    deliverableFilename: 'auth_analysis_deliverable.md',
  },
  'ssrf-vuln': {
    name: 'ssrf-vuln',
    displayName: 'SSRF vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-ssrf',
    deliverableFilename: 'ssrf_analysis_deliverable.md',
  },
  'authz-vuln': {
    name: 'authz-vuln',
    displayName: 'Authz vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-authz',
    deliverableFilename: 'authz_analysis_deliverable.md',
  },
  'prompt_injection-vuln': {
    name: 'prompt_injection-vuln',
    displayName: 'Prompt injection vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-prompt_injection',
    deliverableFilename: 'prompt_injection_analysis_deliverable.md',
  },
  'plugin_design-vuln': {
    name: 'plugin_design-vuln',
    displayName: 'Plugin design vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-plugin_design',
    deliverableFilename: 'plugin_design_analysis_deliverable.md',
  },
  'info_disclosure-vuln': {
    name: 'info_disclosure-vuln',
    displayName: 'Info disclosure vuln agent',
    prerequisites: ['recon'],
    promptTemplate: 'vuln-info_disclosure',
    deliverableFilename: 'info_disclosure_analysis_deliverable.md',
  },
  'injection-exploit': {
    name: 'injection-exploit',
    displayName: 'Injection exploit agent',
    prerequisites: ['injection-vuln'],
    promptTemplate: 'exploit-injection',
    deliverableFilename: 'injection_exploitation_evidence.md',
  },
  'xss-exploit': {
    name: 'xss-exploit',
    displayName: 'XSS exploit agent',
    prerequisites: ['xss-vuln'],
    promptTemplate: 'exploit-xss',
    deliverableFilename: 'xss_exploitation_evidence.md',
  },
  'auth-exploit': {
    name: 'auth-exploit',
    displayName: 'Auth exploit agent',
    prerequisites: ['auth-vuln'],
    promptTemplate: 'exploit-auth',
    deliverableFilename: 'auth_exploitation_evidence.md',
  },
  'ssrf-exploit': {
    name: 'ssrf-exploit',
    displayName: 'SSRF exploit agent',
    prerequisites: ['ssrf-vuln'],
    promptTemplate: 'exploit-ssrf',
    deliverableFilename: 'ssrf_exploitation_evidence.md',
  },
  'authz-exploit': {
    name: 'authz-exploit',
    displayName: 'Authz exploit agent',
    prerequisites: ['authz-vuln'],
    promptTemplate: 'exploit-authz',
    deliverableFilename: 'authz_exploitation_evidence.md',
  },
  'prompt_injection-exploit': {
    name: 'prompt_injection-exploit',
    displayName: 'Prompt injection exploit agent',
    prerequisites: ['prompt_injection-vuln'],
    promptTemplate: 'exploit-prompt_injection',
    deliverableFilename: 'prompt_injection_exploitation_evidence.md',
  },
  'plugin_design-exploit': {
    name: 'plugin_design-exploit',
    displayName: 'Plugin design exploit agent',
    prerequisites: ['plugin_design-vuln'],
    promptTemplate: 'exploit-plugin_design',
    deliverableFilename: 'plugin_design_exploitation_evidence.md',
  },
  'info_disclosure-exploit': {
    name: 'info_disclosure-exploit',
    displayName: 'Info disclosure exploit agent',
    prerequisites: ['info_disclosure-vuln'],
    promptTemplate: 'exploit-info_disclosure',
    deliverableFilename: 'info_disclosure_exploitation_evidence.md',
  },
  report: {
    name: 'report',
    displayName: 'Report agent',
    prerequisites: [
      'injection-exploit',
      'xss-exploit',
      'auth-exploit',
      'ssrf-exploit',
      'authz-exploit',
      'prompt_injection-exploit',
      'plugin_design-exploit',
      'info_disclosure-exploit',
    ],
    promptTemplate: 'report-executive',
    deliverableFilename: 'comprehensive_security_assessment_report.md',
  },

  // === Rescan agents (targeted re-verification after developer fixes) ===
  'injection-vuln-rescan': {
    name: 'injection-vuln-rescan',
    displayName: 'Injection vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-injection-rescan',
    deliverableFilename: 'injection_analysis_deliverable.md',
  },
  'xss-vuln-rescan': {
    name: 'xss-vuln-rescan',
    displayName: 'XSS vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-xss-rescan',
    deliverableFilename: 'xss_analysis_deliverable.md',
  },
  'auth-vuln-rescan': {
    name: 'auth-vuln-rescan',
    displayName: 'Auth vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-auth-rescan',
    deliverableFilename: 'auth_analysis_deliverable.md',
  },
  'ssrf-vuln-rescan': {
    name: 'ssrf-vuln-rescan',
    displayName: 'SSRF vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-ssrf-rescan',
    deliverableFilename: 'ssrf_analysis_deliverable.md',
  },
  'authz-vuln-rescan': {
    name: 'authz-vuln-rescan',
    displayName: 'Authz vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-authz-rescan',
    deliverableFilename: 'authz_analysis_deliverable.md',
  },
  'prompt_injection-vuln-rescan': {
    name: 'prompt_injection-vuln-rescan',
    displayName: 'Prompt injection vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-prompt_injection-rescan',
    deliverableFilename: 'prompt_injection_analysis_deliverable.md',
  },
  'plugin_design-vuln-rescan': {
    name: 'plugin_design-vuln-rescan',
    displayName: 'Plugin design vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-plugin_design-rescan',
    deliverableFilename: 'plugin_design_analysis_deliverable.md',
  },
  'info_disclosure-vuln-rescan': {
    name: 'info_disclosure-vuln-rescan',
    displayName: 'Info disclosure vuln rescan agent',
    prerequisites: [],
    promptTemplate: 'vuln-info_disclosure-rescan',
    deliverableFilename: 'info_disclosure_analysis_deliverable.md',
  },
  'injection-exploit-rescan': {
    name: 'injection-exploit-rescan',
    displayName: 'Injection exploit rescan agent',
    prerequisites: ['injection-vuln-rescan'],
    promptTemplate: 'exploit-injection-rescan',
    deliverableFilename: 'injection_exploitation_evidence.md',
  },
  'xss-exploit-rescan': {
    name: 'xss-exploit-rescan',
    displayName: 'XSS exploit rescan agent',
    prerequisites: ['xss-vuln-rescan'],
    promptTemplate: 'exploit-xss-rescan',
    deliverableFilename: 'xss_exploitation_evidence.md',
  },
  'auth-exploit-rescan': {
    name: 'auth-exploit-rescan',
    displayName: 'Auth exploit rescan agent',
    prerequisites: ['auth-vuln-rescan'],
    promptTemplate: 'exploit-auth-rescan',
    deliverableFilename: 'auth_exploitation_evidence.md',
  },
  'ssrf-exploit-rescan': {
    name: 'ssrf-exploit-rescan',
    displayName: 'SSRF exploit rescan agent',
    prerequisites: ['ssrf-vuln-rescan'],
    promptTemplate: 'exploit-ssrf-rescan',
    deliverableFilename: 'ssrf_exploitation_evidence.md',
  },
  'authz-exploit-rescan': {
    name: 'authz-exploit-rescan',
    displayName: 'Authz exploit rescan agent',
    prerequisites: ['authz-vuln-rescan'],
    promptTemplate: 'exploit-authz-rescan',
    deliverableFilename: 'authz_exploitation_evidence.md',
  },
  'prompt_injection-exploit-rescan': {
    name: 'prompt_injection-exploit-rescan',
    displayName: 'Prompt injection exploit rescan agent',
    prerequisites: ['prompt_injection-vuln-rescan'],
    promptTemplate: 'exploit-prompt_injection-rescan',
    deliverableFilename: 'prompt_injection_exploitation_evidence.md',
  },
  'plugin_design-exploit-rescan': {
    name: 'plugin_design-exploit-rescan',
    displayName: 'Plugin design exploit rescan agent',
    prerequisites: ['plugin_design-vuln-rescan'],
    promptTemplate: 'exploit-plugin_design-rescan',
    deliverableFilename: 'plugin_design_exploitation_evidence.md',
  },
  'info_disclosure-exploit-rescan': {
    name: 'info_disclosure-exploit-rescan',
    displayName: 'Info disclosure exploit rescan agent',
    prerequisites: ['info_disclosure-vuln-rescan'],
    promptTemplate: 'exploit-info_disclosure-rescan',
    deliverableFilename: 'info_disclosure_exploitation_evidence.md',
  },
  'report-rescan': {
    name: 'report-rescan',
    displayName: 'Rescan report agent',
    prerequisites: [
      'injection-exploit-rescan',
      'xss-exploit-rescan',
      'auth-exploit-rescan',
      'ssrf-exploit-rescan',
      'authz-exploit-rescan',
      'prompt_injection-exploit-rescan',
      'plugin_design-exploit-rescan',
      'info_disclosure-exploit-rescan',
    ],
    promptTemplate: 'report-rescan',
    deliverableFilename: 'rescan_verification_report.md',
  },
});

// Phase names for metrics aggregation
export type PhaseName = 'pre-recon' | 'recon' | 'vulnerability-analysis' | 'exploitation' | 'reporting';

// Map agents to their corresponding phases (single source of truth)
export const AGENT_PHASE_MAP: Readonly<Record<AgentName, PhaseName>> = Object.freeze({
  'pre-recon': 'pre-recon',
  recon: 'recon',
  'injection-vuln': 'vulnerability-analysis',
  'xss-vuln': 'vulnerability-analysis',
  'auth-vuln': 'vulnerability-analysis',
  'authz-vuln': 'vulnerability-analysis',
  'ssrf-vuln': 'vulnerability-analysis',
  'prompt_injection-vuln': 'vulnerability-analysis',
  'plugin_design-vuln': 'vulnerability-analysis',
  'info_disclosure-vuln': 'vulnerability-analysis',
  'injection-exploit': 'exploitation',
  'xss-exploit': 'exploitation',
  'auth-exploit': 'exploitation',
  'authz-exploit': 'exploitation',
  'ssrf-exploit': 'exploitation',
  'prompt_injection-exploit': 'exploitation',
  'plugin_design-exploit': 'exploitation',
  'info_disclosure-exploit': 'exploitation',
  report: 'reporting',
  // Rescan agents
  'injection-vuln-rescan': 'vulnerability-analysis',
  'xss-vuln-rescan': 'vulnerability-analysis',
  'auth-vuln-rescan': 'vulnerability-analysis',
  'ssrf-vuln-rescan': 'vulnerability-analysis',
  'authz-vuln-rescan': 'vulnerability-analysis',
  'prompt_injection-vuln-rescan': 'vulnerability-analysis',
  'plugin_design-vuln-rescan': 'vulnerability-analysis',
  'info_disclosure-vuln-rescan': 'vulnerability-analysis',
  'injection-exploit-rescan': 'exploitation',
  'xss-exploit-rescan': 'exploitation',
  'auth-exploit-rescan': 'exploitation',
  'ssrf-exploit-rescan': 'exploitation',
  'authz-exploit-rescan': 'exploitation',
  'prompt_injection-exploit-rescan': 'exploitation',
  'plugin_design-exploit-rescan': 'exploitation',
  'info_disclosure-exploit-rescan': 'exploitation',
  'report-rescan': 'reporting',
});

// Factory function for vulnerability queue validators
function createVulnValidator(vulnType: VulnType): AgentValidator {
  return async (sourceDir: string, logger: ActivityLogger): Promise<boolean> => {
    try {
      await validateQueueAndDeliverable(vulnType, sourceDir);
      return true;
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      logger.warn(`Queue validation failed for ${vulnType}: ${errMsg}`);
      return false;
    }
  };
}

// Factory function for exploit deliverable validators
function createExploitValidator(vulnType: VulnType): AgentValidator {
  return async (sourceDir: string): Promise<boolean> => {
    const evidenceFile = path.join(sourceDir, `${vulnType}_exploitation_evidence.md`);
    return await fs.pathExists(evidenceFile);
  };
}

// Playwright session mapping - assigns each agent to a specific session for browser isolation
// Keys are promptTemplate values from AGENTS registry
export const PLAYWRIGHT_SESSION_MAPPING: Record<string, PlaywrightSession> = Object.freeze({
  // Runs before any agent — non-concurrent, so agent1 is safe to share
  'validate-authentication': 'agent1',

  // Phase 1: Pre-reconnaissance
  'pre-recon-code': 'agent1',

  // Phase 2: Reconnaissance
  recon: 'agent2',

  // Phase 3: Vulnerability Analysis (up to 8 parallel agents)
  'vuln-injection': 'agent1',
  'vuln-xss': 'agent2',
  'vuln-auth': 'agent3',
  'vuln-ssrf': 'agent4',
  'vuln-authz': 'agent5',
  'vuln-prompt_injection': 'agent6',
  'vuln-plugin_design': 'agent7',
  'vuln-info_disclosure': 'agent8',

  // Phase 4: Exploitation (up to 8 parallel agents - same as vuln counterparts)
  'exploit-injection': 'agent1',
  'exploit-xss': 'agent2',
  'exploit-auth': 'agent3',
  'exploit-ssrf': 'agent4',
  'exploit-authz': 'agent5',
  'exploit-prompt_injection': 'agent6',
  'exploit-plugin_design': 'agent7',
  'exploit-info_disclosure': 'agent8',

  // Phase 5: Reporting
  'report-executive': 'agent3',

  // Rescan: vuln re-analysis (parallel, same session slots as normal vuln)
  'vuln-injection-rescan': 'agent1',
  'vuln-xss-rescan': 'agent2',
  'vuln-auth-rescan': 'agent3',
  'vuln-ssrf-rescan': 'agent4',
  'vuln-authz-rescan': 'agent5',
  'vuln-prompt_injection-rescan': 'agent6',
  'vuln-plugin_design-rescan': 'agent7',
  'vuln-info_disclosure-rescan': 'agent8',

  // Rescan: exploit verification (parallel, same session slots as normal exploit)
  'exploit-injection-rescan': 'agent1',
  'exploit-xss-rescan': 'agent2',
  'exploit-auth-rescan': 'agent3',
  'exploit-ssrf-rescan': 'agent4',
  'exploit-authz-rescan': 'agent5',
  'exploit-prompt_injection-rescan': 'agent6',
  'exploit-plugin_design-rescan': 'agent7',
  'exploit-info_disclosure-rescan': 'agent8',

  // Rescan: verification report
  'report-rescan': 'agent3',
});

// Direct agent-to-validator mapping - much simpler than pattern matching
export const AGENT_VALIDATORS: Record<AgentName, AgentValidator> = Object.freeze({
  // Pre-reconnaissance agent - validates the code analysis deliverable created by the agent
  'pre-recon': async (sourceDir: string): Promise<boolean> => {
    const codeAnalysisFile = path.join(sourceDir, 'pre_recon_deliverable.md');
    return await fs.pathExists(codeAnalysisFile);
  },

  // Reconnaissance agent
  recon: async (sourceDir: string): Promise<boolean> => {
    const reconFile = path.join(sourceDir, 'recon_deliverable.md');
    return await fs.pathExists(reconFile);
  },

  // Vulnerability analysis agents
  'injection-vuln': createVulnValidator('injection'),
  'xss-vuln': createVulnValidator('xss'),
  'auth-vuln': createVulnValidator('auth'),
  'ssrf-vuln': createVulnValidator('ssrf'),
  'authz-vuln': createVulnValidator('authz'),
  'prompt_injection-vuln': createVulnValidator('prompt_injection'),
  'plugin_design-vuln': createVulnValidator('plugin_design'),
  'info_disclosure-vuln': createVulnValidator('info_disclosure'),

  // Exploitation agents
  'injection-exploit': createExploitValidator('injection'),
  'xss-exploit': createExploitValidator('xss'),
  'auth-exploit': createExploitValidator('auth'),
  'ssrf-exploit': createExploitValidator('ssrf'),
  'authz-exploit': createExploitValidator('authz'),
  'prompt_injection-exploit': createExploitValidator('prompt_injection'),
  'plugin_design-exploit': createExploitValidator('plugin_design'),
  'info_disclosure-exploit': createExploitValidator('info_disclosure'),

  // Executive report agent
  report: async (sourceDir: string, logger: ActivityLogger): Promise<boolean> => {
    const reportFile = path.join(sourceDir, 'comprehensive_security_assessment_report.md');

    const reportExists = await fs.pathExists(reportFile);

    if (!reportExists) {
      logger.error('Missing required deliverable: comprehensive_security_assessment_report.md');
    }

    return reportExists;
  },

  // Rescan: vuln re-analysis agents (same deliverables as originals — same files, new workspace)
  'injection-vuln-rescan': createVulnValidator('injection'),
  'xss-vuln-rescan': createVulnValidator('xss'),
  'auth-vuln-rescan': createVulnValidator('auth'),
  'ssrf-vuln-rescan': createVulnValidator('ssrf'),
  'authz-vuln-rescan': createVulnValidator('authz'),
  'prompt_injection-vuln-rescan': createVulnValidator('prompt_injection'),
  'plugin_design-vuln-rescan': createVulnValidator('plugin_design'),
  'info_disclosure-vuln-rescan': createVulnValidator('info_disclosure'),

  // Rescan: exploit verification agents
  'injection-exploit-rescan': createExploitValidator('injection'),
  'xss-exploit-rescan': createExploitValidator('xss'),
  'auth-exploit-rescan': createExploitValidator('auth'),
  'ssrf-exploit-rescan': createExploitValidator('ssrf'),
  'authz-exploit-rescan': createExploitValidator('authz'),
  'prompt_injection-exploit-rescan': createExploitValidator('prompt_injection'),
  'plugin_design-exploit-rescan': createExploitValidator('plugin_design'),
  'info_disclosure-exploit-rescan': createExploitValidator('info_disclosure'),

  // Rescan: verification report agent
  'report-rescan': async (sourceDir: string, logger: ActivityLogger): Promise<boolean> => {
    const reportFile = path.join(sourceDir, 'rescan_verification_report.md');
    const reportExists = await fs.pathExists(reportFile);
    if (!reportExists) {
      logger.error('Missing required deliverable: rescan_verification_report.md');
    }
    return reportExists;
  },
});
