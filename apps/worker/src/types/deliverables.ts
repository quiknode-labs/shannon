// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deliverable Type Definitions
 *
 * Maps deliverable types to their filenames for the save-deliverable CLI.
 */

export enum DeliverableType {
  // Pre-recon agent
  CODE_ANALYSIS = 'CODE_ANALYSIS',

  // Recon agent
  RECON = 'RECON',

  // Vulnerability analysis agents
  INJECTION_ANALYSIS = 'INJECTION_ANALYSIS',
  XSS_ANALYSIS = 'XSS_ANALYSIS',
  AUTH_ANALYSIS = 'AUTH_ANALYSIS',
  AUTHZ_ANALYSIS = 'AUTHZ_ANALYSIS',
  SSRF_ANALYSIS = 'SSRF_ANALYSIS',
  PROMPT_INJECTION_ANALYSIS = 'PROMPT_INJECTION_ANALYSIS',
  PLUGIN_DESIGN_ANALYSIS = 'PLUGIN_DESIGN_ANALYSIS',
  INFO_DISCLOSURE_ANALYSIS = 'INFO_DISCLOSURE_ANALYSIS',
  OUTPUT_HANDLING_ANALYSIS = 'OUTPUT_HANDLING_ANALYSIS',
  PROMPT_LEAKAGE_ANALYSIS = 'PROMPT_LEAKAGE_ANALYSIS',
  VECTOR_WEAKNESSES_ANALYSIS = 'VECTOR_WEAKNESSES_ANALYSIS',
  UNBOUNDED_CONSUMPTION_ANALYSIS = 'UNBOUNDED_CONSUMPTION_ANALYSIS',

  // Exploitation agents
  INJECTION_EVIDENCE = 'INJECTION_EVIDENCE',
  XSS_EVIDENCE = 'XSS_EVIDENCE',
  AUTH_EVIDENCE = 'AUTH_EVIDENCE',
  AUTHZ_EVIDENCE = 'AUTHZ_EVIDENCE',
  SSRF_EVIDENCE = 'SSRF_EVIDENCE',
  PROMPT_INJECTION_EVIDENCE = 'PROMPT_INJECTION_EVIDENCE',
  PLUGIN_DESIGN_EVIDENCE = 'PLUGIN_DESIGN_EVIDENCE',
  INFO_DISCLOSURE_EVIDENCE = 'INFO_DISCLOSURE_EVIDENCE',
  OUTPUT_HANDLING_EVIDENCE = 'OUTPUT_HANDLING_EVIDENCE',
  PROMPT_LEAKAGE_EVIDENCE = 'PROMPT_LEAKAGE_EVIDENCE',
  VECTOR_WEAKNESSES_EVIDENCE = 'VECTOR_WEAKNESSES_EVIDENCE',
  UNBOUNDED_CONSUMPTION_EVIDENCE = 'UNBOUNDED_CONSUMPTION_EVIDENCE',
}

/**
 * Hard-coded filename mappings from agent prompts
 */
export const DELIVERABLE_FILENAMES: Record<DeliverableType, string> = {
  [DeliverableType.CODE_ANALYSIS]: 'pre_recon_deliverable.md',
  [DeliverableType.RECON]: 'recon_deliverable.md',
  [DeliverableType.INJECTION_ANALYSIS]: 'injection_analysis_deliverable.md',
  [DeliverableType.XSS_ANALYSIS]: 'xss_analysis_deliverable.md',
  [DeliverableType.AUTH_ANALYSIS]: 'auth_analysis_deliverable.md',
  [DeliverableType.AUTHZ_ANALYSIS]: 'authz_analysis_deliverable.md',
  [DeliverableType.SSRF_ANALYSIS]: 'ssrf_analysis_deliverable.md',
  [DeliverableType.PROMPT_INJECTION_ANALYSIS]: 'prompt_injection_analysis_deliverable.md',
  [DeliverableType.PLUGIN_DESIGN_ANALYSIS]: 'plugin_design_analysis_deliverable.md',
  [DeliverableType.INFO_DISCLOSURE_ANALYSIS]: 'info_disclosure_analysis_deliverable.md',
  [DeliverableType.OUTPUT_HANDLING_ANALYSIS]: 'output_handling_analysis_deliverable.md',
  [DeliverableType.PROMPT_LEAKAGE_ANALYSIS]: 'prompt_leakage_analysis_deliverable.md',
  [DeliverableType.VECTOR_WEAKNESSES_ANALYSIS]: 'vector_weaknesses_analysis_deliverable.md',
  [DeliverableType.UNBOUNDED_CONSUMPTION_ANALYSIS]: 'unbounded_consumption_analysis_deliverable.md',
  [DeliverableType.INJECTION_EVIDENCE]: 'injection_exploitation_evidence.md',
  [DeliverableType.XSS_EVIDENCE]: 'xss_exploitation_evidence.md',
  [DeliverableType.AUTH_EVIDENCE]: 'auth_exploitation_evidence.md',
  [DeliverableType.AUTHZ_EVIDENCE]: 'authz_exploitation_evidence.md',
  [DeliverableType.SSRF_EVIDENCE]: 'ssrf_exploitation_evidence.md',
  [DeliverableType.PROMPT_INJECTION_EVIDENCE]: 'prompt_injection_exploitation_evidence.md',
  [DeliverableType.PLUGIN_DESIGN_EVIDENCE]: 'plugin_design_exploitation_evidence.md',
  [DeliverableType.INFO_DISCLOSURE_EVIDENCE]: 'info_disclosure_exploitation_evidence.md',
  [DeliverableType.OUTPUT_HANDLING_EVIDENCE]: 'output_handling_exploitation_evidence.md',
  [DeliverableType.PROMPT_LEAKAGE_EVIDENCE]: 'prompt_leakage_exploitation_evidence.md',
  [DeliverableType.VECTOR_WEAKNESSES_EVIDENCE]: 'vector_weaknesses_exploitation_evidence.md',
  [DeliverableType.UNBOUNDED_CONSUMPTION_EVIDENCE]: 'unbounded_consumption_exploitation_evidence.md',
};
