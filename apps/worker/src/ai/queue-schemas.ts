// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Zod schema definitions for vulnerability exploitation queue structured outputs.
 *
 * Each vuln agent returns a structured JSON response matching its schema.
 * The SDK validates the output against the JSON Schema generated from these Zod definitions.
 */

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import type { AgentName } from '../types/agents.js';

// === Common Fields ===

const ANALYSIS_NOTES_DESCRIPTION = 'Plain context for defenders (caveats, scope, what is at risk). Not attack steps.';

function notesField(exploit: boolean) {
  const f = z.string().optional();
  return exploit ? f : f.describe(ANALYSIS_NOTES_DESCRIPTION);
}

function makeBase(exploit: boolean) {
  return z.object({
    ID: z.string(),
    vulnerability_type: z.string(),
    externally_exploitable: z.boolean(),
    confidence: z.string(),
    notes: notesField(exploit),
  });
}

// === Per-Vuln-Type Schemas (used for type inference; notes description is mode-agnostic for types) ===

const baseVulnerability = makeBase(true);

const InjectionVulnerability = baseVulnerability.extend({
  source: z.string().optional(),
  combined_sources: z.string().optional(),
  path: z.string().optional(),
  sink_call: z.string().optional(),
  slot_type: z.string().optional(),
  sanitization_observed: z.string().optional(),
  concat_occurrences: z.string().optional(),
  verdict: z.string().optional(),
  mismatch_reason: z.string().optional(),
  witness_payload: z.string().optional(),
});

const XssVulnerability = baseVulnerability.extend({
  source: z.string().optional(),
  source_detail: z.string().optional(),
  path: z.string().optional(),
  sink_function: z.string().optional(),
  render_context: z.string().optional(),
  encoding_observed: z.string().optional(),
  verdict: z.string().optional(),
  mismatch_reason: z.string().optional(),
  witness_payload: z.string().optional(),
});

const AuthVulnerability = baseVulnerability.extend({
  source_endpoint: z.string().optional(),
  vulnerable_code_location: z.string().optional(),
  missing_defense: z.string().optional(),
  exploitation_hypothesis: z.string().optional(),
  suggested_exploit_technique: z.string().optional(),
});

const SsrfVulnerability = baseVulnerability.extend({
  source_endpoint: z.string().optional(),
  vulnerable_parameter: z.string().optional(),
  vulnerable_code_location: z.string().optional(),
  missing_defense: z.string().optional(),
  exploitation_hypothesis: z.string().optional(),
  suggested_exploit_technique: z.string().optional(),
});

const AuthzVulnerability = baseVulnerability.extend({
  endpoint: z.string().optional(),
  vulnerable_code_location: z.string().optional(),
  role_context: z.string().optional(),
  guard_evidence: z.string().optional(),
  side_effect: z.string().optional(),
  reason: z.string().optional(),
  minimal_witness: z.string().optional(),
});

const PromptInjectionVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const PluginDesignVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const InfoDisclosureVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const OutputHandlingVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const PromptLeakageVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const VectorWeaknessesVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const UnboundedConsumptionVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const CryptoFailuresVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const SecurityMisconfigurationVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

const InsecureDeserializationVulnerability = baseVulnerability.extend({
  vulnerable_component: z.string().optional(),
  attack_vector: z.string().optional(),
  evidence: z.string().optional(),
  impact: z.string().optional(),
});

// === Inferred Entry Types (consumed by renderer) ===

export type InjectionFinding = z.infer<typeof InjectionVulnerability>;
export type XssFinding = z.infer<typeof XssVulnerability>;
export type AuthFinding = z.infer<typeof AuthVulnerability>;
export type SsrfFinding = z.infer<typeof SsrfVulnerability>;
export type AuthzFinding = z.infer<typeof AuthzVulnerability>;
export type PromptInjectionFinding = z.infer<typeof PromptInjectionVulnerability>;
export type PluginDesignFinding = z.infer<typeof PluginDesignVulnerability>;
export type InfoDisclosureFinding = z.infer<typeof InfoDisclosureVulnerability>;
export type OutputHandlingFinding = z.infer<typeof OutputHandlingVulnerability>;
export type PromptLeakageFinding = z.infer<typeof PromptLeakageVulnerability>;
export type VectorWeaknessesFinding = z.infer<typeof VectorWeaknessesVulnerability>;
export type UnboundedConsumptionFinding = z.infer<typeof UnboundedConsumptionVulnerability>;
export type CryptoFailuresFinding = z.infer<typeof CryptoFailuresVulnerability>;
export type SecurityMisconfigurationFinding = z.infer<typeof SecurityMisconfigurationVulnerability>;
export type InsecureDeserializationFinding = z.infer<typeof InsecureDeserializationVulnerability>;

// === Convert to JSON Schema for SDK ===

// NOTE: The SDK's AJV validator expects draft-07. Zod defaults to draft-2020-12 which
// causes the SDK to silently skip structured output.
function toOutputFormat(zodSchema: z.ZodType): JsonSchemaOutputFormat {
  return { type: 'json_schema', schema: z.toJSONSchema(zodSchema, { target: 'draft-07' }) as Record<string, unknown> };
}

// === Per-Mode Output Format Builders ===
// Two maps cached at module load; the only per-mode difference is the
// description on the `notes` field, which steers the LLM's writing.

function buildOutputFormats(exploit: boolean): Partial<Record<AgentName, JsonSchemaOutputFormat>> {
  const base = makeBase(exploit);
  return {
    'injection-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            source: z.string().optional(),
            combined_sources: z.string().optional(),
            path: z.string().optional(),
            sink_call: z.string().optional(),
            slot_type: z.string().optional(),
            sanitization_observed: z.string().optional(),
            concat_occurrences: z.string().optional(),
            verdict: z.string().optional(),
            mismatch_reason: z.string().optional(),
            witness_payload: z.string().optional(),
          }),
        ),
      }),
    ),
    'xss-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            source: z.string().optional(),
            source_detail: z.string().optional(),
            path: z.string().optional(),
            sink_function: z.string().optional(),
            render_context: z.string().optional(),
            encoding_observed: z.string().optional(),
            verdict: z.string().optional(),
            mismatch_reason: z.string().optional(),
            witness_payload: z.string().optional(),
          }),
        ),
      }),
    ),
    'auth-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            source_endpoint: z.string().optional(),
            vulnerable_code_location: z.string().optional(),
            missing_defense: z.string().optional(),
            exploitation_hypothesis: z.string().optional(),
            suggested_exploit_technique: z.string().optional(),
          }),
        ),
      }),
    ),
    'ssrf-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            source_endpoint: z.string().optional(),
            vulnerable_parameter: z.string().optional(),
            vulnerable_code_location: z.string().optional(),
            missing_defense: z.string().optional(),
            exploitation_hypothesis: z.string().optional(),
            suggested_exploit_technique: z.string().optional(),
          }),
        ),
      }),
    ),
    'authz-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            endpoint: z.string().optional(),
            vulnerable_code_location: z.string().optional(),
            role_context: z.string().optional(),
            guard_evidence: z.string().optional(),
            side_effect: z.string().optional(),
            reason: z.string().optional(),
            minimal_witness: z.string().optional(),
          }),
        ),
      }),
    ),
    'prompt_injection-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'plugin_design-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'info_disclosure-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'output_handling-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'prompt_leakage-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'vector_weaknesses-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'unbounded_consumption-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'crypto_failures-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'security_misconfiguration-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
    'insecure_deserialization-vuln': toOutputFormat(
      z.object({
        vulnerabilities: z.array(
          base.extend({
            vulnerable_component: z.string().optional(),
            attack_vector: z.string().optional(),
            evidence: z.string().optional(),
            impact: z.string().optional(),
          }),
        ),
      }),
    ),
  };
}

const OUTPUT_FORMATS_EXPLOIT = buildOutputFormats(true);
const OUTPUT_FORMATS_ANALYSIS = buildOutputFormats(false);

const VULN_AGENT_QUEUE_FILENAMES: Partial<Record<AgentName, string>> = {
  'injection-vuln': 'injection_exploitation_queue.json',
  'xss-vuln': 'xss_exploitation_queue.json',
  'auth-vuln': 'auth_exploitation_queue.json',
  'ssrf-vuln': 'ssrf_exploitation_queue.json',
  'authz-vuln': 'authz_exploitation_queue.json',
  'prompt_injection-vuln': 'prompt_injection_exploitation_queue.json',
  'plugin_design-vuln': 'plugin_design_exploitation_queue.json',
  'info_disclosure-vuln': 'info_disclosure_exploitation_queue.json',
  'output_handling-vuln': 'output_handling_exploitation_queue.json',
  'prompt_leakage-vuln': 'prompt_leakage_exploitation_queue.json',
  'vector_weaknesses-vuln': 'vector_weaknesses_exploitation_queue.json',
  'unbounded_consumption-vuln': 'unbounded_consumption_exploitation_queue.json',
  'crypto_failures-vuln': 'crypto_failures_exploitation_queue.json',
  'security_misconfiguration-vuln': 'security_misconfiguration_exploitation_queue.json',
  'insecure_deserialization-vuln': 'insecure_deserialization_exploitation_queue.json',
};

/** Returns the structured output format for a vuln agent, or undefined for non-vuln agents. */
export function getOutputFormat(agentName: AgentName, exploit = true): JsonSchemaOutputFormat | undefined {
  return (exploit ? OUTPUT_FORMATS_EXPLOIT : OUTPUT_FORMATS_ANALYSIS)[agentName];
}

/** Returns the queue filename for a vuln agent, or undefined for non-vuln agents. */
export function getQueueFilename(agentName: AgentName): string | undefined {
  return VULN_AGENT_QUEUE_FILENAMES[agentName];
}
