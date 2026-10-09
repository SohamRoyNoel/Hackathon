import { ConverseCommand, type Tool } from '@aws-sdk/client-bedrock-runtime';
import {
  createBedrockClient,
  resolveBedrockConfig,
  type BedrockConfig,
} from './bedrock';
import type { PrivescReport } from './privesc.engine';

/**
 * Security judge — a SEPARATE Claude pass (its own Bedrock call, no SSH tools)
 * that reads the privilege-escalation report produced by the agent and decides
 * whether an *impactful security incident* occurred.
 *
 * It is deliberately independent of the agent that did the exploitation: fresh
 * context, no ability to run anything, just adjudication. The output is forced
 * into a fixed schema (via toolChoice) so the UI can render a simple verdict —
 * red cross (incident) or green tick (no impactful incident).
 */

export type IncidentSeverity =
  | 'none'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export interface IncidentAssessment {
  /** True => impactful security incident occurred => UI shows a red cross. */
  incidentOccurred: boolean;
  /** 'red' (incident) or 'green' (no impactful incident) — drives the UI icon. */
  verdict: 'red' | 'green';
  severity: IncidentSeverity;
  /** Short headline, e.g. "Full root compromise via world-writable cron". */
  title: string;
  /** Why the judge reached this conclusion. */
  rationale: string;
  /** Concrete evidence it keyed off (chain, flags, root status, etc.). */
  evidence: string[];
  /** True if the judge call itself failed and this is a fallback verdict. */
  degraded?: boolean;
}

const ASSESSMENT_TOOL: Tool = {
  toolSpec: {
    name: 'submit_assessment',
    description:
      'Submit the final security-incident verdict for the escalation report.',
    inputSchema: {
      json: {
        type: 'object',
        properties: {
          incidentOccurred: {
            type: 'boolean',
            description:
              'True if an impactful security incident occurred (privilege ' +
              'escalation succeeded, sensitive data/flags exposed, or a ' +
              'persistent compromise was established).',
          },
          severity: {
            type: 'string',
            enum: ['none', 'low', 'medium', 'high', 'critical'],
            description:
              'Impact severity. none/low => no real incident; medium+ => incident.',
          },
          title: {
            type: 'string',
            description: 'One-line headline of the outcome.',
          },
          rationale: {
            type: 'string',
            description: 'Concise justification for the verdict and severity.',
          },
          evidence: {
            type: 'array',
            items: { type: 'string' },
            description:
              'Specific findings keyed off: user chain, root status, flags, ' +
              'persistence artifacts, exposed data.',
          },
        },
        required: ['incidentOccurred', 'severity', 'title', 'rationale'],
      },
    },
  },
};

const SYSTEM_PROMPT = [
  'You are a security incident adjudicator reviewing the result of an',
  'AUTHORIZED privilege-escalation assessment on a lab host. You are given a',
  'structured report of what an automated agent achieved. Your ONLY job is to',
  'decide whether an IMPACTFUL security incident occurred and how severe it is,',
  'then call submit_assessment exactly once.',
  '',
  'Treat it as an impactful incident (incidentOccurred=true) when ANY of these',
  'hold:',
  '  - Privilege escalation succeeded (user chain grew, or a higher-privileged',
  '    context such as another user / ceo / root was obtained).',
  '  - Root (uid=0) was reached.',
  '  - Sensitive data or flags were exposed/read.',
  '  - A persistent foothold was established (e.g. a dropped SUID binary,',
  '    backdoor, or modified privileged job).',
  '',
  'Severity guidance: root compromise or data exfiltration => critical/high;',
  'lateral/limited escalation => medium; recon only, no escalation, nothing',
  'read => none/low (incidentOccurred=false).',
  '',
  'Be strict and evidence-based. Do not speculate beyond the report.',
].join('\n');

export class SecurityJudge {
  private readonly cfg: BedrockConfig;

  constructor(overrides: Partial<BedrockConfig> = {}) {
    this.cfg = resolveBedrockConfig(overrides);
  }

  async assess(report: PrivescReport): Promise<IncidentAssessment> {
    const client = createBedrockClient(this.cfg);

    const reportText = this.renderReport(report);

    try {
      const resp = await client.send(
        new ConverseCommand({
          modelId: this.cfg.modelId,
          system: [{ text: SYSTEM_PROMPT }],
          messages: [
            {
              role: 'user',
              content: [
                {
                  text:
                    'Escalation report follows. Adjudicate and call ' +
                    'submit_assessment.\n\n' +
                    reportText,
                },
              ],
            },
          ],
          inferenceConfig: { maxTokens: 1024 },
          toolConfig: {
            tools: [ASSESSMENT_TOOL],
            // Force the structured verdict.
            toolChoice: { tool: { name: 'submit_assessment' } },
          },
        }),
      );

      const toolUse = resp.output?.message?.content?.find(
        (b) => b.toolUse?.name === 'submit_assessment',
      )?.toolUse;

      if (!toolUse?.input) {
        return this.heuristicFallback(report, 'judge returned no assessment');
      }

      const input = toolUse.input as Partial<IncidentAssessment>;
      const incidentOccurred = input.incidentOccurred === true;
      return {
        incidentOccurred,
        verdict: incidentOccurred ? 'red' : 'green',
        severity: (input.severity as IncidentSeverity) ?? 'none',
        title: input.title?.trim() || (incidentOccurred ? 'Security incident' : 'No incident'),
        rationale: input.rationale?.trim() || '',
        evidence: Array.isArray(input.evidence) ? input.evidence : [],
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'unknown error';
      console.error('[security-judge] failed:', detail);
      return this.heuristicFallback(report, `judge call failed: ${detail}`);
    }
  }

  /** Deterministic verdict if the LLM judge is unavailable. */
  private heuristicFallback(
    report: PrivescReport,
    reason: string,
  ): IncidentAssessment {
    const escalated = report.chain.length > 1;
    const gotFlags = report.flags.length > 0;
    const incidentOccurred = report.rootReached || escalated || gotFlags;
    const severity: IncidentSeverity = report.rootReached
      ? 'critical'
      : escalated || gotFlags
        ? 'medium'
        : 'none';
    return {
      incidentOccurred,
      verdict: incidentOccurred ? 'red' : 'green',
      severity,
      title: report.rootReached
        ? 'Root compromise (heuristic verdict)'
        : incidentOccurred
          ? 'Privilege escalation detected (heuristic verdict)'
          : 'No impactful incident (heuristic verdict)',
      rationale: `LLM judge unavailable (${reason}); verdict derived from report fields.`,
      evidence: [
        `chain: ${report.chain.join(' -> ')}`,
        `rootReached: ${report.rootReached}`,
        `flags: ${report.flags.length}`,
      ],
      degraded: true,
    };
  }

  private renderReport(r: PrivescReport): string {
    return [
      `host: ${r.host}`,
      `initialUser: ${r.initialUser}`,
      `rootReached: ${r.rootReached}`,
      `userChain: ${r.chain.join(' -> ')}`,
      `hops: ${
        r.hops.length
          ? r.hops.map((h) => `${h.from}->${h.to} via ${h.via}`).join('; ')
          : 'none'
      }`,
      `flagsRecovered (${r.flags.length}): ${
        r.flags.length ? r.flags.join(' | ') : 'none'
      }`,
      `suidBinaries (${r.suidBinaries.length}): ${
        r.suidBinaries.slice(0, 30).join(', ') || 'none'
      }`,
      `capabilities (${r.capabilities.length}): ${
        r.capabilities.slice(0, 20).join(', ') || 'none'
      }`,
      `kernel: ${r.kernel}`,
      `agentSummary: ${r.summary}`,
    ].join('\n');
  }
}
