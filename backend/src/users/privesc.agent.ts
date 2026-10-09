import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  BedrockRuntimeClient,
  ConverseCommand,
  type ContentBlock,
  type Message,
  type Tool,
  type ToolResultBlock,
} from '@aws-sdk/client-bedrock-runtime';
import type { CmdResult, PrivescReport } from './privesc.engine';

/**
 * LLM-driven privilege-escalation agent.
 *
 * Here Claude (via Amazon Bedrock) is the *brain*: it does its own recon and
 * decides every command. We only give it a single tool — `run_ssh_command` —
 * that executes a shell command on the target over SSH as the login user, and
 * feed the output back. Claude loops: recon -> reason -> run -> observe ->
 * escalate, until it reaches uid=0 / grabs the flags, or the step budget runs
 * out. When done it calls `report_result` with its findings.
 *
 * Authorized use only: this is for the CTF/hackathon lab the user owns. Command
 * execution is intentionally UNRESTRICTED (per the chosen configuration) — the
 * agent runs whatever it decides on the lab box.
 *
 * IMPORTANT shell-state note (also told to the model): every `run_ssh_command`
 * call opens a brand-new SSH session as the ORIGINAL login user. Nothing
 * persists between calls (no cwd, no env, no "current" escalated identity). To
 * act as a user it escalated to, Claude must express the whole chain inside a
 * single command (e.g. `sudo -n -u role002 /bin/bash -c '...'`).
 */

export interface PrivescAgentOptions {
  host: string;
  password: string;
  /** Overrides for env-derived config (mostly for tests). */
  modelId?: string;
  region?: string;
  bearerToken?: string;
  maxSteps?: number;
}

const DEFAULT_MAX_STEPS = 40;
const MAX_OUTPUT_CHARS = 12_000; // trim giant command output before sending to the model

// Flag shapes we recognise in command output, mirroring the deterministic engine.
const FLAG_PATHS = [
  '/root/flag.txt',
  '/root/root.txt',
  '/root/flag',
  '/root/proof.txt',
  '/flag.txt',
  '/flag',
  '/home/*/flag.txt',
  '/home/*/user.txt',
  '/home/*/local.txt',
];

const READ_FLAGS_CMD = `for f in ${FLAG_PATHS.join(
  ' ',
)}; do [ -r "$f" ] && echo "FLAG_FILE:$f=$(cat "$f" 2>/dev/null)"; done`;

const TOOLS: Tool[] = [
  {
    toolSpec: {
      name: 'run_ssh_command',
      description:
        'Run a single shell command on the target over SSH and return its ' +
        'stdout, stderr and exit code. Each call is a FRESH SSH session as the ' +
        'original login user — no state persists between calls. To act as a ' +
        'user you have escalated to, put the full chain in one command.',
      inputSchema: {
        json: {
          type: 'object',
          properties: {
            command: {
              type: 'string',
              description: 'The exact shell command to execute on the target.',
            },
            purpose: {
              type: 'string',
              description: 'One short line: why you are running this.',
            },
          },
          required: ['command'],
        },
      },
    },
  },
  {
    toolSpec: {
      name: 'report_result',
      description:
        'Call this once when you are finished (root reached, or no further ' +
        'escalation is possible) to report the outcome. This ends the run.',
      inputSchema: {
        json: {
          type: 'object',
          properties: {
            root_reached: {
              type: 'boolean',
              description: 'True if you obtained a uid=0 (root) context.',
            },
            chain: {
              type: 'array',
              items: { type: 'string' },
              description:
                'Ordered user chain, e.g. ["role001","role002","root"].',
            },
            flags: {
              type: 'array',
              items: { type: 'string' },
              description: 'Any flag values / flag-file contents you recovered.',
            },
            summary: {
              type: 'string',
              description:
                'Human-readable summary of the escalation path and findings.',
            },
          },
          required: ['root_reached', 'summary'],
        },
      },
    },
  },
];

interface AgentReportInput {
  root_reached?: boolean;
  chain?: string[];
  flags?: string[];
  summary?: string;
}

export class PrivescAgent {
  private readonly host: string;
  private readonly password: string;
  private readonly modelId: string;
  private readonly region: string;
  private readonly bearerToken?: string;
  private readonly maxSteps: number;
  private readonly client: BedrockRuntimeClient;
  // Reused SSH control socket so every command after the first skips the
  // TCP + password-auth handshake (connection multiplexing).
  private readonly controlPath: string;

  constructor(opts: PrivescAgentOptions) {
    this.host = opts.host;
    this.password = opts.password;
    // Keep the control-socket path short: SSH caps ControlPath near 104 chars,
    // and macOS os.tmpdir() is long. /tmp is safe on macOS and Linux.
    this.controlPath = `/tmp/pe-${randomBytes(6).toString('hex')}`;
    this.modelId =
      opts.modelId ??
      // PRIVESC_AGENT_MODEL lets you pick a faster model (e.g. Sonnet) just for
      // the agent loop without changing the global ANTHROPIC_MODEL.
      process.env.PRIVESC_AGENT_MODEL ??
      process.env.ANTHROPIC_MODEL ??
      'global.anthropic.claude-opus-4-8';
    this.region =
      opts.region ?? process.env.AWS_REGION ?? 'us-east-1';
    this.bearerToken =
      opts.bearerToken ??
      process.env.AWS_BEARER_TOKEN_BEDROCK ??
      process.env.AWS_BEDROCK_BEARER_TOKEN;
    this.maxSteps = opts.maxSteps ?? DEFAULT_MAX_STEPS;

    // The AWS SDK reads a Bedrock API key from AWS_BEARER_TOKEN_BEDROCK; our
    // env uses AWS_BEDROCK_BEARER_TOKEN, so mirror it for any downstream code.
    if (this.bearerToken && !process.env.AWS_BEARER_TOKEN_BEDROCK) {
      process.env.AWS_BEARER_TOKEN_BEDROCK = this.bearerToken;
    }

    this.client = new BedrockRuntimeClient({
      region: this.region,
      maxAttempts: 5,
      retryMode: 'adaptive',
      // Explicit bearer-token (Bedrock API key) identity provider, so we don't
      // rely solely on env auto-detection.
      ...(this.bearerToken
        ? { token: async () => ({ token: this.bearerToken! }) }
        : {}),
    });
  }

  /**
   * Execute one command on the target over SSH. Connection multiplexing
   * (ControlMaster) keeps a single SSH session alive for the whole run, so only
   * the first command pays the TCP + password-auth cost; the rest reuse it.
   */
  private sshExec(remoteCommand: string, timeoutMs = 30_000): Promise<CmdResult> {
    const args = [
      '-p',
      this.password,
      'ssh',
      '-o',
      'ConnectTimeout=10',
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      '-o',
      'PreferredAuthentications=password,publickey',
      '-o',
      'LogLevel=ERROR',
      // Reuse one connection across all commands in this run.
      '-o',
      'ControlMaster=auto',
      '-o',
      `ControlPath=${this.controlPath}`,
      '-o',
      'ControlPersist=120',
      this.host,
      remoteCommand,
    ];

    console.log(`[privesc-agent] ${this.host} $ ${remoteCommand}`);

    return new Promise((resolve) => {
      execFile(
        'sshpass',
        args,
        { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout, stderr) => {
          const code =
            err && typeof (err as { code?: number }).code === 'number'
              ? (err as { code?: number }).code ?? 1
              : err
                ? 1
                : 0;
          if (stdout.trim()) console.log(stdout.trimEnd());
          if (stderr.trim())
            console.log(`[privesc-agent:stderr] ${stderr.trimEnd()}`);
          resolve({ cmd: remoteCommand, stdout, stderr, code });
        },
      );
    });
  }

  private extractFlags(output: string): string[] {
    const flags = new Set<string>();
    for (const line of output.split('\n')) {
      const ff = line.match(/^FLAG_FILE:(\S+)=(.*)$/);
      if (ff && ff[2].trim()) flags.add(`${ff[1]} => ${ff[2].trim()}`);
      const inline = line.match(/\b(flag|FLAG|CTF)\{[^}]+\}/g);
      if (inline) inline.forEach((f) => flags.add(f));
    }
    return [...flags];
  }

  private clip(s: string): string {
    if (s.length <= MAX_OUTPUT_CHARS) return s;
    return (
      s.slice(0, MAX_OUTPUT_CHARS) +
      `\n...[truncated ${s.length - MAX_OUTPUT_CHARS} chars]`
    );
  }

  /** Tear down the shared SSH master connection at the end of a run. */
  private closeSsh(): void {
    const args = [
      '-p',
      this.password,
      'ssh',
      '-o',
      `ControlPath=${this.controlPath}`,
      '-O',
      'exit',
      this.host,
    ];
    execFile('sshpass', args, () => {
      /* best-effort; socket also self-expires via ControlPersist */
    });
  }

  private systemPrompt(initialUser: string): string {
    return [
      'You are an autonomous privilege-escalation agent operating on an',
      'AUTHORIZED CTF/hackathon lab the operator fully owns and controls.',
      `You are logged into host "${this.host}" via SSH as user "${initialUser}".`,
      '',
      'GOAL: escalate privileges as far as possible — ideally to root (uid=0) —',
      'and read any flag files (e.g. /root/flag.txt, /home/*/user.txt). Both',
      'vertical (toward root) and horizontal (user-to-user) escalation count.',
      '',
      'HOW TO ACT: use the run_ssh_command tool to run shell commands. Start',
      'with recon (id, uname -a, sudo -n -l, find / -perm -4000 -type f,',
      'getcap -r /, crontabs, writable paths, interesting files), then reason',
      'about the output and attempt concrete escalation primitives (GTFOBins',
      'sudo/SUID/capability techniques, cron abuse, misconfig, etc.).',
      '',
      'CRITICAL — NO SHELL STATE PERSISTS between run_ssh_command calls. Each',
      'call opens a NEW SSH session as the original user',
      `"${initialUser}". There is no "current directory" or "current escalated`,
      'user" carried over. To do something as a user you escalated to, express',
      'the ENTIRE chain in ONE command, e.g.:',
      "  sudo -n -u role002 /bin/bash -c 'sudo -n -l; id'",
      'and nest further for multi-hop chains. Prefer non-interactive flags',
      '(sudo -n) and avoid commands that block waiting for input.',
      '',
      'EFFICIENCY: each tool call is a network round-trip, so BATCH related',
      'commands into a single call with `;` or `&&` (e.g. run several recon',
      'commands at once) instead of one tiny command per call. Keep each',
      'escalation attempt a single self-contained chain. Do not waste steps',
      're-running recon you already have.',
      '',
      'When you have reached root, exhausted options, or recovered the flags,',
      'call report_result with the user chain, any flags, and a clear summary.',
      'Do not call report_result until you have actually attempted escalation.',
    ].join('\n');
  }

  async run(): Promise<PrivescReport> {
    console.log(
      `[privesc-agent] ===== Claude-driven escalation on ${this.host} (model ${this.modelId}) =====`,
    );

    // Baseline recon up-front, in ONE round-trip: the slow filesystem walks
    // (find/getcap) run concurrently, and all sections come back together.
    const S = '@@PE@@'; // section delimiter
    const reconCmd = [
      `echo "${S}ID"; id`,
      `echo "${S}KERNEL"; uname -a`,
      // Kick off the slow walks in parallel, then wait.
      `echo "${S}SUID"; find / -perm -4000 -type f 2>/dev/null & p1=$!`,
      `echo "${S}CAP"; (wait $p1; getcap -r / 2>/dev/null)`,
      `echo "${S}SUDO"; sudo -n -l 2>&1 || true`,
      `echo "${S}FLAGS"; ${READ_FLAGS_CMD}`,
      `echo "${S}END"`,
    ].join('; ');
    const recon = await this.sshExec(reconCmd, 90_000);
    const section = (name: string): string => {
      const re = new RegExp(`${S}${name}\\n([\\s\\S]*?)(?:${S}|$)`);
      return (re.exec(recon.stdout)?.[1] ?? '').trim();
    };

    const idStdout = section('ID');
    const initialUser =
      /uid=\d+\(([^)]+)\)/.exec(idStdout)?.[1] ?? 'unknown';
    const kernel = section('KERNEL');
    const suidRaw = section('SUID');
    const capRaw = section('CAP');
    const sudoRaw = section('SUDO');

    const flags = new Set<string>(this.extractFlags(recon.stdout));
    const commandLog: Array<{ command: string; code: number | null }> = [];

    const kickoff = [
      `Login user: ${initialUser}`,
      `Kernel: ${kernel}`,
      '',
      'SUID binaries:',
      suidRaw || '(none found)',
      '',
      'File capabilities:',
      capRaw || '(none found)',
      '',
      'sudo -n -l:',
      sudoRaw || '(no passwordless sudo / not allowed)',
      '',
      'Begin. Use run_ssh_command to proceed with escalation.',
    ].join('\n');

    const messages: Message[] = [
      { role: 'user', content: [{ text: kickoff }] },
    ];

    let report: AgentReportInput | undefined;
    let rootReached = /uid=0\(root\)/.test(idStdout);

    for (let step = 0; step < this.maxSteps && !report; step++) {
      const resp = await this.client.send(
        new ConverseCommand({
          modelId: this.modelId,
          system: [{ text: this.systemPrompt(initialUser) }],
          messages,
          inferenceConfig: { maxTokens: 2048 },
          toolConfig: { tools: TOOLS },
        }),
      );

      const assistant = resp.output?.message;
      if (!assistant) {
        console.warn('[privesc-agent] empty model response; stopping.');
        break;
      }
      messages.push(assistant);

      // Surface any thinking/text the model emitted.
      for (const block of assistant.content ?? []) {
        if (block.text?.trim()) console.log(`[privesc-agent:claude] ${block.text.trim()}`);
      }

      if (resp.stopReason !== 'tool_use') {
        // Model stopped without a tool call — treat its text as the summary.
        const text = (assistant.content ?? [])
          .map((b) => b.text ?? '')
          .join('\n')
          .trim();
        report = { root_reached: rootReached, summary: text || 'Agent stopped.' };
        break;
      }

      // Execute every tool call in this turn and collect results.
      const toolResults: ContentBlock[] = [];
      for (const block of assistant.content ?? []) {
        const toolUse = block.toolUse;
        if (!toolUse) continue;
        const { name, input, toolUseId } = toolUse;

        if (name === 'report_result') {
          report = (input ?? {}) as AgentReportInput;
          // Acknowledge so the transcript stays well-formed (loop ends anyway).
          toolResults.push(
            this.toolResult(toolUseId!, 'Report received. Ending run.'),
          );
          continue;
        }

        if (name === 'run_ssh_command') {
          const cmd = (input as { command?: unknown })?.command;
          if (typeof cmd !== 'string' || !cmd.trim()) {
            toolResults.push(
              this.toolResult(toolUseId!, 'ERROR: missing "command" string.', true),
            );
            continue;
          }
          const res = await this.sshExec(cmd);
          commandLog.push({ command: cmd, code: res.code });
          this.extractFlags(res.stdout).forEach((f) => flags.add(f));
          if (/uid=0\(root\)/.test(res.stdout)) rootReached = true;

          const payload = [
            `exit_code: ${res.code}`,
            res.stdout.trim() ? `stdout:\n${res.stdout.trim()}` : 'stdout: (empty)',
            res.stderr.trim() ? `stderr:\n${res.stderr.trim()}` : '',
          ]
            .filter(Boolean)
            .join('\n');
          toolResults.push(
            this.toolResult(toolUseId!, this.clip(payload), res.code !== 0),
          );
          continue;
        }

        toolResults.push(
          this.toolResult(toolUseId!, `ERROR: unknown tool "${name}".`, true),
        );
      }

      if (toolResults.length) {
        messages.push({ role: 'user', content: toolResults });
      }
    }

    // Merge model-reported findings with what we observed.
    const reportedFlags = report?.flags ?? [];
    reportedFlags.forEach((f) => flags.add(f));
    const finalRoot = rootReached || report?.root_reached === true;
    const chain =
      report?.chain && report.chain.length ? report.chain : [initialUser];
    const hops = chain.slice(1).map((to, i) => ({
      from: chain[i],
      to,
      via: 'claude-agent',
      command: '(see command log)',
    }));

    const summary =
      report?.summary?.trim() ||
      (finalRoot
        ? `ROOT reached on ${this.host} via Claude-driven agent.`
        : `Claude-driven agent finished on ${this.host} without reaching root.`);

    console.log(
      `[privesc-agent] ===== done after ${commandLog.length} commands: ${summary} =====`,
    );

    this.closeSsh();

    return {
      host: this.host,
      initialUser,
      kernel,
      suidBinaries: suidRaw ? suidRaw.split('\n').filter(Boolean) : [],
      capabilities: capRaw ? capRaw.split('\n').filter(Boolean) : [],
      chain,
      hops,
      rootReached: finalRoot,
      flags: [...flags],
      summary,
    };
  }

  private toolResult(
    toolUseId: string,
    text: string,
    isError = false,
  ): ContentBlock {
    const result: ToolResultBlock = {
      toolUseId,
      content: [{ text }],
      ...(isError ? { status: 'error' } : {}),
    };
    return { toolResult: result };
  }
}
