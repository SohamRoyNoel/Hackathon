import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  analyzeReport,
  type AnalysisResult,
} from '../blue-team/report-analyzer';
import { CreateUserDto } from '../dto/create-user.dto';
import { Role, RoleDocument } from '../schemas/role.schema';
import { User, UserDocument } from '../schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    @InjectModel(Role.name) private readonly roleModel: Model<RoleDocument>,
  ) {}

  /**
   * Lets regular `ssh` answer its own password prompt non-interactively.
   * We point SSH_ASKPASS at a tiny helper script and force its use; the
   * script echoes the password from an env var, so the secret never lands
   * on disk. Call cleanup() once the child process has exited.
   */
  private createAskpass(passKey?: string): {
    env: NodeJS.ProcessEnv;
    cleanup: () => void;
  } {
    const scriptPath = join(
      tmpdir(),
      `ssh-askpass-${randomBytes(6).toString('hex')}.sh`,
    );
    writeFileSync(scriptPath, '#!/bin/sh\nprintf \'%s\\n\' "$SSH_PASSWORD"\n', {
      mode: 0o700,
    });

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      SSH_ASKPASS: scriptPath,
      SSH_ASKPASS_REQUIRE: 'force',
      SSH_PASSWORD: passKey ?? '',
      DISPLAY: process.env.DISPLAY ?? ':0',
    };
console.log("--==dd===> ", passKey);
    const cleanup = () => {
      try {
        unlinkSync(scriptPath);
      } catch {
        // best-effort; ignore if already gone
      }
    };

    return { env, cleanup };
  }

  private async generateClaudeMessage(): Promise<string> {
    const region = process.env.AWS_REGION ?? 'ap-south-1';
    const baseURL =
      process.env.BEDROCK_RUNTIME_BASE_URL ?? `https://bedrock-runtime.${region}.amazonaws.com`;
    const modelId =
      process.env.ANTHROPIC_MODEL ??
      process.env.BEDROCK_MODEL_ID ??
      'global.anthropic.claude-opus-4-8';
    const apiKey =
      process.env.AWS_BEDROCK_BEARER_TOKEN ?? process.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      return 'Claude agent unavailable: BEDROCK bearer token is not set.';
    }

    const endpoint = `${baseURL.replace(/\/$/, '')}/model/${modelId}/invoke`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        anthropic_version: 'bedrock-2023-05-31',
        max_tokens: 64,
        messages: [
          {
            role: 'user',
            content:
              'Generate one concise human-readable message about a secure role scanning result. It should sound like a real security review update and be one sentence only. Do not include markdown, bullets, or extra formatting.',
          },
        ],
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      return `Claude agent request failed: ${response.status} ${text}`;
    }

    const payload = (await response.json()) as Record<string, unknown>;
    const content = Array.isArray(payload.content) ? payload.content : [];
    const text = content
      .filter((block): block is { type: string; text?: string } => !!block && typeof block === 'object' && 'text' in block)
      .map((block) => block.text)
      .filter((value): value is string => typeof value === 'string')
      .join('\n')
      .trim();

    if (text) {
      return text;
    }

    if (typeof payload.output_text === 'string' && payload.output_text.trim()) {
      return payload.output_text.trim();
    }

    if (typeof payload.completion === 'string' && payload.completion.trim()) {
      return payload.completion.trim();
    }

    return JSON.stringify(payload);
  }

  private async triggerPostAgentCommand(
    agentMessage: string,
    roleName?: string,
    passKey?: string,
  ): Promise<void> {
    const rawSshHost = process.env.POST_AGENT_SSH_HOST ?? process.env.SSH_HOST;
    const remoteCommandTemplate =
      process.env.POST_AGENT_SSH_COMMAND ??
      process.env.SSH_REMOTE_COMMAND ??
      'ls';

    if (!rawSshHost) {
      return;
    }

    const safeMessage = agentMessage
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\$/g, '\\$')
      .replace(/`/g, '\\`');

    const remoteCommand = remoteCommandTemplate.includes('%MESSAGE%')
      ? remoteCommandTemplate.replace(/%MESSAGE%/g, safeMessage)
      : remoteCommandTemplate;

    const sshHost = roleName
      ? `${roleName.toLowerCase()}${rawSshHost}`
      : rawSshHost;
    console.log('--====> ', sshHost);

    // Regular ssh; the role's passKey answers the password prompt via askpass.
    const { env, cleanup } = this.createAskpass(passKey);
    const sshArgs = [
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      sshHost,
      remoteCommand,
    ];

    await new Promise<void>((resolve, reject) => {
      const child = spawn('ssh', sshArgs, { stdio: 'inherit', env });

      child.on('error', reject);
      child.on('exit', (code) => {
        if (code === 0) {
          console.log('Post-agent SSH command executed successfully.');
          resolve();
          return;
        }

        reject(new Error(`SSH command exited with code ${code}`));
      });
    })
      .catch((error) => {
        const message =
          error instanceof Error ? error.message : 'Unknown SSH execution error';
        console.error('Post-agent SSH command failed:', message);
      })
      .finally(cleanup);
  }

  /**
   * Fetch the red-team report back from the remote host over SSH.
   * The post-agent command appends its scan to a remote file (default
   * /tmp/report.txt); here we `cat` it and capture stdout for analysis.
   */
  private async fetchRemoteReport(
    roleName?: string,
    passKey?: string,
  ): Promise<string | null> {
    const rawSshHost = process.env.POST_AGENT_SSH_HOST ?? process.env.SSH_HOST;
    if (!rawSshHost) {
      return null;
    }

    const remotePath = process.env.POST_AGENT_REPORT_PATH ?? '/tmp/report.txt';
    const sshHost = roleName
      ? `${roleName.toLowerCase()}${rawSshHost}`
      : rawSshHost;
    const remoteCommand = `cat '${remotePath.replace(/'/g, "'\\''")}'`;

    // Regular ssh; the role's passKey answers the password prompt via askpass.
    const { env, cleanup } = this.createAskpass(passKey);
    const sshArgs = [
      '-o',
      'ConnectTimeout=10',
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      sshHost,
      remoteCommand,
    ];

    return new Promise<string | null>((resolve) => {
      const child = spawn('ssh', sshArgs, {
        stdio: ['ignore', 'pipe', 'inherit'],
        env,
      });

      let stdout = '';
      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.on('error', () => {
        cleanup();
        resolve(null);
      });
      child.on('exit', (code) => {
        cleanup();
        resolve(code === 0 ? stdout : null);
      });
    });
  }

  /**
   * Blue-team step: read the report (remote first, local fallback) and decide
   * whether a dangerous event has happened. The caller only needs `outcome`.
   */
  private async analyzePostAgentReport(
    roleName?: string,
    passKey?: string,
  ): Promise<AnalysisResult> {
    let reportText = await this.fetchRemoteReport(roleName, passKey);

    if (reportText === null) {
      const localPath =
        process.env.POST_AGENT_REPORT_PATH ?? '/tmp/report.txt';
      reportText = existsSync(localPath)
        ? readFileSync(localPath, 'utf8')
        : '';
    }

    const result = analyzeReport(reportText);

    console.log(
      `Blue team analysis: outcome=${result.outcome} ` +
        `(CRITICAL=${result.summary.CRITICAL} HIGH=${result.summary.HIGH} ` +
        `MEDIUM=${result.summary.MEDIUM} LOW=${result.summary.LOW})`,
    );
    if (result.outcome) {
      console.warn('Blue team: DANGEROUS EVENT DETECTED (outcome=true)');
    }

    return result;
  }

  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.userModel.findOne({
      userName: createUserDto.userName,
    });

    if (existingUser) {
      return {
        message: 'user already exists',
      };
    }

    const foundRoles = await this.roleModel
      .find({ roleId: { $in: createUserDto.role } })
      .lean();

    const foundRoleIds = foundRoles.map((role) => role._id);

    if (foundRoleIds.length !== createUserDto.role.length) {
      const missingRoleIds = createUserDto.role.filter(
        (roleId) => !foundRoles.some((role) => role.roleId === roleId),
      );

      return {
        message: `Role not found: ${missingRoleIds.join(', ')}`,
      };
    }

    const createdUser = await this.userModel.create({
      userName: createUserDto.userName,
      roleId: foundRoleIds,
    });

    const shouldNotifyAgent = createUserDto.shouldIncludeScan;
    const selectedRoleName = foundRoles[0]?.roleName;
    const selectedPassKey = foundRoles[0]?.passKey;

    const agentMessage = shouldNotifyAgent
      ? await this.generateClaudeMessage()
      : `User '${createUserDto.userName}' created successfully.`;

    console.log('Claude agent message:', agentMessage);

    await this.triggerPostAgentCommand(
      agentMessage,
      selectedRoleName,
      selectedPassKey,
    );

    // Blue-team step: analyze the report produced by the red-team scan.
    const blueTeam = shouldNotifyAgent
      ? await this.analyzePostAgentReport(selectedRoleName, selectedPassKey)
      : undefined;

    return {
      message: agentMessage,
      createdUser,
      roles: foundRoles,
      shouldIncludeScan: createUserDto.shouldIncludeScan,
      // The value the blue team cares about: did a dangerous event happen?
      outcome: blueTeam?.outcome ?? false,
      blueTeam,
    };
  }
}
