/**
 * Blue-team analyzer for the post-agent report.
 *
 * The post-agent SSH step (red-team activity) runs a privilege-escalation
 * enumeration scan (linpeas) on the target host and appends the result to
 * `report.txt`. This module consumes that report and decides, defensively,
 * whether a *dangerous event* was observed.
 *
 * The single source of truth for callers is the `outcome` boolean:
 *   - outcome === true  -> at least one dangerous (CRITICAL/HIGH) finding
 *   - outcome === false -> nothing dangerous was detected
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DetectionRule {
  id: string;
  severity: Severity;
  /** Human-readable name of the privesc / exposure vector. */
  title: string;
  /** What this means for a defender. */
  description: string;
  /** Matched against each (ANSI-stripped) line of the report. */
  pattern: RegExp;
  /** If set and this also matches the line, the rule is suppressed (e.g. negations like "No writable..."). */
  exclude?: RegExp;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  /** 1-based line number in the (cleaned) report. */
  line: number;
  /** The offending line, trimmed. */
  evidence: string;
}

export interface AnalysisResult {
  /**
   * THE answer the blue team cares about.
   * true  => a dangerous event has happened.
   * false => no dangerous event detected.
   */
  outcome: boolean;
  /** Highest severity seen, or null when clean. */
  highestSeverity: Severity | null;
  /** Count of findings per severity. */
  summary: Record<Severity, number>;
  /** Every dangerous finding, most severe first. */
  findings: Finding[];
  /** Total lines scanned after cleaning. */
  linesScanned: number;
  /** Non-empty when the report could not be read / was empty. */
  note?: string;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 3,
  HIGH: 2,
  MEDIUM: 1,
  LOW: 0,
};

/**
 * A dangerous event is any CRITICAL or HIGH finding. MEDIUM/LOW are reported
 * for context but do not, on their own, flip the outcome to true.
 */
const DANGEROUS_THRESHOLD: Severity = 'HIGH';

/**
 * Suppresses negated phrasing such as "No writable files in PATH" or
 * "not vulnerable" so clean reports don't trip the writable/vulnerable rules.
 */
const NEGATION = /\b(no|not|none|isn'?t|aren'?t|cannot|can't)\b/i;

/**
 * Detection rules for the most common high-impact privilege-escalation and
 * credential-exposure vectors that a linpeas-style report surfaces.
 * Patterns are intentionally conservative to keep false positives low.
 */
export const DEFAULT_RULES: DetectionRule[] = [
  {
    id: 'writable-passwd',
    severity: 'CRITICAL',
    title: 'Writable /etc/passwd',
    description:
      'The passwd database is writable; an attacker can add a root-equivalent account.',
    pattern: /(\/etc\/passwd).*(writable|you can write|is writable)/i,
  },
  {
    id: 'writable-shadow',
    severity: 'CRITICAL',
    title: 'Readable/Writable /etc/shadow',
    description:
      'The shadow file is accessible; password hashes can be read or overwritten.',
    pattern: /(\/etc\/shadow).*(writable|readable|you can (read|write))/i,
  },
  {
    id: 'sudo-nopasswd',
    severity: 'CRITICAL',
    title: 'Passwordless sudo (NOPASSWD)',
    description:
      'A NOPASSWD sudo rule allows command execution as root without a password.',
    pattern: /NOPASSWD/,
  },
  {
    id: 'sudo-all',
    severity: 'CRITICAL',
    title: 'Unrestricted sudo (ALL : ALL)',
    description: 'The user may run any command as root via sudo.',
    pattern: /\(ALL\s*:\s*ALL\)\s*ALL/i,
  },
  {
    id: 'cap-setuid',
    severity: 'CRITICAL',
    title: 'Dangerous Linux capability',
    description:
      'A binary carries a file capability (e.g. cap_setuid/cap_dac_read_search) usable for privesc.',
    // Require real file-capability grant syntax ("cap_setuid+ep"); this avoids
    // the CapBnd/CapEff process-status dumps that list every capability.
    pattern:
      /\bcap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace|sys_module)\w*\+e/i,
    exclude: /^\s*Cap(Bnd|Eff|Prm|Inh|Amb)\s*[:=]/i,
  },
  {
    id: 'docker-group',
    severity: 'CRITICAL',
    title: 'Member of docker group',
    description:
      'Docker group membership is trivially escalatable to root on the host.',
    pattern: /\b(groups?|member).*\bdocker\b|\bdocker\b.*\b(group|privesc)\b/i,
  },
  {
    id: 'lxd-group',
    severity: 'CRITICAL',
    title: 'Member of lxd/lxc group',
    description: 'lxd/lxc group membership can be escalated to root on the host.',
    pattern: /\b(groups?|member).*\blx[dc]\b|\blx[dc]\b.*\b(group|privesc)\b/i,
  },
  {
    id: 'cve-pwnkit',
    severity: 'CRITICAL',
    title: 'PwnKit (CVE-2021-4034)',
    description: 'Host appears vulnerable to the pkexec local root exploit.',
    pattern: /CVE-2021-4034|pwnkit/i,
  },
  {
    id: 'cve-dirtypipe',
    severity: 'CRITICAL',
    title: 'DirtyPipe (CVE-2022-0847)',
    description: 'Kernel appears vulnerable to the DirtyPipe local root exploit.',
    pattern: /CVE-2022-0847|dirty\s*pipe/i,
  },
  {
    id: 'cve-baron-samedit',
    severity: 'CRITICAL',
    title: 'Sudo Baron Samedit (CVE-2021-3156)',
    description: 'sudo appears vulnerable to the Baron Samedit heap overflow.',
    pattern: /CVE-2021-3156|baron\s*samedit/i,
  },
  {
    id: 'cve-dirtycow',
    severity: 'CRITICAL',
    title: 'DirtyCow (CVE-2016-5195)',
    description: 'Kernel appears vulnerable to the DirtyCow race-condition exploit.',
    pattern: /CVE-2016-5195|dirty\s*cow/i,
  },
  {
    id: 'private-key',
    severity: 'HIGH',
    title: 'Exposed private key',
    description: 'A private key was found in the report and may allow lateral movement.',
    pattern: /-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----/,
  },
  {
    id: 'suid-gtfobin',
    severity: 'HIGH',
    title: 'Exploitable SUID binary',
    description:
      'A SUID binary flagged as a known GTFOBin can be abused to run as root.',
    pattern: /(SUID|SGID).*(gtfo|known|exploit|interesting)|gtfobins/i,
  },
  {
    id: 'writable-path',
    severity: 'HIGH',
    title: 'Writable directory in $PATH',
    description:
      'A writable $PATH entry allows binary hijacking of commands run by other users.',
    pattern: /writable.*\bPATH\b|\bPATH\b.*writable/i,
    exclude: NEGATION,
  },
  {
    id: 'writable-cron',
    severity: 'HIGH',
    title: 'Writable cron job / script',
    description:
      'A cron-executed file is writable; its contents run on a schedule, often as root.',
    pattern: /(cron|crontab).*(writable|you can write)/i,
    exclude: NEGATION,
  },
  {
    id: 'writable-service',
    severity: 'HIGH',
    title: 'Writable systemd service / unit',
    description:
      'A writable service unit lets an attacker control a command run by root.',
    pattern: /(\.service|systemd|init\.d).*(writable|you can write)/i,
    exclude: NEGATION,
  },
  {
    id: 'hardcoded-cred',
    severity: 'HIGH',
    title: 'Hardcoded credential / password',
    description: 'A plaintext password or secret was surfaced in the report.',
    pattern:
      /\b(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\b\s*[:=]\s*['"]?[^\s'"]{3,}/i,
    // Skip package-manager / log noise like "passwd:amd64 1:4.17.4-2".
    exclude: /\.log:|\bdpkg\b|\bapt\b|:(amd64|arm64|i386|all)\b|base-passwd|half-(installed|configured)|\b(status|configure|install|unpack|upgrade)\b/i,
  },
  {
    id: 'linpeas-99',
    severity: 'HIGH',
    title: 'linpeas high-probability PE vector',
    description:
      'linpeas marked this item as a 95-99% probable privilege-escalation path.',
    pattern: /\b9[59]%\b/,
  },
  {
    id: 'cve-vulnerable',
    severity: 'HIGH',
    title: 'Confirmed/likely vulnerable to CVE',
    description:
      'The scanner judged the host vulnerable to a specific CVE; patch and review.',
    pattern: /\b(likely\s+)?vulnerable\s+to\b|\bvulnerable\b.*\bCVE-\d{4}-\d{4,}/i,
    exclude: NEGATION,
  },
  {
    id: 'generic-vulnerable',
    severity: 'MEDIUM',
    title: 'Potential vulnerability flagged',
    description: 'The scanner flagged a possible vulnerability; review for impact.',
    pattern: /\b(vulnerable|exploitable)\b/i,
    exclude: NEGATION,
  },
];

/** Remove ANSI color/escape sequences that linpeas emits. */
export function stripAnsi(input: string): string {
  // eslint-disable-next-line no-control-regex
  return input.replace(/\x1B\[[0-9;?]*[ -/]*[@-~]/g, '');
}

function emptySummary(): Record<Severity, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
}

/**
 * linpeas decorates output with box-drawing section headers and appends
 * hacktricks/github reference URLs. Those lines carry keywords (SUID,
 * vulnerable, writable...) but describe *what was checked*, not a finding,
 * so we skip them to avoid false positives.
 */
const BOX_DRAWING = /[╔╚╗╝═║╠╣╦╩╬├└┌┐┤┴┬│─]/;
const REFERENCE_URL = /https?:\/\/[^\s]*(hacktricks|github|book\.|\.wiki)/i;

function isNoiseLine(line: string): boolean {
  return BOX_DRAWING.test(line) || REFERENCE_URL.test(line);
}

/**
 * Analyze report text and decide whether a dangerous event occurred.
 *
 * @param reportText Raw report contents (ANSI codes allowed).
 * @param rules Override the default ruleset (e.g. for tests).
 */
export function analyzeReport(
  reportText: string,
  rules: DetectionRule[] = DEFAULT_RULES,
): AnalysisResult {
  const cleaned = stripAnsi(reportText ?? '');
  const lines = cleaned.split(/\r?\n/);
  const findings: Finding[] = [];
  const summary = emptySummary();

  if (cleaned.trim().length === 0) {
    return {
      outcome: false,
      highestSeverity: null,
      summary,
      findings: [],
      linesScanned: 0,
      note: 'Report was empty or unreadable; treating as no dangerous event.',
    };
  }

  // Collapse identical (rule, evidence) hits that linpeas prints more than once.
  const seen = new Set<string>();

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || isNoiseLine(line)) {
      return;
    }

    for (const rule of rules) {
      if (rule.exclude && rule.exclude.test(line)) {
        continue;
      }
      if (rule.pattern.test(line)) {
        const evidence = line.length > 300 ? `${line.slice(0, 297)}...` : line;
        const dedupeKey = `${rule.id}\u0000${evidence.toLowerCase()}`;
        if (seen.has(dedupeKey)) {
          continue;
        }
        seen.add(dedupeKey);
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          line: index + 1,
          evidence,
        });
      }
    }
  });

  // Collapse rules that matched the exact same line, keeping the most severe
  // (e.g. a specific CVE rule wins over the generic "vulnerable" catch-all).
  const byEvidence = new Map<string, Finding>();
  for (const finding of findings) {
    const key = finding.evidence.toLowerCase();
    const existing = byEvidence.get(key);
    if (
      !existing ||
      SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.severity]
    ) {
      byEvidence.set(key, finding);
    }
  }

  const collapsed = [...byEvidence.values()];
  for (const finding of collapsed) {
    summary[finding.severity] += 1;
  }
  findings.length = 0;
  findings.push(...collapsed);

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.line - b.line,
  );

  const highestSeverity: Severity | null = findings.length
    ? findings[0].severity
    : null;

  const outcome =
    highestSeverity !== null &&
    SEVERITY_ORDER[highestSeverity] >= SEVERITY_ORDER[DANGEROUS_THRESHOLD];

  return {
    outcome,
    highestSeverity,
    summary,
    findings,
    linesScanned: lines.length,
  };
}
