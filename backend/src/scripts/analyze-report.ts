/**
 * Blue-team CLI: read the post-agent report.txt and report whether a
 * dangerous event has happened.
 *
 * Usage:
 *   ts-node src/scripts/analyze-report.ts [path-to-report]
 *   # defaults to env POST_AGENT_REPORT_PATH, then ./report.txt, then /tmp/report.txt
 *
 * Exit codes:
 *   0 -> outcome=false (no dangerous event)
 *   2 -> outcome=true  (dangerous event detected)
 *   1 -> usage / read error
 */
import 'dotenv/config';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyzeReport, type Severity } from '../blue-team/report-analyzer';

function resolveReportPath(argPath?: string): string | null {
  const candidates = [
    argPath,
    process.env.POST_AGENT_REPORT_PATH,
    resolve(process.cwd(), 'report.txt'),
    '/tmp/report.txt',
  ].filter((value): value is string => !!value);

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: '[CRITICAL]',
  HIGH: '[HIGH]    ',
  MEDIUM: '[MEDIUM]  ',
  LOW: '[LOW]     ',
};

function main(): void {
  const argPath = process.argv[2];
  const reportPath = resolveReportPath(argPath);

  if (!reportPath) {
    console.error(
      'Blue team: report.txt not found. Pass a path or set POST_AGENT_REPORT_PATH.',
    );
    process.exit(1);
  }

  let reportText: string;
  try {
    reportText = readFileSync(reportPath, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown error';
    console.error(`Blue team: could not read ${reportPath}: ${message}`);
    process.exit(1);
  }

  const result = analyzeReport(reportText);

  console.log('='.repeat(64));
  console.log('BLUE TEAM REPORT ANALYSIS');
  console.log(`Source     : ${reportPath}`);
  console.log(`Lines       : ${result.linesScanned}`);
  console.log(
    `Findings    : CRITICAL=${result.summary.CRITICAL} HIGH=${result.summary.HIGH} ` +
      `MEDIUM=${result.summary.MEDIUM} LOW=${result.summary.LOW}`,
  );
  console.log(`Max severity: ${result.highestSeverity ?? 'none'}`);
  if (result.note) {
    console.log(`Note        : ${result.note}`);
  }
  console.log('-'.repeat(64));

  if (result.findings.length === 0) {
    console.log('No dangerous findings.');
  } else {
    for (const finding of result.findings) {
      console.log(
        `${SEVERITY_LABEL[finding.severity]} L${finding.line} ${finding.title}`,
      );
      console.log(`           ${finding.description}`);
      console.log(`           evidence: ${finding.evidence}`);
    }
  }

  console.log('='.repeat(64));
  // This is the value the blue team cares about.
  console.log(`outcome = ${result.outcome}`);
  console.log(
    result.outcome
      ? '>> DANGEROUS EVENT DETECTED (outcome=true)'
      : '>> No dangerous event detected (outcome=false)',
  );

  process.exit(result.outcome ? 2 : 0);
}

main();
