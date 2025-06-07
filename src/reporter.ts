import { Context } from '@actions/github/lib/context'
import { Octokit } from '@octokit/rest'
import { ScanReport, Finding, Severity } from './types'

const COMMENT_TAG = '<!-- secret-scanner -->'

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high:     '🟠',
  medium:   '🟡',
  low:      '🔵',
  info:     'ℹ️',
}

export async function renderReport(
  octokit: Octokit,
  ctx: Context,
  report: ScanReport,
): Promise<void> {
  if (!ctx.payload.pull_request) return

  const body = buildComment(report)
  const { owner, repo } = ctx.repo
  const prNumber = ctx.payload.pull_request.number

  const { data: comments } = await octokit.issues.listComments({
    owner, repo, issue_number: prNumber,
  })
  const existing = comments.find(c => c.body?.includes(COMMENT_TAG))

  if (existing) {
    await octokit.issues.updateComment({ owner, repo, comment_id: existing.id, body })
  } else {
    await octokit.issues.createComment({ owner, repo, issue_number: prNumber, body })
  }
}

function buildComment(report: ScanReport): string {
  const total = report.critical.length + report.high.length + report.medium.length + report.low.length
  const lines = [COMMENT_TAG, '## 🛡️ secret-scanner report\n']

  if (total === 0) {
    lines.push(`✅ **No issues found** — ${report.totalScanned} file(s) scanned`)
    return lines.join('\n')
  }

  lines.push(`Found **${total} issue(s)** across ${report.totalScanned} file(s) — ${report.workflowFiles} workflow file(s)\n`)
  lines.push('| Severity | Count |')
  lines.push('|----------|-------|')
  if (report.critical.length) lines.push(`| ${SEVERITY_EMOJI.critical} Critical | ${report.critical.length} |`)
  if (report.high.length)     lines.push(`| ${SEVERITY_EMOJI.high} High     | ${report.high.length} |`)
  if (report.medium.length)   lines.push(`| ${SEVERITY_EMOJI.medium} Medium   | ${report.medium.length} |`)
  if (report.low.length)      lines.push(`| ${SEVERITY_EMOJI.low} Low      | ${report.low.length} |`)

  for (const [label, findings] of [
    ['Critical', report.critical],
    ['High', report.high],
    ['Medium', report.medium],
  ] as [string, Finding[]][]) {
    if (!findings.length) continue
    lines.push(`\n<details><summary>${SEVERITY_EMOJI[label.toLowerCase() as Severity]} ${label} (${findings.length})</summary>\n`)
    for (const f of findings) {
      lines.push(`**${f.message}**  `)
      lines.push(`File: \`${f.file}\`${f.line ? ` · Line ${f.line}` : ''}  `)
      lines.push(`> ${f.detail}  `)
      lines.push(`💡 ${f.fix}\n`)
    }
    lines.push('</details>')
  }

  return lines.join('\n')
}
