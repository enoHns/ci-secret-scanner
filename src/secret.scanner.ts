import * as core from '@actions/core'
import { Octokit } from '@octokit/rest'
import { Finding } from './types'

// Common secret patterns
const SECRET_PATTERNS: { pattern: RegExp; type: string; severity: Finding['severity'] }[] = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i,           type: 'API Key',          severity: 'critical' },
  { pattern: /(?:secret|token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i,                  type: 'Secret/Token',     severity: 'critical' },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/i,                    type: 'Password',         severity: 'critical' },
  { pattern: /AKIA[0-9A-Z]{16}/,                                                              type: 'AWS Access Key',   severity: 'critical' },
  { pattern: /ghp_[A-Za-z0-9]{36}/,                                                           type: 'GitHub PAT',       severity: 'critical' },
  { pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/,                                                 type: 'Slack Token',      severity: 'high'     },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,                                      type: 'Private Key',      severity: 'critical' },
  { pattern: /(?:database_url|db_url|mongo_uri|redis_url)\s*[:=]\s*['"]?[^\s'"]{10,}['"]?/i, type: 'DB Connection',    severity: 'high'     },
]

export async function scanSecrets(
  octokit: Octokit,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  core.info('Scanning workflow files for secrets...')

  const findings: Finding[] = []

  // Fetch all workflow files
  let workflowFiles: { path: string; sha: string }[] = []
  try {
    const { data: tree } = await octokit.git.getTree({
      owner, repo, tree_sha: 'HEAD', recursive: '1',
    })
    workflowFiles = tree.tree
      .filter(f => f.path?.startsWith('.github/') && f.path.endsWith('.yml') || f.path?.endsWith('.yaml'))
      .map(f => ({ path: f.path!, sha: f.sha! }))
  } catch {
    core.warning('Could not fetch workflow file tree')
    return []
  }

  core.info(`  Found ${workflowFiles.length} workflow file(s) to scan`)

  for (const file of workflowFiles) {
    try {
      const { data: blob } = await octokit.git.getBlob({ owner, repo, file_sha: file.sha })
      const content = Buffer.from(blob.content, 'base64').toString('utf8')
      const lines   = content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]

        // Skip if value looks like a GitHub Actions secret expression
        if (line.includes('${{ secrets.') || line.includes('${{ env.')) continue

        for (const { pattern, type, severity } of SECRET_PATTERNS) {
          if (pattern.test(line)) {
            findings.push({
              severity,
              type:    'secret',
              file:    file.path,
              line:    i + 1,
              message: `Potential ${type} found`,
              detail:  `Line ${i + 1}: ${line.trim().substring(0, 80)}...`,
              fix:     `Move this value to a GitHub Actions secret and reference it via \${{ secrets.YOUR_SECRET }}`,
            })
            break  // one finding per line
          }
        }
      }
    } catch {
      // file unreadable — skip
    }
  }

  core.info(`  Found ${findings.length} potential secret(s)`)
  return findings
}
