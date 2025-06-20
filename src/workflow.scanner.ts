import * as core from '@actions/core'
import { Octokit } from '@octokit/rest'
import { Finding } from './types'
import { getRepoFiles } from './git.utils'

export async function scanWorkflowRisks(
  octokit: Octokit,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  core.info('Scanning for workflow security risks...')
  const findings: Finding[] = []

  let workflows: { path: string; sha: string }[] = []
  try {
    const allFiles = await getRepoFiles(octokit, owner, repo, '.github/workflows/')
    workflows = allFiles.filter(f => f.path.endsWith('.yml') || f.path.endsWith('.yaml'))
  } catch {
    return []
  }

  for (const file of workflows) {
    try {
      const { data: blob } = await octokit.git.getBlob({ owner, repo, file_sha: file.sha })
      const content = Buffer.from(blob.content, 'base64').toString('utf8')

      if (content.includes('pull_request_target') && content.includes('github.event.pull_request.head.sha')) {
        findings.push({
          severity: 'critical', type: 'workflow-risk', file: file.path,
          message:  'pull_request_target with PR head checkout — script injection risk',
          detail:   'Checking out untrusted PR code in pull_request_target grants write permissions to external code.',
          fix:      'Use pull_request instead, or restrict permissions and avoid checking out PR head.',
        })
      }

      const unpinnedActions = content.match(/uses:\s+[^@\s]+@(?:main|master|latest)/g) ?? []
      for (const action of unpinnedActions) {
        findings.push({
          severity: 'medium', type: 'workflow-risk', file: file.path,
          message:  `Unpinned action: ${action.replace('uses:', '').trim()}`,
          detail:   'Branch refs can be updated silently — a compromised action repo could inject malicious code.',
          fix:      'Pin to a specific tag or commit SHA.',
        })
      }

      if (content.includes('write-all') || (content.includes('contents: write') && content.includes('pull-requests: write'))) {
        findings.push({
          severity: 'high', type: 'workflow-risk', file: file.path,
          message:  'Overly broad GITHUB_TOKEN permissions',
          detail:   'write-all or combined write permissions increase blast radius.',
          fix:      'Grant only the minimum permissions each job needs.',
        })
      }
    } catch {
      // skip
    }
  }

  core.info(`  Found ${findings.length} workflow risk(s)`)
  return findings
}
