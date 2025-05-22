import * as core from '@actions/core'
import { Octokit } from '@octokit/rest'
import { Finding } from './types'

export async function scanWorkflowRisks(
  octokit: Octokit,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  core.info('Scanning for workflow security risks...')

  const findings: Finding[] = []

  let workflows: { path: string; sha: string }[] = []
  try {
    const { data: tree } = await octokit.git.getTree({
      owner, repo, tree_sha: 'HEAD', recursive: '1',
    })
    workflows = tree.tree
      .filter(f => f.path?.startsWith('.github/workflows/') && (f.path.endsWith('.yml') || f.path.endsWith('.yaml')))
      .map(f => ({ path: f.path!, sha: f.sha! }))
  } catch {
    return []
  }

  for (const file of workflows) {
    try {
      const { data: blob } = await octokit.git.getBlob({ owner, repo, file_sha: file.sha })
      const content = Buffer.from(blob.content, 'base64').toString('utf8')

      // Risk: pull_request_target with checkout of PR code (script injection vector)
      if (content.includes('pull_request_target') && content.includes('ref: ${{ github.event.pull_request.head.sha }}')) {
        findings.push({
          severity: 'critical',
          type:     'workflow-risk',
          file:     file.path,
          message:  'pull_request_target with PR head checkout — script injection risk',
          detail:   'Checking out untrusted PR code in a pull_request_target context grants write permissions to external code.',
          fix:      'Use pull_request instead, or add explicit permissions: read-only and avoid checking out PR head ref.',
        })
      }

      // Risk: unpinned third-party actions (uses: actions/checkout@main instead of @v4)
      const unpinnedActions = content.match(/uses:\s+[^@\s]+@(?:main|master|latest)/g) ?? []
      for (const action of unpinnedActions) {
        findings.push({
          severity: 'medium',
          type:     'workflow-risk',
          file:     file.path,
          message:  `Unpinned action: ${action.replace('uses:', '').trim()}`,
          detail:   'Using branch refs instead of pinned tags means a compromised action repo could inject malicious code.',
          fix:      'Pin to a specific tag or commit SHA: e.g. uses: actions/checkout@v4',
        })
      }

      // Risk: GITHUB_TOKEN with excessive permissions
      if (content.includes('write-all') || (content.includes('contents: write') && content.includes('pull-requests: write'))) {
        findings.push({
          severity: 'high',
          type:     'workflow-risk',
          file:     file.path,
          message:  'Overly broad GITHUB_TOKEN permissions',
          detail:   'Granting write access to multiple resources increases blast radius if the workflow is compromised.',
          fix:      'Apply principle of least privilege — grant only the permissions each job actually needs.',
        })
      }

    } catch {
      // skip
    }
  }

  core.info(`  Found ${findings.length} workflow risk(s)`)
  return findings
}
