import * as core   from '@actions/core'
import * as github from '@actions/github'
import { Octokit } from '@octokit/rest'
import { scanSecrets }       from './secret.scanner'
import { scanWorkflowRisks } from './workflow.scanner'
import { scanDependencies }  from './dep.scanner'
import { renderReport }      from './reporter'
import { ScanReport }        from './types'

async function run(): Promise<void> {
  try {
    const token         = core.getInput('github-token', { required: true })
    const postComment   = core.getBooleanInput('post-comment')
    const failOnCritical = core.getBooleanInput('fail-on-critical')

    const octokit = new Octokit({ auth: token })
    const ctx     = github.context
    const { owner, repo } = ctx.repo

    core.info(`secret-scanner — ${owner}/${repo}`)

    const [secretFindings, workflowFindings, depFindings] = await Promise.all([
      scanSecrets(octokit, owner, repo),
      scanWorkflowRisks(octokit, owner, repo),
      scanDependencies(octokit, owner, repo),
    ])

    const allFindings = [...secretFindings, ...workflowFindings, ...depFindings]

    const report: ScanReport = {
      critical:      allFindings.filter(f => f.severity === 'critical'),
      high:          allFindings.filter(f => f.severity === 'high'),
      medium:        allFindings.filter(f => f.severity === 'medium'),
      low:           allFindings.filter(f => f.severity === 'low'),
      totalScanned:  allFindings.length,
      workflowFiles: workflowFindings.length,
    }

    core.setOutput('critical-count', report.critical.length)
    core.setOutput('high-count',     report.high.length)

    if (postComment && ctx.payload.pull_request) {
      await renderReport(octokit, ctx, report)
    }

    if (failOnCritical && report.critical.length > 0) {
      core.setFailed(`${report.critical.length} critical finding(s) — merge blocked`)
      return
    }

    core.info(`Done — ${report.critical.length} critical, ${report.high.length} high`)
  } catch (err) {
    core.setFailed(`secret-scanner failed: ${(err as Error).message}`)
  }
}

run()
