import * as core from '@actions/core'
import { Octokit } from '@octokit/rest'
import { Finding } from './types'

export async function scanDependencies(
  octokit: Octokit,
  owner: string,
  repo: string,
): Promise<Finding[]> {
  core.info('Scanning dependencies via GitHub Dependency Review API...')

  const findings: Finding[] = []

  try {
    // GitHub Dependency Review API — available on PRs
    const { data: alerts } = await (octokit as any).request(
      'GET /repos/{owner}/{repo}/vulnerability-alerts',
      { owner, repo, mediaType: { previews: ['dorian'] } }
    )

    core.info(`  ${alerts.length} open vulnerability alert(s) from Dependabot`)

    for (const alert of alerts) {
      const pkg  = alert.security_vulnerability?.package
      const adv  = alert.security_advisory
      const cvss = adv?.cvss?.score ?? 0

      const severity: Finding['severity'] =
        cvss >= 9.0 ? 'critical' :
        cvss >= 7.0 ? 'high' :
        cvss >= 4.0 ? 'medium' : 'low'

      findings.push({
        severity,
        type:    'vulnerable-dep',
        file:    pkg?.ecosystem === 'npm' ? 'package.json' : 'dependencies',
        message: `${pkg?.name ?? 'unknown'} — ${adv?.summary ?? 'vulnerability'}`,
        detail:  `CVSS ${cvss} · ${adv?.cve_id ?? adv?.ghsa_id ?? 'no CVE'} · Affected: ${alert.security_vulnerability?.vulnerable_version_range}`,
        fix:     `Update to ${alert.security_vulnerability?.first_patched_version?.identifier ?? 'latest patched version'}`,
      })
    }
  } catch (err: any) {
    if (err?.status === 404) {
      core.info('  Dependency vulnerability alerts not available for this repo (requires Dependabot enabled)')
    } else {
      core.warning(`  Dep scan failed: ${err?.message}`)
    }
  }

  return findings
}
