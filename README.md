# secret-scanner

[![CI](https://github.com/enoHns/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/enoHns/secret-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Scan your GitHub Actions workflows and dependencies for hardcoded secrets, vulnerable packages, and risky workflow patterns — as a single CI step.

---

## Install

```yaml
- name: Security scan
  uses: enoHns/secret-scanner@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `github-token` | required | Token with `contents:read` + `pull-requests:write` |
| `post-comment` | `true` | Post/update PR comment with findings |
| `fail-on-critical` | `false` | Fail the step on any critical finding |

## Outputs

| Output | Description |
|--------|-------------|
| `critical-count` | Number of critical findings |
| `high-count` | Number of high-severity findings |

## What it scans

| Check | Severity |
|-------|----------|
| Hardcoded API keys, tokens, passwords | Critical |
| AWS access keys, GitHub PATs, private keys | Critical |
| Dependabot vulnerability alerts | Critical–Low |
| `pull_request_target` script injection | Critical |
| Unpinned third-party actions | Medium |
| Overly broad `GITHUB_TOKEN` permissions | High |

---

## License

MIT
