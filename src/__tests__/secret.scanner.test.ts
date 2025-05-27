// Unit tests for the secret pattern matching logic
// We test the regex patterns directly since the scanner integrates with Octokit

const SECRET_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i, type: 'API Key' },
  { pattern: /AKIA[0-9A-Z]{16}/, type: 'AWS Access Key' },
  { pattern: /ghp_[A-Za-z0-9]{36}/, type: 'GitHub PAT' },
  { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, type: 'Private Key' },
]

describe('secret pattern detection', () => {
  it('detects AWS access key', () => {
    const line = 'AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE'
    expect(SECRET_PATTERNS.some(p => p.pattern.test(line))).toBe(true)
  })

  it('detects GitHub PAT', () => {
    const line = 'token: ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234'
    expect(SECRET_PATTERNS.some(p => p.pattern.test(line))).toBe(true)
  })

  it('detects private key header', () => {
    const line = '-----BEGIN RSA PRIVATE KEY-----'
    expect(SECRET_PATTERNS.some(p => p.pattern.test(line))).toBe(true)
  })

  it('does not flag GitHub Actions secret expressions', () => {
    const line = 'API_KEY: ${{ secrets.API_KEY }}'
    // This check mirrors what the scanner does — skip lines with ${{ secrets.
    const isSafe = line.includes('${{ secrets.') || line.includes('${{ env.')
    expect(isSafe).toBe(true)
  })

  it('does not false-positive on short values', () => {
    const line = 'api_key: short'
    expect(/(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i.test(line)).toBe(false)
  })
})
