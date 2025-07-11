"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanSecrets = scanSecrets;
const core = __importStar(require("@actions/core"));
const git_utils_1 = require("./git.utils");
const SECRET_PATTERNS = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i, type: 'API Key', severity: 'critical' },
    { pattern: /(?:secret|token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?/i, type: 'Secret/Token', severity: 'critical' },
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/i, type: 'Password', severity: 'critical' },
    { pattern: /AKIA[0-9A-Z]{16}/, type: 'AWS Access Key', severity: 'critical' },
    { pattern: /ghp_[A-Za-z0-9]{36}/, type: 'GitHub PAT', severity: 'critical' },
    { pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/, type: 'Slack Token', severity: 'high' },
    { pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, type: 'Private Key', severity: 'critical' },
    { pattern: /(?:database_url|db_url|mongo_uri|redis_url)\s*[:=]\s*['"]?[^\s'"]{10,}['"]?/i, type: 'DB Connection', severity: 'high' },
];
async function scanSecrets(octokit, owner, repo) {
    core.info('Scanning workflow files for secrets...');
    const findings = [];
    let workflowFiles = [];
    try {
        workflowFiles = await (0, git_utils_1.getRepoFiles)(octokit, owner, repo, '.github/');
    }
    catch {
        core.warning('Could not fetch workflow files');
        return [];
    }
    core.info(`  Found ${workflowFiles.length} file(s) to scan`);
    for (const file of workflowFiles) {
        try {
            const { data: blob } = await octokit.git.getBlob({ owner, repo, file_sha: file.sha });
            const content = Buffer.from(blob.content, 'base64').toString('utf8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.includes('${{ secrets.') || line.includes('${{ env.'))
                    continue;
                for (const { pattern, type, severity } of SECRET_PATTERNS) {
                    if (pattern.test(line)) {
                        findings.push({
                            severity,
                            type: 'secret',
                            file: file.path,
                            line: i + 1,
                            message: `Potential ${type} found`,
                            detail: `Line ${i + 1}: ${line.trim().substring(0, 80)}`,
                            fix: `Move to a GitHub Actions secret: \${{ secrets.YOUR_SECRET }}`,
                        });
                        break;
                    }
                }
            }
        }
        catch {
            // skip unreadable files
        }
    }
    core.info(`  Found ${findings.length} potential secret(s)`);
    return findings;
}
