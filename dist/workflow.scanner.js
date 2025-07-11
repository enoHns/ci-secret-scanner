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
exports.scanWorkflowRisks = scanWorkflowRisks;
const core = __importStar(require("@actions/core"));
const git_utils_1 = require("./git.utils");
async function scanWorkflowRisks(octokit, owner, repo) {
    core.info('Scanning for workflow security risks...');
    const findings = [];
    let workflows = [];
    try {
        const allFiles = await (0, git_utils_1.getRepoFiles)(octokit, owner, repo, '.github/workflows/');
        workflows = allFiles.filter(f => f.path.endsWith('.yml') || f.path.endsWith('.yaml'));
    }
    catch {
        return [];
    }
    for (const file of workflows) {
        try {
            const { data: blob } = await octokit.git.getBlob({ owner, repo, file_sha: file.sha });
            const content = Buffer.from(blob.content, 'base64').toString('utf8');
            if (content.includes('pull_request_target') && content.includes('github.event.pull_request.head.sha')) {
                findings.push({
                    severity: 'critical', type: 'workflow-risk', file: file.path,
                    message: 'pull_request_target with PR head checkout — script injection risk',
                    detail: 'Checking out untrusted PR code in pull_request_target grants write permissions to external code.',
                    fix: 'Use pull_request instead, or restrict permissions and avoid checking out PR head.',
                });
            }
            const unpinnedActions = content.match(/uses:\s+[^@\s]+@(?:main|master|latest)/g) ?? [];
            for (const action of unpinnedActions) {
                findings.push({
                    severity: 'medium', type: 'workflow-risk', file: file.path,
                    message: `Unpinned action: ${action.replace('uses:', '').trim()}`,
                    detail: 'Branch refs can be updated silently — a compromised action repo could inject malicious code.',
                    fix: 'Pin to a specific tag or commit SHA.',
                });
            }
            if (content.includes('write-all') || (content.includes('contents: write') && content.includes('pull-requests: write'))) {
                findings.push({
                    severity: 'high', type: 'workflow-risk', file: file.path,
                    message: 'Overly broad GITHUB_TOKEN permissions',
                    detail: 'write-all or combined write permissions increase blast radius.',
                    fix: 'Grant only the minimum permissions each job needs.',
                });
            }
        }
        catch {
            // skip
        }
    }
    core.info(`  Found ${findings.length} workflow risk(s)`);
    return findings;
}
