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
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const rest_1 = require("@octokit/rest");
const secret_scanner_1 = require("./secret.scanner");
const workflow_scanner_1 = require("./workflow.scanner");
const dep_scanner_1 = require("./dep.scanner");
const reporter_1 = require("./reporter");
async function run() {
    try {
        const token = core.getInput('github-token', { required: true });
        const postComment = core.getBooleanInput('post-comment');
        const failOnCritical = core.getBooleanInput('fail-on-critical');
        const octokit = new rest_1.Octokit({ auth: token });
        const ctx = github.context;
        const { owner, repo } = ctx.repo;
        core.info(`secret-scanner — ${owner}/${repo}`);
        const [secretFindings, workflowFindings, depFindings] = await Promise.all([
            (0, secret_scanner_1.scanSecrets)(octokit, owner, repo),
            (0, workflow_scanner_1.scanWorkflowRisks)(octokit, owner, repo),
            (0, dep_scanner_1.scanDependencies)(octokit, owner, repo),
        ]);
        const allFindings = [...secretFindings, ...workflowFindings, ...depFindings];
        const report = {
            critical: allFindings.filter(f => f.severity === 'critical'),
            high: allFindings.filter(f => f.severity === 'high'),
            medium: allFindings.filter(f => f.severity === 'medium'),
            low: allFindings.filter(f => f.severity === 'low'),
            totalScanned: allFindings.length,
            workflowFiles: workflowFindings.length,
        };
        core.setOutput('critical-count', report.critical.length);
        core.setOutput('high-count', report.high.length);
        if (postComment && ctx.payload.pull_request) {
            await (0, reporter_1.renderReport)(octokit, ctx, report);
        }
        if (failOnCritical && report.critical.length > 0) {
            core.setFailed(`${report.critical.length} critical finding(s) — merge blocked`);
            return;
        }
        core.info(`Done — ${report.critical.length} critical, ${report.high.length} high`);
    }
    catch (err) {
        core.setFailed(`secret-scanner failed: ${err.message}`);
    }
}
run();
