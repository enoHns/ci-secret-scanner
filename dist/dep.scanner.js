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
exports.scanDependencies = scanDependencies;
const core = __importStar(require("@actions/core"));
async function scanDependencies(octokit, owner, repo) {
    core.info('Scanning dependencies via GitHub Dependency Review API...');
    const findings = [];
    try {
        // GitHub Dependency Review API — available on PRs
        const { data: alerts } = await octokit.request('GET /repos/{owner}/{repo}/vulnerability-alerts', { owner, repo, mediaType: { previews: ['dorian'] } });
        core.info(`  ${alerts.length} open vulnerability alert(s) from Dependabot`);
        for (const alert of alerts) {
            const pkg = alert.security_vulnerability?.package;
            const adv = alert.security_advisory;
            const cvss = adv?.cvss?.score ?? 0;
            const severity = cvss >= 9.0 ? 'critical' :
                cvss >= 7.0 ? 'high' :
                    cvss >= 4.0 ? 'medium' : 'low';
            findings.push({
                severity,
                type: 'vulnerable-dep',
                file: pkg?.ecosystem === 'npm' ? 'package.json' : 'dependencies',
                message: `${pkg?.name ?? 'unknown'} — ${adv?.summary ?? 'vulnerability'}`,
                detail: `CVSS ${cvss} · ${adv?.cve_id ?? adv?.ghsa_id ?? 'no CVE'} · Affected: ${alert.security_vulnerability?.vulnerable_version_range}`,
                fix: `Update to ${alert.security_vulnerability?.first_patched_version?.identifier ?? 'latest patched version'}`,
            });
        }
    }
    catch (err) {
        if (err?.status === 404) {
            core.info('  Dependency vulnerability alerts not available for this repo (requires Dependabot enabled)');
        }
        else {
            core.warning(`  Dep scan failed: ${err?.message}`);
        }
    }
    return findings;
}
