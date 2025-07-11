"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRepoFiles = getRepoFiles;
async function getRepoFiles(octokit, owner, repo, pathPrefix) {
    // Get the default branch HEAD sha
    const { data: repoData } = await octokit.repos.get({ owner, repo });
    const branch = repoData.default_branch;
    const { data: refData } = await octokit.git.getRef({
        owner, repo, ref: `heads/${branch}`,
    });
    const headSha = refData.object.sha;
    const { data: tree } = await octokit.git.getTree({
        owner, repo, tree_sha: headSha, recursive: '1',
    });
    return tree.tree
        .filter(f => f.type === 'blob' && f.path?.startsWith(pathPrefix))
        .map(f => ({ path: f.path, sha: f.sha }));
}
