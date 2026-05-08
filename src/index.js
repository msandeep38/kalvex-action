const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const https = require('https');

// ── helpers ──────────────────────────────────────────────────────────────────

function httpsPost(url, body, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const data = JSON.stringify(body);
    const options = {
      hostname: parsed.hostname,
      port: 443,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...headers,
      },
    };
    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(raw) });
        } catch {
          resolve({ status: res.statusCode, body: raw });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function findSolFiles(dirOrFile) {
  const results = [];
  if (!fs.existsSync(dirOrFile)) return results;
  const stat = fs.statSync(dirOrFile);
  if (stat.isFile()) {
    if (dirOrFile.endsWith('.sol')) results.push(dirOrFile);
    return results;
  }
  function walk(dir) {
    for (const entry of fs.readdirSync(dir)) {
      const full = path.join(dir, entry);
      if (fs.statSync(full).isDirectory()) {
        if (['node_modules', 'lib', 'forge-std', '.git'].includes(entry)) continue;
        walk(full);
      } else if (entry.endsWith('.sol')) {
        results.push(full);
      }
    }
  }
  walk(dirOrFile);
  return results;
}

function severityRank(s) {
  return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }[s] ?? 0;
}

function verdictEmoji(verdict) {
  return {
    DO_NOT_DEPLOY:   '🚨',
    HIGH_RISK:       '⚠️',
    REVIEW_REQUIRED: '🔍',
    SAFE_TO_DEPLOY:  '✅',
  }[verdict] ?? '🔍';
}

function severityEmoji(s) {
  return { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢', INFO: 'ℹ️' }[s] ?? '⚪';
}

function buildPRComment(results) {
  const lines = [];
  lines.push('## 🛡️ Kalvex Smart Contract Audit');
  lines.push('');

  for (const { file, verdict, verdict_reason, findings, error } of results) {
    const emoji = verdictEmoji(verdict);
    lines.push(`### ${emoji} \`${file}\``);

    if (error) {
      lines.push(`> ⚠️ Audit failed: ${error}`);
      lines.push('');
      continue;
    }

    lines.push(`**Verdict:** ${verdict.replace(/_/g, ' ')}  `);
    lines.push(`**${verdict_reason}**`);
    lines.push('');

    if (!findings || findings.length === 0) {
      lines.push('No vulnerabilities detected.');
      lines.push('');
      continue;
    }

    const bySev = {};
    for (const f of findings) {
      (bySev[f.severity] = bySev[f.severity] || []).push(f);
    }

    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      if (!bySev[sev]) continue;
      lines.push(`<details>`);
      lines.push(`<summary>${severityEmoji(sev)} <strong>${sev}</strong> — ${bySev[sev].length} finding${bySev[sev].length > 1 ? 's' : ''}</summary>`);
      lines.push('');
      for (const f of bySev[sev]) {
        lines.push(`#### ${f.title}`);
        lines.push(`- **CVSS:** ${f.cvss_score ?? 'N/A'}  `);
        lines.push(`- **CWE:** ${f.cwe_id ?? 'N/A'}  `);
        if (f.real_world_context) {
          lines.push(`- **⚡ Real exploit:** ${f.real_world_context}`);
        }
        lines.push('');
        lines.push(f.description ?? '');
        lines.push('');
        lines.push(`**Fix:** ${f.remediation ?? 'See Kalvex docs.'}`);
        lines.push('');
      }
      lines.push('</details>');
      lines.push('');
    }
  }

  const allFindings = results.flatMap(r => r.findings ?? []);
  const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const high = allFindings.filter(f => f.severity === 'HIGH').length;

  lines.push('---');
  lines.push(`**Total findings:** ${allFindings.length} | 🔴 Critical: ${critical} | 🟠 High: ${high}`);
  lines.push('');
  lines.push('> Powered by [Kalvex](https://kalvex.io) — AI Smart Contract Security  ');
  lines.push('> Get your free API key at [kalvex.io/get-api-key](https://kalvex.io/get-api-key)');

  if (critical > 0) {
    lines.push('');
    lines.push('> 🔑 **Unlock PoC exploit generation** for every CRITICAL finding — upgrade to [Kalvex Pro](https://kalvex.io/get-api-key) ($49/mo)');
  }

  return lines.join('\n');
}

// ── main ─────────────────────────────────────────────────────────────────────

async function run() {
  try {
    const apiKey        = core.getInput('api-key', { required: true });
    const contractsPath = core.getInput('contracts-path');
    const failOn        = core.getInput('fail-on').toUpperCase();
    const commentOnPR   = core.getInput('comment-on-pr') === 'true';
    const baseUrl       = core.getInput('base-url').replace(/\/$/, '');

    const solFiles = findSolFiles(contractsPath);
    if (solFiles.length === 0) {
      core.warning(`No Solidity files found at path: ${contractsPath}`);
      core.setOutput('verdict', 'SAFE_TO_DEPLOY');
      core.setOutput('findings-count', '0');
      core.setOutput('critical-count', '0');
      core.setOutput('high-count', '0');
      return;
    }

    core.info(`Found ${solFiles.length} Solidity file(s) to audit.`);

    const results = [];
    for (const file of solFiles) {
      core.info(`Auditing ${file}...`);
      const source = fs.readFileSync(file, 'utf8');
      const contractName = path.basename(file, '.sol');

      const res = await httpsPost(
        `${baseUrl}/api/threat-intel/audit`,
        { source, contract_name: contractName, generate_report: false },
        { 'X-API-Key': apiKey }
      );

      if (res.status !== 200) {
        const detail = res.body?.detail ?? res.body?.error ?? `HTTP ${res.status}`;
        core.error(`Audit failed for ${file}: ${detail}`);
        if (res.status === 401) core.error('Invalid API key. Get a free key at kalvex.io/get-api-key');
        if (res.status === 429) core.error('Quota exceeded. Upgrade to Pro at kalvex.io/get-api-key');
        results.push({ file, verdict: 'ERROR', verdict_reason: detail, findings: [], error: detail });
        continue;
      }

      results.push({
        file,
        verdict:        res.body.verdict ?? 'REVIEW_REQUIRED',
        verdict_reason: res.body.verdict_reason ?? '',
        findings:       res.body.findings ?? [],
        error:          null,
      });

      core.info(`  Verdict: ${res.body.verdict} — ${res.body.findings?.length ?? 0} findings`);
    }

    const allFindings    = results.flatMap(r => r.findings ?? []);
    const criticalCount  = allFindings.filter(f => f.severity === 'CRITICAL').length;
    const highCount      = allFindings.filter(f => f.severity === 'HIGH').length;

    const verdictOrder   = ['DO_NOT_DEPLOY', 'HIGH_RISK', 'REVIEW_REQUIRED', 'SAFE_TO_DEPLOY'];
    const worstVerdict   = results.reduce((worst, r) => {
      const idx = verdictOrder.indexOf(r.verdict);
      return idx < verdictOrder.indexOf(worst) ? r.verdict : worst;
    }, 'SAFE_TO_DEPLOY');

    core.setOutput('verdict', worstVerdict);
    core.setOutput('findings-count', String(allFindings.length));
    core.setOutput('critical-count', String(criticalCount));
    core.setOutput('high-count', String(highCount));

    if (commentOnPR && github.context.payload.pull_request) {
      const token = process.env.GITHUB_TOKEN;
      if (token) {
        const octokit = github.getOctokit(token);
        const { owner, repo } = github.context.repo;
        const prNumber = github.context.payload.pull_request.number;
        const body = buildPRComment(results);
        await octokit.rest.issues.createComment({ owner, repo, issue_number: prNumber, body });
        core.info('Posted audit results as PR comment.');
      } else {
        core.warning('GITHUB_TOKEN not set — skipping PR comment.');
      }
    }

    if (failOn !== 'NONE') {
      const shouldFail = allFindings.some(f => severityRank(f.severity) >= severityRank(failOn));
      if (shouldFail) {
        core.setFailed(
          `❌ Kalvex found ${criticalCount} CRITICAL and ${highCount} HIGH severity vulnerabilities. ` +
          `Verdict: ${worstVerdict}. Fix issues before merging.`
        );
        return;
      }
    }

    core.info(`✅ Kalvex audit passed. Verdict: ${worstVerdict}`);

  } catch (err) {
    core.setFailed(`Kalvex action error: ${err.message}`);
  }
}

run();
