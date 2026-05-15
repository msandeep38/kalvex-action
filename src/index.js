const core = require('@actions/core');
const https = require('https');

async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const contractPath = core.getInput('contract-path', { required: true });
    const failOnCritical = core.getInput('fail-on-critical') === 'true';

    const fs = require('fs');
    const source = fs.readFileSync(contractPath, 'utf8');

    core.info('Running Kalvex audit...');

    const payload = JSON.stringify({
      source: source,
      contract_name: contractPath.split('/').pop().replace(/\.sol$/, ''),
    });

    const options = {
      hostname: 'kalvex.io',
      path: '/api/threat-intel/audit',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey,
        'Content-Length': Buffer.byteLength(payload),
      },
    };

    const result = await new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error(`Invalid JSON response (HTTP ${res.statusCode}): ${data.slice(0, 200)}`));
          }
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });

    const verdict    = result.verdict    || 'UNKNOWN';
    const findings   = result.findings   || [];
    const reportUrl  = result.report_url || '';

    core.setOutput('verdict',        verdict);
    core.setOutput('findings-count', findings.length.toString());
    core.setOutput('report-url',     reportUrl);

    core.info(`Verdict:  ${verdict}`);
    core.info(`Findings: ${findings.length}`);
    if (reportUrl) core.info(`Report:   ${reportUrl}`);

    if (failOnCritical && verdict === 'DO_NOT_DEPLOY') {
      core.setFailed(`Kalvex audit failed: ${verdict}. See report: ${reportUrl}`);
    }

  } catch (error) {
    core.setFailed(`Kalvex action failed: ${error.message}`);
  }
}

run();
