// ci/sec-probes.js
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const TARGET = process.env.TARGET_URL || 'http://localhost:3000';
const OUTDIR = path.join(process.cwd(), 'artifacts');
fs.mkdirSync(OUTDIR, { recursive: true });

const findings = [];
function addFinding(sev, title, detail, url) {
  findings.push({ sev, title, detail, url });
}

function toSarif(findings) {
  return {
    $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "playwright-sec-probes" } },
      results: findings.map(f => ({
        ruleId: f.title.replace(/\s+/g,'-').toLowerCase(),
        level: (f.sev === 'high' ? 'error' : f.sev === 'medium' ? 'warning' : 'note'),
        message: { text: `${f.title}: ${f.detail}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.url || TARGET } } }]
      }))
    }]
  };
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, recordHar: { path: path.join(OUTDIR, 'session.har') } });
  const page = await context.newPage();

  try {
    await page.goto(TARGET, { waitUntil: 'networkidle', timeout: 30000 });
  } catch (e) {
    addFinding('high', 'Navigation failed', `Could not reach ${TARGET}: ${e.message}`, TARGET);
  }

  try {
    await page.screenshot({ path: path.join(OUTDIR, 'home.png'), fullPage: true });
  } catch {}

  try {
    const resp = await page.waitForResponse(r => r.url() === page.url(), { timeout: 5000 });
    const headers = resp.headers();
    const required = [
      ['content-security-policy',  'CSP missing weakens XSS defenses'],
      ['strict-transport-security','HSTS missing allows downgrade attacks'],
      ['x-frame-options',          'Clickjacking protection missing (X-Frame-Options)'],
      ['x-content-type-options',   'MIME sniffing protection missing (nosniff)'],
      ['referrer-policy',          'Referrer-Policy missing can leak URLs'],
      ['permissions-policy',       'Permissions-Policy missing (sensors/cam/mic control)']
    ];
    for (const [h, msg] of required) {
      if (!headers[h]) addFinding('medium', `Missing header: ${h}`, msg, page.url());
    }
    if (headers['content-security-policy'] && /unsafe-inline|unsafe-eval/.test(headers['content-security-policy'])) {
      addFinding('medium', 'Weak CSP', `Contains unsafe directive: ${headers['content-security-policy']}`, page.url());
    }
  } catch {}

  // Light XSS probe
  const payload = `"><svg/onload=alert(1)>`;
  try {
    const inputs = await page.$$('input:not([type=hidden]), textarea');
    for (let i = 0; i < Math.min(inputs.length, 6); i++) {
      try { await inputs[i].fill(payload); } catch {}
    }
    const buttons = await page.$$('form button[type=submit], form input[type=submit]');
    if (buttons.length) {
      try {
        await buttons[0].click({ noWaitAfter: true });
        await page.waitForTimeout(1200);
        const content = await page.content();
        if (content.includes(payload)) {
          addFinding('high', 'Possible reflected XSS', 'Probe payload appears reflected in page content', page.url());
        }
      } catch {}
    }
  } catch {}

  fs.writeFileSync(path.join(OUTDIR, 'findings.sarif.json'), JSON.stringify(toSarif(findings), null, 2));

  await context.close();
  await browser.close();

  if (findings.some(f => f.sev === 'high')) process.exit(2);
  process.exit(0);
})();
