// Given a fresh Rusty, its original header and fonts remain usable even without Sink.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { chromium } from '../../tincanban/node_modules/@playwright/test/index.mjs';

const listener = createServer();
await new Promise(done => listener.listen(0, '127.0.0.1', done));
const port = listener.address().port;
await new Promise(done => listener.close(done));
const origin = `http://127.0.0.1:${port}`;
const directory = await mkdtemp(`${tmpdir()}/rusty-ui-`);
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(RUSTY_|LIGHTHOUSE_)/.test(key)));
const child = spawn(resolve(process.argv[2] || 'target/debug/mesh-lighthouse'), [directory, `127.0.0.1:${port}`], {
  env: { ...environment, RUSTY_PUBLIC_ORIGIN: origin }, stdio: ['ignore', 'pipe', 'pipe'],
});
let logs = '';
child.stdout.on('data', data => { logs += data; });
child.stderr.on('data', data => { logs += data; });
let browser;
try {
  for (let attempt = 0; ; attempt++) {
    try { if ((await fetch(`${origin}/health`)).ok) break; } catch {}
    assert(attempt < 150 && child.exitCode === null, `Rusty readiness failed: ${logs}`);
    await new Promise(done => setTimeout(done, 100));
  }
  browser = await chromium.launch({ headless: true });
  for (const scenario of ['desktop', 'mobile']) {
    const context = await browser.newContext({ viewport: scenario === 'mobile' ? { width: 375, height: 812 } : { width: 1280, height: 800 } });
    const page = await context.newPage();
    const externalResources = [];
    const failures = [];
    page.on('request', request => { if (!request.url().startsWith(origin)) externalResources.push(request.url()); });
    page.on('requestfailed', request => failures.push(request.url()));
    await page.goto(origin);
    await page.getByRole('heading', { name: 'RUSTY', exact: true }).waitFor();
    await page.locator('#service-availability').filter({ hasText: /^Storage available$/ }).waitFor();
    assert.equal(await page.getByRole('link', { name: 'Open tincanban' }).getAttribute('href'), 'https://match.meta-uber-engineer.dev');
    assert.equal(await page.getByRole('link', { name: 'View Rusty logs' }).count(), 0);
    const appearance = await page.evaluate(async () => {
      await document.fonts.ready;
      const logo = document.querySelector('.rusty-mark');
      const box = logo.getBoundingClientRect();
      return {
        bodyFont: getComputedStyle(document.body).fontFamily,
        headingFont: getComputedStyle(document.querySelector('h1')).fontFamily,
        loadedFonts: [...document.fonts].filter(font => font.status === 'loaded').map(font => font.family.replaceAll('"', '')),
        logo: { width: box.width, height: box.height, decoded: logo.naturalWidth > 0 },
        overflow: document.documentElement.scrollWidth > innerWidth,
        favicon: document.querySelector('link[rel="icon"]').getAttribute('href'),
      };
    });
    assert(appearance.bodyFont.startsWith('"Fira Code"'), JSON.stringify(appearance));
    assert(appearance.headingFont.startsWith('Caveat'), JSON.stringify(appearance));
    assert(appearance.loadedFonts.includes('Fira Code') && appearance.loadedFonts.includes('Caveat'), JSON.stringify(appearance));
    assert.deepEqual(appearance.logo, scenario === 'mobile' ? { width: 52, height: 65, decoded: true } : { width: 64, height: 80, decoded: true });
    assert.equal(appearance.overflow, false);
    assert.equal(appearance.favicon, '/assets/rusty-head-32.png');
    assert.deepEqual(externalResources, [], 'Rusty must render independently of external services');
    assert.deepEqual(failures, [], 'Local fonts and paint must load');
    await page.screenshot({ path: `target/service-ui-${scenario}.png`, fullPage: true });
    await context.close();
  }
  console.log('Original Rusty header, local fonts and mobile layout work without an external collector');
} finally {
  await browser?.close();
  child.kill('SIGINT');
  await new Promise(done => { if (child.exitCode !== null) done(); else child.once('exit', done); });
  await rm(directory, { recursive: true, force: true });
}
