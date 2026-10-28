import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseRustyDeploySpec } from './deploy_release.mjs';

const repository = 'https://tangled.org/bobishh.bsky.social/hetzner_kamal';
const officialKnot = 'https://knot1.tangled.sh/did:plc:tixq2h74rkvrthusdtkcbaqn';
const capturedPin = JSON.parse(readFileSync(new URL('../release/deployment-config.json', import.meta.url), 'utf8'));

/** Fetch public configuration only. Runtime credentials stay in the CI secret store. */
export function fetchRustyDeployConfig(rawSpec = process.env.RUSTY_DEPLOY_SPEC, ports = {}) {
  const spec = parseRustyDeploySpec(rawSpec);
  const pin = ports.pin ?? capturedPin;
  if (pin.repository !== repository || !/^[a-f0-9]{40}$/.test(pin.commit ?? '') || spec.configSha !== pin.commit) {
    throw new Error('Rusty deployment must use the captured Tangled repository and commit');
  }
  const workspace = resolve(ports.workspace ?? process.env.GITHUB_WORKSPACE ?? process.cwd());
  const directory = resolve(workspace, spec.directory);
  if ((ports.exists ?? existsSync)(directory)) throw new Error('Rusty deployment checkout already exists; refusing to overwrite it');
  const run = ports.run ?? ((command, args, options) => execFileSync(command, args, { encoding: 'utf8', ...options }));
  const options = { env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' }, timeout: 120000 };
  const git = args => run('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never', ...args], options);
  git(['init', '--quiet', directory]);
  const fetchFrom = remote => git(['-C', directory, 'fetch', '--depth=1', '--no-tags', '--', remote, pin.commit]);
  try { fetchFrom(pin.repository); }
  catch (primaryError) {
    // The hosting knot serves the same repository; the exact commit stays pinned.
    try { fetchFrom(officialKnot); }
    catch (knotError) {
      throw new AggregateError([primaryError, knotError], 'Could not fetch the pinned Rusty configuration from Tangled or its official knot');
    }
  }
  const received = git(['-C', directory, 'rev-parse', 'FETCH_HEAD^{commit}']).trim();
  if (received !== pin.commit) throw new Error('Rusty fetched configuration differs from the captured commit');
  git(['-C', directory, 'checkout', '--quiet', '--detach', pin.commit]);
  return directory;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) fetchRustyDeployConfig();
