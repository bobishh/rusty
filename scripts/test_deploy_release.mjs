import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRustyDeploySpec } from './deploy_release.mjs';
import { deployRustyArtifact } from './deploy_release.mjs';
import { fetchRustyDeployConfig } from './fetch_deploy_config.mjs';
import { verifyLiveRelease } from './deploy_release.mjs';

test('live release accepts configured browser discovery and signed-request preflight', async () => {
  const artifact = { sourceSha: 'a'.repeat(40), binarySha256: 'b'.repeat(64), readers: {} };
  const origin = 'https://identity.example';
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push([url, init]);
    if (url.endsWith('/health')) return Response.json({ status: 'ok', buildSha: artifact.sourceSha, artifactSha256: artifact.binarySha256 });
    return new Response(null, { headers: { 'access-control-allow-origin': origin,
      'access-control-allow-methods': 'GET,POST,PUT', 'access-control-allow-headers': 'authorization,content-type,x-rusty-identity-proof' } });
  };
  await verifyLiveRelease('https://rusty.example', artifact, fetcher, [origin]);
  assert.ok(calls.some(([url, init]) => url.endsWith('/.well-known/mesh-lighthouse') && init.headers.Origin === origin));
  assert.ok(calls.some(([, init]) => init.method === 'OPTIONS' && init.headers['Access-Control-Request-Method'] === 'PUT'));
  await assert.rejects(verifyLiveRelease('https://rusty.example', artifact, async (url, init) => {
    if (url.endsWith('/health')) return fetcher(url, init);
    return new Response(null);
  }, [origin]), /Browser origin unavailable/);
  await assert.rejects(verifyLiveRelease('https://rusty.example', artifact, async (url, init) => {
    if (init.method !== 'OPTIONS') return fetcher(url, init);
    return new Response(null, { headers: { 'access-control-allow-origin': origin,
      'access-control-allow-methods': 'GET,POST,PUT', 'access-control-allow-headers': 'content-type' } });
  }, [origin]), /Browser proof headers unavailable/);
});

test('deployment config parser is exported from the release adapter', () => {
  const spec = {
    kind: 'kamal',
    directory: '.release-config/hetzner_playground',
    configFile: 'config/deploy.mesh-lighthouse.yml',
    configSha: 'a'.repeat(40),
    server: 'rusty.example',
    origin: 'https://rusty.example',
  };
  assert.deepEqual(parseRustyDeploySpec(JSON.stringify(spec)), spec);
});

test('pinned deploy config adapter loads release spec parser', () => {
  assert.equal(typeof fetchRustyDeployConfig, 'function');
});

const configRepository = 'https://tangled.org/bobishh.bsky.social/hetzner_kamal';
const configKnot = 'https://knot1.tangled.sh/did:plc:tixq2h74rkvrthusdtkcbaqn';

function configFetchFixture({ failPrimary = false, failKnot = false, received = 'a'.repeat(40) } = {}) {
  const calls = [];
  const pin = { repository: configRepository, commit: 'a'.repeat(40) };
  const spec = JSON.stringify({ kind: 'kamal', directory: '.release-config/hetzner_playground',
    configFile: 'config/deploy.mesh-lighthouse.yml', configSha: pin.commit,
    server: 'rusty.example', origin: 'https://rusty.example' });
  const ports = { pin, workspace: '/release-test', exists: () => false,
    run: (command, args, options) => {
      assert.equal(command, 'git');
      assert.deepEqual(args.slice(0, 4), ['-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never']);
      assert.equal(options.env.GIT_CONFIG_NOSYSTEM, '1');
      assert.equal(options.env.GIT_CONFIG_GLOBAL, '/dev/null');
      assert.equal(options.env.GIT_TERMINAL_PROMPT, '0');
      calls.push(args);
      if (args.includes('fetch')) {
        assert.deepEqual(args.slice(-5, -2), ['--depth=1', '--no-tags', '--']);
        assert.equal(args.at(-1), pin.commit);
        if (args.at(-2) === configRepository && failPrimary) throw new Error('Tangled unavailable');
        if (args.at(-2) === configKnot && failKnot) throw new Error('Knot unavailable');
      }
      if (args.includes('rev-parse')) return `${received}\n`;
      return '';
    } };
  return { calls, fetch: () => fetchRustyDeployConfig(spec, ports) };
}

test('Given Tangled transport failure, when fetching the pinned deployment config, then use its official knot and verify the identical commit before checkout', () => {
  const fixture = configFetchFixture({ failPrimary: true });
  assert.equal(fixture.fetch(), '/release-test/.release-config/hetzner_playground');
  assert.deepEqual(fixture.calls.filter(args => args.includes('fetch')).map(args => args.at(-2)), [configRepository, configKnot]);
  assert.equal(fixture.calls.filter(args => args.includes('checkout')).length, 1);
  assert.ok(fixture.calls.findIndex(args => args.includes('rev-parse')) < fixture.calls.findIndex(args => args.includes('checkout')));
});

test('Given successful Tangled transport, when fetching the pinned deployment config, then keep the primary source without contacting its knot', () => {
  const fixture = configFetchFixture();
  fixture.fetch();
  assert.deepEqual(fixture.calls.filter(args => args.includes('fetch')).map(args => args.at(-2)), [configRepository]);
});

test('Given a different received commit, when either transport returns it, then reject without checkout or another transport attempt', () => {
  for (const failPrimary of [false, true]) {
    const fixture = configFetchFixture({ failPrimary, received: 'b'.repeat(40) });
    assert.throws(fixture.fetch, /differs from the captured commit/);
    assert.equal(fixture.calls.filter(args => args.includes('fetch')).length, failPrimary ? 2 : 1);
    assert.ok(!fixture.calls.some(args => args.includes('checkout')));
  }
});

test('Given both official transports fail, when fetching deployment config, then report failure without checking out configuration', () => {
  const fixture = configFetchFixture({ failPrimary: true, failKnot: true });
  assert.throws(fixture.fetch, /Could not fetch the pinned Rusty configuration/);
  assert.deepEqual(fixture.calls.filter(args => args.includes('fetch')).map(args => args.at(-2)), [configRepository, configKnot]);
  assert.ok(!fixture.calls.some(args => args.includes('checkout') || args.includes('rev-parse')));
});

test('failed live reader-floor verification restores the previous writer', async () => {
  const configSha = 'a'.repeat(40);
  const digest = `sha256:${'c'.repeat(64)}`;
  const config = [
    `image: "<%= ENV['DOCKER_REGISTRY_USERNAME'] %>/mesh-lighthouse"`,
    'service: mesh-lighthouse',
    'proxy:',
    'accessories:',
    'volumes:',
    '  - mesh_lighthouse_blind_20261008:/data',
    '  clickhouse:',
  ].join('\n');
  const artifact = {
    image: `ghcr.io/bobishh/rusty@${digest}`,
    binarySha256: 'd'.repeat(64),
    sourceSha: 'e'.repeat(40),
    sdkSha: 'f'.repeat(40),
    readers: { scopePolicy: 2, managementPolicy: 2, archiveStorage: 1, publicBoardPublication: 1 },
  };
  const spec = JSON.stringify({ kind: 'kamal', directory: '.release-config/hetzner_playground',
    configFile: 'config/deploy.mesh-lighthouse.yml', configSha, server: 'rusty.example', origin: 'https://rusty.example' });
  let aliasCreated = false;
  const calls = [];
  const run = (command, args, options = {}) => {
    calls.push([command, args, options]);
    if (command === 'ssh' && options.input?.includes('docker --config "$config_dir" pull')) {
      assert.equal(options.stdio[0], 'pipe', 'SSH must receive the preparation script on stdin');
    }
    if (command === 'git' && args[2] === 'rev-parse') return `${configSha}\n`;
    if (command === 'git' && args[2] === 'show') return config;
    if (command === 'docker' && args[0] === 'buildx' && args[1] === 'imagetools' && args[2] === 'inspect') {
      if (args[3].includes(':release-') && !aliasCreated) throw Object.assign(new Error('missing'), { stderr: 'manifest unknown' });
      return `Digest: ${digest}\n`;
    }
    if (command === 'docker' && args[2] === 'create') { aliasCreated = true; return ''; }
    if (command === 'ssh' && options.input?.includes("handoff(action")) return '{"version":"release-previous"}\n';
    if (command === 'ssh' && (options.input?.includes('docker inspect') || options.input?.includes('docker image inspect'))) {
      return JSON.stringify({ image: artifact.image, containerImageId: `sha256:${'b'.repeat(64)}`, repoDigests: [`ghcr.io/bobishh/rusty@${digest}`] });
    }
    return '';
  };
  const oldWorkspace = process.env.GITHUB_WORKSPACE;
  const oldToken = process.env.GH_TOKEN;
  process.env.GITHUB_WORKSPACE = '/tmp/rusty-release-test';
  process.env.GH_TOKEN = 'test-token';
  try {
    await assert.rejects(deployRustyArtifact(artifact, 'a'.repeat(64), spec, {
      run,
      readConfig: () => config,
      writeConfig: () => {},
      unlinkConfig: () => {},
      fetch: async () => Response.json({ status: 'ok', buildSha: artifact.sourceSha,
        artifactSha256: artifact.binarySha256, readers: { scopePolicy: 1, managementPolicy: 2, archiveStorage: 1, publicBoardPublication: 1 } }),
      verifyRestored: async () => {},
    }), /reader floor missing/);
    assert.ok(calls.some(([command, args]) => command === 'kamal' && args[0] === 'app' && args[1] === 'start' && args.includes('release-previous')));
    const stopped = calls.findIndex(([command, args]) => command === 'ssh' && args.at(-1).includes("'stop'"));
    const pulled = calls.findIndex(([command, args, options]) => command === 'ssh' && options.input?.includes('docker --config "$config_dir" pull'));
    const prepared = calls.findIndex(([command, args, options]) => command === 'ssh' && options.input?.includes('docker image inspect'));
    const rendered = calls.findIndex(([command, args]) => command === 'kamal' && args[0] === 'config');
    assert.ok(pulled >= 0 && prepared > pulled && stopped > prepared, 'the exact image must be pulled and verified before stopping the previous writer');
    assert.ok(rendered >= 0 && stopped > rendered, 'Kamal must render the deployment config before stopping the previous writer');
    assert.deepEqual(calls[rendered][2].stdio, ['ignore', 'ignore', 'ignore'], 'rendered config and secret values must stay out of logs');
    assert.ok(calls.some(([command, args]) => command === 'kamal' && args[0] === 'app' && args[1] === 'boot'));
    assert.ok(!calls.some(([command, args]) => command === 'kamal' && args[0] === 'deploy'), 'activation must not delete and pull the prepared image again after stopping storage');
    calls.length = 0;
    await assert.rejects(deployRustyArtifact(artifact, 'a'.repeat(64), spec, {
      run: (command, args, options) => {
        if (command === 'ssh' && options?.input?.includes('docker --config "$config_dir" pull')) throw new Error('registry unavailable');
        return run(command, args, options);
      }, readConfig: () => config, writeConfig: () => {}, unlinkConfig: () => {},
    }), /registry unavailable/);
    assert.ok(!calls.some(([command, args]) => command === 'ssh' && args.at(-1).includes("'stop'")), 'failed image preparation must leave the running writer untouched');
    calls.length = 0;
    await assert.rejects(deployRustyArtifact(artifact, 'a'.repeat(64), spec, {
      run: (command, args, options) => {
        if (command === 'ssh' && options?.input?.includes('docker image inspect')) {
          return JSON.stringify({ image: artifact.image, containerImageId: `sha256:${'b'.repeat(64)}`, repoDigests: [`ghcr.io/bobishh/rusty@sha256:${'0'.repeat(64)}`] });
        }
        return run(command, args, options);
      }, readConfig: () => config, writeConfig: () => {}, unlinkConfig: () => {},
    }), /sealed Rusty image digest/);
    assert.ok(!calls.some(([command, args]) => command === 'ssh' && args.at(-1).includes("'stop'")), 'wrong prepared image must leave the running writer untouched');
    calls.length = 0;
    await assert.rejects(deployRustyArtifact(artifact, 'a'.repeat(64), spec, {
      run: (command, args, options = {}) => {
        if (command === 'kamal' && args[0] === 'config') {
          calls.push([command, args, options]);
          throw Object.assign(new Error('private config detail'), { status: 2 });
        }
        return run(command, args, options);
      }, readConfig: () => config, writeConfig: () => {}, unlinkConfig: () => {},
    }), /Kamal config render failed before Rusty storage handoff \(exit 2\)/);
    assert.ok(!calls.some(([command, args]) => command === 'ssh' && args.at(-1).includes("'stop'")), 'invalid Kamal config must leave the running writer untouched');
  } finally {
    if (oldWorkspace === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = oldWorkspace;
    if (oldToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = oldToken;
  }
});
