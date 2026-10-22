import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRustyDeploySpec } from './deploy_release.mjs';
import { deployRustyArtifact } from './deploy_release.mjs';
import { fetchRustyDeployConfig } from './fetch_deploy_config.mjs';

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
    assert.ok(pulled >= 0 && prepared > pulled && stopped > prepared, 'the exact image must be pulled and verified before stopping the previous writer');
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
  } finally {
    if (oldWorkspace === undefined) delete process.env.GITHUB_WORKSPACE;
    else process.env.GITHUB_WORKSPACE = oldWorkspace;
    if (oldToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = oldToken;
  }
});
