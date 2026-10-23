import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';

const digestPattern = /^sha256:[a-f0-9]{64}$/;
const sourceImagePattern = /^ghcr\.io\/bobishh\/rusty@sha256:[a-f0-9]{64}$/;

export function parseRustyDeploySpec(raw) {
  const spec = JSON.parse(raw ?? 'null');
  if (!spec || spec.kind !== 'kamal' || !/^\.release-config\/[A-Za-z0-9_-]+$/.test(spec.directory ?? '') ||
    spec.configFile !== 'config/deploy.mesh-lighthouse.yml' || !/^[a-f0-9]{40}$/.test(spec.configSha ?? '') ||
    !/^[A-Za-z0-9.-]+$/.test(spec.server ?? '') || !/^https:\/\/[^/]+$/.test(spec.origin ?? '')) {
    throw new Error('Configure the exact existing Rusty Kamal deployment before activation');
  }
  return spec;
}

export function rustyReleaseTag(releaseId) {
  if (!/^[a-f0-9]{64}$/.test(releaseId ?? '')) throw new Error('Invalid Rusty release identity');
  return `release-${releaseId}`;
}

export function kamalImageConfig(source, repository, keyFile) {
  if (!/^ghcr\.io\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '')) throw new Error('Invalid sealed Rusty image repository');
  const imageLine = /^image: "<%= ENV\['DOCKER_REGISTRY_USERNAME'\] %>\/mesh-lighthouse"$/gm;
  const matches = [...source.matchAll(imageLine)];
  if (matches.length !== 1 || !/^service: mesh-lighthouse$/m.test(source) ||
    !/^proxy:$/m.test(source) || !/^accessories:$/m.test(source) ||
    !/^volumes:\n  - mesh_lighthouse_blind_20261008:\/data$/m.test(source) ||
    !/^  clickhouse:$/m.test(source)) throw new Error('Pinned Rusty Kamal config differs from the preserved production service');
  let config = source.replace(imageLine, `image: "${repository.slice('ghcr.io/'.length)}"`);
  if (keyFile) {
    if (!/^\/[A-Za-z0-9_./-]+$/.test(keyFile) || keyFile.split('/').includes('..') || /^ssh:$/m.test(config)) {
      throw new Error('Kamal deployment requires a safe SSH key path and no conflicting SSH config');
    }
    config += `\nssh:\n  keys:\n    - ${JSON.stringify(keyFile)}\n  keys_only: true\n`;
  }
  return config;
}

export function parseImageDigest(output) {
  const match = String(output).match(/^Digest:\s*(sha256:[a-f0-9]{64})\s*$/m);
  if (!match) throw new Error('Registry did not report an exact image digest');
  return match[1];
}

export function assertRustyRuntimeImageReceipt(receipt, artifact) {
  const expectedDigest = artifact.image.slice(artifact.image.indexOf('@') + 1);
  if (receipt.image !== artifact.image || !/^sha256:[a-f0-9]{64}$/.test(receipt.containerImageId ?? '') ||
    !Array.isArray(receipt.repoDigests) || !receipt.repoDigests.includes(`ghcr.io/bobishh/rusty@${expectedDigest}`)) {
    throw new Error('Kamal host did not confirm the sealed Rusty image digest');
  }
  return receipt;
}

function defaultRun(command, args, options = {}) {
  return execFileSync(command, args, { encoding: 'utf8', ...options });
}

function storageHandoff(run, spec, releaseId, action) {
  const args = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=20'];
  if (process.env.RUSTY_SSH_KEY_FILE) args.push('-i', process.env.RUSTY_SSH_KEY_FILE);
  const output = run('ssh', [...args, `root@${spec.server}`, `python3 - '${action}' '${releaseId}'`], {
    input: readFileSync(new URL('./storage_handoff.py', import.meta.url), 'utf8'), timeout: 180000,
  });
  const receipt = JSON.parse(output.trim().split('\n').at(-1));
  if (!/^[A-Za-z0-9_.-]+$/.test(receipt.version ?? '')) throw new Error('Invalid previous Rusty version');
  return receipt;
}

function notFound(error) {
  const detail = String(error?.stderr ?? '');
  return /manifest unknown|manifest not found|name unknown|not found/i.test(detail);
}

function inspectDigest(run, reference) {
  return parseImageDigest(run('docker', ['buildx', 'imagetools', 'inspect', reference]));
}

function ensureReleaseAlias(run, artifact, releaseId) {
  const sourceDigest = artifact.image.slice(artifact.image.indexOf('@') + 1);
  if (!digestPattern.test(sourceDigest) || inspectDigest(run, artifact.image) !== sourceDigest) {
    throw new Error('Sealed Rusty image reference does not resolve to its recorded digest');
  }
  const repository = artifact.image.slice(0, artifact.image.indexOf('@'));
  const alias = `${repository}:${rustyReleaseTag(releaseId)}`;
  let aliasDigest;
  try { aliasDigest = inspectDigest(run, alias); }
  catch (error) {
    if (!notFound(error)) throw new Error('Cannot establish the existing Rusty release image tag');
  }
  if (aliasDigest && aliasDigest !== sourceDigest) throw new Error('Rusty release image tag already names another sealed artifact');
  if (!aliasDigest) {
    run('docker', ['buildx', 'imagetools', 'create', '--prefer-index=false', '--tag', alias, artifact.image]);
    aliasDigest = inspectDigest(run, alias);
  }
  if (aliasDigest !== sourceDigest) throw new Error('Rusty release image tag changed during publication');
  return { alias, sourceDigest };
}

function validateKamalConfig(run, configArgs, options) {
  try {
    run('kamal', ['config', ...configArgs], { ...options, stdio: ['ignore', 'ignore', 'ignore'] });
  } catch (error) {
    throw new Error(`Kamal config render failed before Rusty storage handoff (exit ${error?.status ?? 'unknown'})`);
  }
}

function preparePublicImage(run, spec, version, artifact) {
  const args = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=20'];
  if (process.env.RUSTY_SSH_KEY_FILE) args.push('-i', process.env.RUSTY_SSH_KEY_FILE);
  // The release is public. Keep expiring CI registry credentials out of host pull authorization.
  const script = `set -eu\nconfig_dir=$(mktemp -d /tmp/rusty-image-pull.XXXXXXXX)\ntrap 'rm -rf "$config_dir"' EXIT\ndocker --config "$config_dir" pull "$1"\ndocker image tag "$1" "$2"\n`;
  const alias = `ghcr.io/bobishh/rusty:${version}`;
  const remote = ['sh', '-s', '--', artifact.image, alias].map(value => `'${String(value).replaceAll("'", "'\\''")}'`).join(' ');
  run('ssh', [...args, `root@${spec.server}`, remote], { input: script, timeout: 180000, stdio: ['pipe', 'inherit', 'inherit'] });
}

function verifyPreparedImage(run, spec, version, artifact) {
  const args = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=20'];
  if (process.env.RUSTY_SSH_KEY_FILE) args.push('-i', process.env.RUSTY_SSH_KEY_FILE);
  const image = `ghcr.io/bobishh/rusty:${version}`;
  const script = `set -eu\nimage_id=$(docker image inspect --format '{{.Id}}' "$1")\nrepo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$image_id")\nprintf '{"image":"%s","containerImageId":"%s","repoDigests":%s}\\n' "$2" "$image_id" "$repo_digests"\n`;
  const remote = ['sh', '-s', '--', image, artifact.image].map(value => `'${String(value).replaceAll("'", "'\\''")}'`).join(' ');
  const output = run('ssh', [...args, `root@${spec.server}`, remote], { input: script, timeout: 60000 });
  return assertRustyRuntimeImageReceipt(JSON.parse(output.trim().split('\n').at(-1)), artifact);
}

function verifyOnHost(run, spec, version, artifact) {
  const keyArgs = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=20'];
  if (process.env.RUSTY_SSH_KEY_FILE) keyArgs.push('-i', process.env.RUSTY_SSH_KEY_FILE);
  const script = `set -eu\nname="$1"\ncontainer=$(docker inspect --format '{{.Id}}' "$name")\nimage_id=$(docker inspect --format '{{.Image}}' "$container")\nrepo_digests=$(docker image inspect --format '{{json .RepoDigests}}' "$image_id")\nprintf '{"image":"%s","containerImageId":"%s","repoDigests":%s}\\n' "$2" "$image_id" "$repo_digests"\n`;
  const name = `mesh-lighthouse-web-${version}`;
  const remote = ['sh', '-s', '--', name, artifact.image].map(value => `'${String(value).replaceAll("'", "'\\''")}'`).join(' ');
  const output = run('ssh', [...keyArgs, `root@${spec.server}`, remote], { input: script, timeout: 60000 });
  const receipt = JSON.parse(output.trim().split('\n').at(-1));
  return assertRustyRuntimeImageReceipt(receipt, artifact);
}

async function verifyLiveRelease(origin, artifact, fetcher = fetch) {
  const response = await fetcher(`${origin}/health`, { redirect: 'error', signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw new Error(`Rusty health returned ${response.status}`);
  const health = await response.json();
  if (health.status !== 'ok' || health.buildSha !== artifact.sourceSha || health.artifactSha256 !== artifact.binarySha256) {
    throw new Error('Running Rusty does not match sealed release artifact');
  }
  for (const [schema, floor] of Object.entries(artifact.readers)) {
    if ((health.readers?.[schema] ?? 0) < floor) throw new Error(`Rusty reader floor missing: ${schema}`);
  }
}

async function waitForRestoredHealth(origin, fetcher = fetch) {
  let lastError;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      const response = await fetcher(`${origin}/health`, { redirect: 'error', signal: AbortSignal.timeout(3000) });
      if (response.ok && (await response.json()).status === 'ok') return;
      lastError = new Error(`Restored Rusty health returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  throw lastError ?? new Error('Restored Rusty did not become healthy');
}

export async function deployRustyArtifact(artifact, releaseId, rawSpec = process.env.RUSTY_DEPLOY_SPEC, ports = {}) {
  const spec = parseRustyDeploySpec(rawSpec);
  if (!sourceImagePattern.test(artifact.image ?? '') || !digestPattern.test(`sha256:${artifact.binarySha256 ?? ''}`) ||
    !/^[a-f0-9]{40}$/.test(artifact.sourceSha ?? '') || !/^[a-f0-9]{40}$/.test(artifact.sdkSha ?? '')) {
    throw new Error('Unsealed native deployment request');
  }
  const version = rustyReleaseTag(releaseId);
  const repository = artifact.image.slice(0, artifact.image.indexOf('@'));
  const infraDirectory = resolve(process.env.GITHUB_WORKSPACE ?? process.cwd(), spec.directory);
  const run = ports.run ?? defaultRun;
  const actualConfigSha = run('git', ['-C', infraDirectory, 'rev-parse', 'HEAD']).trim();
  if (actualConfigSha !== spec.configSha) throw new Error('Rusty Kamal configuration checkout differs from the captured commit');
  const baseConfig = join(infraDirectory, spec.configFile);
  const temporaryConfig = join(infraDirectory, 'config', `.deploy.mesh-lighthouse.${version}.yml`);
  const originalConfig = ports.readConfig ? ports.readConfig(baseConfig) : readFileSync(baseConfig, 'utf8');
  const pinnedConfig = run('git', ['-C', infraDirectory, 'show', `${spec.configSha}:${spec.configFile}`]);
  if (pinnedConfig !== originalConfig) throw new Error('Rusty Kamal config file differs from its pinned commit');
  const deployedConfig = kamalImageConfig(originalConfig, repository, process.env.RUSTY_SSH_KEY_FILE);
  const token = process.env.GH_TOKEN;
  if (!token) throw new Error('GitHub package credentials are required for the Rusty release image tag');
  run('docker', ['login', 'ghcr.io', '--username', process.env.GITHUB_ACTOR ?? 'github-actions', '--password-stdin'], { input: `${token}\n` });
  const { alias, sourceDigest } = ensureReleaseAlias(run, artifact, releaseId);
  if (ports.writeConfig) ports.writeConfig(temporaryConfig, deployedConfig);
  else writeFileSync(temporaryConfig, deployedConfig, { flag: 'wx', mode: 0o600 });
  let receipt;
  try {
    const environment = { ...process.env, SERVER_IP: spec.server, VERSION: version,
      DOCKER_REGISTRY_PASSWORD: process.env.DOCKER_REGISTRY_PASSWORD ?? token };
    const options = { cwd: infraDirectory, env: environment, timeout: 900000, stdio: 'inherit' };
    const configArgs = ['--skip-hooks', '--version', version, '--config-file', temporaryConfig];
    validateKamalConfig(run, configArgs, options);
    preparePublicImage(run, spec, version, artifact);
    verifyPreparedImage(run, spec, version, artifact);
    try {
      storageHandoff(run, spec, releaseId, 'stop');
      // app boot activates the verified local image; deploy --skip-push would delete and pull it again.
      run('kamal', ['app', 'boot', ...configArgs], options);
      receipt = verifyOnHost(run, spec, version, artifact);
      if (!receipt.repoDigests.includes(`ghcr.io/bobishh/rusty@${sourceDigest}`)) throw new Error('Running Rusty image differs from the sealed release digest');
      if (ports.verifyLive) await ports.verifyLive(spec.origin, artifact);
      else await verifyLiveRelease(spec.origin, artifact, ports.fetch ?? fetch);
    } catch (error) {
      try {
        const previous = storageHandoff(run, spec, releaseId, 'restore');
        run('kamal', ['app', 'start', '--skip-hooks', '--version', previous.version, '--config-file', temporaryConfig], options);
        if (ports.verifyRestored) await ports.verifyRestored(spec.origin);
        else await waitForRestoredHealth(spec.origin, ports.fetch ?? fetch);
      } catch (restoreError) {
        throw new AggregateError([error, restoreError], 'Rusty activation failed and the previous writer could not be restored');
      }
      throw error;
    }
    return { image: artifact.image, releaseTag: alias, sourceDigest, ...receipt };
  } finally {
    if (ports.unlinkConfig) ports.unlinkConfig(temporaryConfig);
    else unlinkSync(temporaryConfig);
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${resolve(process.argv[1])}`).href) {
  const [artifactPath, releaseId] = process.argv.slice(2);
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  await deployRustyArtifact(artifact, releaseId);
}
