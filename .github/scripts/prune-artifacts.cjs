const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const day = 86_400_000;
const sha = value => /^[a-f0-9]{40}$/.test(value ?? '');
const digest = value => /^[a-f0-9]{64}$/.test(value ?? '');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const ordered = value => value && typeof value === 'object'
  ? Array.isArray(value) ? value.map(ordered)
    : Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])])) : value;
const canonical = value => JSON.stringify(ordered(value));
const releaseName = /^rusty-(release|deployment)-([a-f0-9]{40})-([1-9]\d*)$/;
const diagnosticName = /^rusty-tlc-[a-f0-9]{40}$/;
const sourceRun = run => run?.path === '.github/workflows/ci.yml' && run.event === 'push' &&
  run.head_branch === 'main' && run.status === 'completed' && run.conclusion === 'success' &&
  run.head_repository?.full_name === 'bobishh/rusty';
const deployRun = run => run?.path === '.github/workflows/deploy-rusty.yml';

function verifySeal(manifest, binary, artifact) {
  const { artifactSha256, ...body } = manifest;
  const name = artifact.name.match(releaseName);
  const candidate = /^([1-9]\d*)-([1-9]\d*)$/.exec(manifest.candidateId ?? '');
  if (!name || !candidate || manifest.kind !== 'tincanban-component-artifact' || manifest.version !== 1 ||
      manifest.component !== 'rusty' || !sha(manifest.sourceSha) || !sha(manifest.sdkSha) ||
      !digest(artifactSha256) || hash(canonical(body)) !== artifactSha256 ||
      !/^ghcr\.io\/bobishh\/rusty@sha256:[a-f0-9]{64}$/.test(manifest.image ?? '') ||
      !manifest.readers || Array.isArray(manifest.readers) || Object.keys(manifest.readers).length === 0 ||
      !Object.values(manifest.readers).every(value => Number.isSafeInteger(value) && value >= 1) ||
      !Number.isSafeInteger(manifest.writerVersion) || manifest.writerVersion < 1 ||
      Object.keys(manifest.files ?? {}).join() !== 'mesh-lighthouse' ||
      !digest(manifest.binarySha256) || manifest.files['mesh-lighthouse'] !== manifest.binarySha256 ||
      hash(binary) !== manifest.binarySha256 || name[2] !== manifest.sourceSha || name[3] !== candidate[2] ||
      name[1] === 'release' && (artifact.workflow_run?.id !== Number(candidate[1]) || artifact.workflow_run?.head_sha !== manifest.sourceSha)) {
    throw new Error(`Invalid sealed Rusty artifact ${artifact.id}`);
  }
  return manifest;
}

function validHealth(health) {
  if (health?.status !== 'ok' || !sha(health.buildSha) || !sha(health.sdkSha) || !digest(health.artifactSha256) ||
      !health.readers || Array.isArray(health.readers) || Object.keys(health.readers).length === 0 ||
      !Object.values(health.readers).every(value => Number.isSafeInteger(value) && value >= 1)) {
    throw new Error('Cannot establish active Rusty release and reader floors');
  }
}

function compatible(manifest, health, writerFloor = 2) {
  return manifest.writerVersion >= writerFloor && Object.entries(health.readers).every(([schema, floor]) =>
    Number.isSafeInteger(manifest.readers[schema]) && manifest.readers[schema] >= floor);
}

async function buildPlan({ artifacts, activeRuns, runs, health, readSeal, getRun, now = Date.now() }) {
  validHealth(health);
  const reasons = new Map();
  const protect = (artifact, reason) => reasons.set(artifact.id, reason);
  const live = artifacts.filter(artifact => artifact.expired === false);
  const sourceArtifacts = live.filter(artifact => artifact.name.startsWith('rusty-release-') && releaseName.test(artifact.name));
  const sealCache = new Map();
  const seal = async artifact => {
    if (!sealCache.has(artifact.id)) {
      const manifest = await readSeal(artifact);
      const [runId, attempt] = manifest.candidateId.split('-').map(Number);
      const run = await getRun(runId);
      if (!sourceRun(run) || run.head_sha !== manifest.sourceSha || run.run_attempt < attempt) {
        throw new Error(`Artifact ${artifact.id} has no successful exact source CI`);
      }
      sealCache.set(artifact.id, manifest);
    }
    return sealCache.get(artifact.id);
  };
  const preservedSeals = new Map();
  for (const artifact of sourceArtifacts.filter(value => value.workflow_run?.head_sha === health.buildSha)) {
    const manifest = await seal(artifact);
    if (manifest.sourceSha === health.buildSha && manifest.sdkSha === health.sdkSha &&
        manifest.binarySha256 === health.artifactSha256 && compatible(manifest, health)) {
      preservedSeals.set(manifest.artifactSha256, 'active');
    }
  }
  if (preservedSeals.size === 0) throw new Error('Active sealed source artifact unavailable; retain all artifacts');
  const activeSeals = new Set(preservedSeals.keys());
  const writerFloor = Math.max(...[...sealCache.values()].filter(manifest => activeSeals.has(manifest.artifactSha256))
    .map(manifest => manifest.writerVersion));
  const latest = runs.filter(sourceRun).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
  if (!latest) throw new Error('Latest successful push CI is unavailable');
  const latestArtifacts = sourceArtifacts.filter(artifact => artifact.workflow_run?.id === latest.id);
  if (latestArtifacts.length === 0) throw new Error('Latest successful push CI source artifact unavailable');
  for (const artifact of latestArtifacts) {
    const manifest = await seal(artifact);
    preservedSeals.set(manifest.artifactSha256, preservedSeals.get(manifest.artifactSha256) ?? 'latest successful push CI');
  }

  // Deployment head_sha may name workflow code rather than the recovered release. Read the seal.
  const deployments = runs.filter(run => deployRun(run) && run.status === 'completed' && run.conclusion === 'success')
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  for (const run of deployments) {
    const copies = live.filter(artifact => artifact.workflow_run?.id === run.id && artifact.name.startsWith('rusty-deployment-'));
    let found = false;
    for (const artifact of copies) {
      const manifest = await seal(artifact);
      if (activeSeals.has(manifest.artifactSha256) || !compatible(manifest, health, writerFloor)) continue;
      const source = sourceArtifacts.find(value => value.name === `rusty-release-${manifest.sourceSha}-${manifest.candidateId.split('-')[1]}` &&
        value.workflow_run?.id === Number(manifest.candidateId.split('-')[0]));
      if (!source || (await seal(source)).artifactSha256 !== manifest.artifactSha256) {
        throw new Error('Compatible rollback source is unavailable; retain all artifacts');
      }
      preservedSeals.set(manifest.artifactSha256, 'previous compatible deployment');
      found = true;
    }
    if (found) break;
  }

  const pendingDeploy = activeRuns.some(deployRun);
  const activeIds = new Set(activeRuns.map(run => run.id));
  const activeShas = new Set(activeRuns.map(run => run.head_sha));
  const protectedNames = new Set([...sealCache.values()].filter(manifest => preservedSeals.has(manifest.artifactSha256))
    .map(manifest => `${manifest.sourceSha}-${manifest.candidateId.split('-')[1]}`));
  const candidates = [];
  for (const artifact of artifacts) {
    const age = now - Date.parse(artifact.created_at);
    const release = releaseName.test(artifact.name);
    const diagnostic = diagnosticName.test(artifact.name) || artifact.name.endsWith('.dockerbuild');
    if (artifact.expired || !Number.isFinite(age) || age < 0 || !(release || diagnostic)) { protect(artifact, 'unknown or expired'); continue; }
    if (activeIds.has(artifact.workflow_run?.id) || release && activeShas.has(artifact.workflow_run?.head_sha)) { protect(artifact, 'in-flight run'); continue; }
    if (release && pendingDeploy) { protect(artifact, 'deployment pending'); continue; }
    if (release) {
      // Only protected revisions need archive reads; obsolete copies are bounded by exact known names and completed runs.
      const name = artifact.name.match(releaseName);
      if (protectedNames.has(`${name[2]}-${name[3]}`)) {
        const manifest = await seal(artifact);
        if (preservedSeals.has(manifest.artifactSha256)) { protect(artifact, preservedSeals.get(manifest.artifactSha256)); continue; }
      }
      if (age < 3_600_000) { protect(artifact, 'new release grace period'); continue; }
    } else if (age < day) { protect(artifact, 'diagnostic under one day'); continue; }
    const run = await getRun(artifact.workflow_run?.id);
    if (run?.status !== 'completed') { protect(artifact, 'run not completed'); continue; }
    candidates.push(artifact);
  }
  return { candidates, kept: artifacts.filter(artifact => reasons.has(artifact.id)).map(artifact => ({
    id: artifact.id, name: artifact.name, bytes: artifact.size_in_bytes, reason: reasons.get(artifact.id),
  })), protectedSeals: [...sealCache].filter(([, manifest]) => preservedSeals.has(manifest.artifactSha256)).map(([id, manifest]) => ({
    id, artifactSha256: manifest.artifactSha256, binarySha256: manifest.binarySha256, sourceSha: manifest.sourceSha,
    candidateId: manifest.candidateId, readers: manifest.readers, writerVersion: manifest.writerVersion,
  })), bytes: candidates.reduce((total, artifact) => total + artifact.size_in_bytes, 0) };
}

module.exports = async ({ github, context, core }) => {
  const { owner, repo } = context.repo;
  if (owner !== 'bobishh' || repo !== 'rusty') throw new Error('Rusty artifact cleanup requires bobishh/rusty');
  const api = github.rest.actions;
  const paginate = (method, options = {}) => github.paginate(method, { owner, repo, per_page: 100, ...options });
  const active = async () => (await Promise.all(['queued', 'in_progress', 'waiting', 'pending', 'requested'].map(status =>
    paginate(api.listWorkflowRunsForRepo, { status })))).flat();
  const readHealth = async () => {
    const response = await fetch('https://ingest.meta-uber-engineer.dev/health', { redirect: 'error', signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Rusty health unavailable (${response.status})`);
    const health = await response.json(); validHealth(health); return health;
  };
  const [artifacts, activeRuns, ci, deployments, health] = await Promise.all([
    paginate(api.listArtifactsForRepo), active(), paginate(api.listWorkflowRuns, { workflow_id: 'ci.yml', branch: 'main', status: 'success' }),
    paginate(api.listWorkflowRuns, { workflow_id: 'deploy-rusty.yml', branch: 'main', status: 'success' }), readHealth(),
  ]);
  const runCache = new Map([...ci, ...deployments, ...activeRuns].map(run => [run.id, run]));
  const getRun = async id => {
    if (!runCache.has(id)) runCache.set(id, (await api.getWorkflowRun({ owner, repo, run_id: id })).data);
    return runCache.get(id);
  };
  const readSeal = async artifact => {
    const directory = mkdtempSync(join(tmpdir(), 'rusty-retention-'));
    try {
      const archive = join(directory, 'artifact.zip');
      writeFileSync(archive, execFileSync('gh', ['api', `repos/${owner}/${repo}/actions/artifacts/${artifact.id}/zip`],
        { maxBuffer: 64 * 1024 * 1024, timeout: 60_000 }));
      const manifest = JSON.parse(execFileSync('unzip', ['-p', archive, 'artifact.json'], { encoding: 'utf8', maxBuffer: 1024 * 1024 }));
      const binary = execFileSync('unzip', ['-p', archive, 'mesh-lighthouse'], { maxBuffer: 64 * 1024 * 1024 });
      return verifySeal(manifest, binary, artifact);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  };
  const plan = await buildPlan({ artifacts, activeRuns, runs: [...ci, ...deployments], health, getRun, readSeal });
  const dryRun = context.eventName === 'workflow_dispatch' && String(context.payload.inputs?.dry_run) === 'true';
  // Establish the whole plan before any delete; changed runtime or new work invalidates it.
  if (!dryRun && (canonical(await readHealth()) !== canonical(health) ||
      canonical((await active()).map(run => run.id).sort()) !== canonical(activeRuns.map(run => run.id).sort()))) {
    throw new Error('Rusty release or active runs changed during cleanup planning');
  }
  for (const artifact of plan.candidates) {
    core.info(`${dryRun ? 'Would delete' : 'Delete'} ${artifact.id} ${artifact.name} (${artifact.size_in_bytes} bytes)`);
    if (!dryRun) await api.deleteArtifact({ owner, repo, artifact_id: artifact.id });
  }
  core.info(`Preserved: ${JSON.stringify(plan.kept)}`);
  core.info(`Protected seals: ${JSON.stringify(plan.protectedSeals)}`);
  await core.summary.addHeading(dryRun ? 'Rusty artifact cleanup preview' : 'Rusty artifact cleanup')
    .addRaw(`${plan.candidates.length} artifacts, ${plan.bytes} bytes ${dryRun ? 'eligible' : 'removed'}. Active release, compatible rollback, latest successful push CI and in-flight runs retained. Caches and container images untouched.\n`).write();
  return plan;
};
module.exports.buildPlan = buildPlan;
module.exports.verifySeal = verifySeal;
