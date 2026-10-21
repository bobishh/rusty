const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { buildPlan, verifySeal } = require('../.github/scripts/prune-artifacts.cjs');

const now = Date.parse('2026-10-21T16:00:00Z');
const sha = letter => letter.repeat(40);
const digest = letter => letter.repeat(64);
const health = { status: 'ok', buildSha: sha('a'), sdkSha: sha('e'), artifactSha256: digest('a'),
  readers: { scopePolicy: 2, managementPolicy: 1, archiveStorage: 1, publicBoardPublication: 1 } };
const manifest = (letter, run) => ({ sourceSha: sha(letter), sdkSha: sha('e'), binarySha256: digest(letter),
  artifactSha256: digest(letter), candidateId: `${run}-1`, readers: health.readers, writerVersion: 2 });
const artifact = (id, type, letter, run, days = 2) => ({ id, name: `rusty-${type}-${sha(letter)}${type === 'tlc' ? '' : '-1'}`,
  expired: false, size_in_bytes: 10, created_at: new Date(now - days * 86_400_000).toISOString(),
  workflow_run: { id: run, head_sha: sha(letter) } });
const ci = (id, letter, day) => ({ id, path: '.github/workflows/ci.yml', event: 'push', head_branch: 'main',
  head_sha: sha(letter), head_repository: { full_name: 'bobishh/rusty' }, run_attempt: 1,
  created_at: `2026-10-${day}T00:00:00Z`, status: 'completed', conclusion: 'success' });
const deploy = (id, day) => ({ id, path: '.github/workflows/deploy-rusty.yml',
  head_sha: sha('f'), status: 'completed', conclusion: 'success', created_at: `2026-10-${day}T01:00:00Z` });

function fixture() {
  const artifacts = [artifact(1, 'release', 'a', 11), artifact(2, 'deployment', 'a', 21),
    artifact(3, 'release', 'b', 12), artifact(4, 'deployment', 'b', 22),
    artifact(5, 'release', 'c', 13), artifact(6, 'deployment', 'c', 23),
    artifact(7, 'tlc', 'a', 11), artifact(8, 'tlc', 'a', 14, 0.5)];
  const runs = [ci(11, 'a', '20'), ci(12, 'b', '19'), ci(13, 'c', '18'), deploy(21, '20'), deploy(22, '19'), deploy(23, '18')];
  const seals = new Map([[1, manifest('a', 11)], [2, manifest('a', 11)], [3, manifest('b', 12)],
    [4, manifest('b', 12)], [5, manifest('c', 13)], [6, manifest('c', 13)]]);
  return { artifacts, activeRuns: [], runs, health, now, seals,
    readSeal: async a => seals.get(a.id), getRun: async id => runs.find(run => run.id === id) ?? { status: 'completed' } };
}

test('Given active and previous compatible releases, when pruning, then keep their source and deployment seals and expire old diagnostics', async () => {
  const plan = await buildPlan(fixture());
  assert.deepEqual(plan.candidates.map(a => a.id), [5, 6, 7]);
  assert.equal(plan.bytes, 30);
  assert.deepEqual(plan.kept.map(a => a.id), [1, 2, 3, 4, 8]);
});

test('Given a later source CI and an in-flight run, then keep both without replacing the deployed rollback floor', async () => {
  const input = fixture();
  input.runs.push(ci(15, 'd', '21'));
  input.artifacts.push(artifact(9, 'release', 'd', 15), artifact(10, 'tlc', 'd', 16));
  input.seals.set(9, manifest('d', 15));
  input.activeRuns.push({ id: 16, head_sha: sha('d'), path: '.github/workflows/ci.yml' });
  const plan = await buildPlan(input);
  assert.ok(plan.kept.some(a => a.id === 9));
  assert.ok(plan.kept.some(a => a.id === 10));
  assert.ok(plan.kept.some(a => a.id === 3));
});

test('Given an incompatible recent deployment, then retain the earlier compatible rollback by its seal rather than workflow head SHA', async () => {
  const input = fixture();
  input.seals.set(3, { ...manifest('b', 12), readers: { ...health.readers, scopePolicy: 1 } });
  input.seals.set(4, input.seals.get(3));
  const plan = await buildPlan(input);
  assert.deepEqual(plan.candidates.map(a => a.id), [3, 4, 7]);
  assert.ok(plan.kept.some(a => a.id === 5 && a.reason === 'previous compatible deployment'));
});

test('Given a higher active writer floor, then retain rollback with that writer floor instead of an older writer', async () => {
  const input = fixture();
  for (const id of [1, 2, 5, 6]) input.seals.get(id).writerVersion = 3;
  const plan = await buildPlan(input);
  assert.deepEqual(plan.candidates.map(a => a.id), [3, 4, 7]);
});

test('Given an unhealthy service, absent active source, missing rollback source or invalid source CI, then abort before deletion', async () => {
  const cases = [input => { input.health = { ...health, status: 'starting' }; },
    input => { input.artifacts = input.artifacts.filter(a => a.id !== 1); },
    input => { input.artifacts = input.artifacts.filter(a => a.id !== 3); },
    input => { input.runs.push(ci(15, 'd', '21')); },
    input => { input.runs[0].event = 'pull_request'; }];
  for (const change of cases) {
    const input = fixture(); change(input);
    await assert.rejects(buildPlan(input));
  }
});

test('Given unhealthy runtime evidence, when the cleanup entry point runs, then never call the delete API', async () => {
  const prune = require('../.github/scripts/prune-artifacts.cjs');
  const originalFetch = globalThis.fetch;
  let deletions = 0;
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ ...health, status: 'starting' }) });
  try {
    await assert.rejects(prune({ github: { paginate: async () => [], rest: { actions: {
      deleteArtifact: async () => { deletions++; },
    } } }, context: { repo: { owner: 'bobishh', repo: 'rusty' } }, core: {} }), /active Rusty/);
    assert.equal(deletions, 0);
  } finally { globalThis.fetch = originalFetch; }
});

test('Given rollback starts after the first delete, when the cleanup entry point continues, then abort before the second delete', async () => {
  const prune = require('../.github/scripts/prune-artifacts.cjs');
  const input = fixture();
  const originalFetch = globalThis.fetch;
  const deleted = [];
  const actions = {
    listArtifactsForRepo: () => {}, listWorkflowRunsForRepo: () => {}, listWorkflowRuns: () => {},
    getWorkflowRun: async ({ run_id }) => ({ data: await input.getRun(run_id) }),
    deleteArtifact: async ({ artifact_id }) => { deleted.push(artifact_id); },
  };
  const github = { rest: { actions }, paginate: async (method, options) => {
    if (method === actions.listArtifactsForRepo) return input.artifacts;
    if (method === actions.listWorkflowRunsForRepo) return deleted.length > 0 && options.status === 'queued'
      ? [{ id: 31, path: '.github/workflows/deploy-rusty.yml', head_sha: sha('f') }] : [];
    return input.runs.filter(run => run.path === `.github/workflows/${options.workflow_id}`);
  } };
  const summary = { addHeading() { return this; }, addRaw() { return this; }, async write() {} };
  globalThis.fetch = async () => ({ ok: true, json: async () => health });
  try {
    await assert.rejects(prune({ github, context: { repo: { owner: 'bobishh', repo: 'rusty' },
      eventName: 'workflow_dispatch', payload: { inputs: { dry_run: 'false' } } },
    core: { info() {}, summary }, ports: { readSeal: input.readSeal } }), /release or active runs changed/);
    assert.deepEqual(deleted, [5]);
  } finally { globalThis.fetch = originalFetch; }
});

test('Given deployment pending, young release, or unknown artifact, then exclude them from deletion', async () => {
  const input = fixture();
  input.activeRuns.push({ id: 30, path: '.github/workflows/deploy-rusty.yml' });
  input.artifacts.push({ ...artifact(9, 'release', 'd', 15), name: 'unrelated-user-artifact' });
  const plan = await buildPlan(input);
  assert.deepEqual(plan.candidates.map(a => a.id), [7]);
  const quiet = fixture(); quiet.artifacts[4].created_at = new Date(now - 1000).toISOString();
  assert.ok((await buildPlan(quiet)).kept.some(a => a.id === 5));
});

test('Given an archive seal, when checking identity, then verify canonical manifest, exact binary and source run binding', () => {
  const binary = Buffer.from('verified binary');
  const binarySha = createHash('sha256').update(binary).digest('hex');
  const body = { kind: 'tincanban-component-artifact', version: 1, component: 'rusty', sourceSha: sha('a'), sdkSha: sha('e'),
    candidateId: '11-1', image: `ghcr.io/bobishh/rusty@sha256:${digest('a')}`, readers: health.readers,
    writerVersion: 2, binarySha256: binarySha, files: { 'mesh-lighthouse': binarySha } };
  const canonical = value => value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
  const sealed = { ...body, artifactSha256: createHash('sha256').update(JSON.stringify(canonical(body))).digest('hex') };
  const source = artifact(1, 'release', 'a', 11);
  assert.equal(verifySeal(sealed, binary, source), sealed);
  assert.throws(() => verifySeal({ ...sealed, sdkSha: sha('b') }, binary, source));
  assert.throws(() => verifySeal(sealed, Buffer.from('changed'), source));
  assert.throws(() => verifySeal(sealed, binary, { ...source, workflow_run: { id: 99, head_sha: sha('a') } }));
});
