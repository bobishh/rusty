# Blind storage models

Finite executable TLA+ specifications for the current opaque-object protocol.
They do not reactivate or validate the former readable Keeper architecture.
TLC is bounded model checking, not a proof of the Rust/browser implementation.

`BlindUploadRetry` distinguishes visible renamed bytes from a confirmed durable
object. It checks receipt-after-directory-sync, immutable duplicate retry, lost
reply and current authorization. A directory-sync failure may leave a visible file;
retry must confirm durability before returning a signed receipt. The visible-only
mutant represents that discovered bug; the skip-policy mutant bypasses revocation.

`BlindCheckpoint` checks two candidates for one frontier: durable replacement,
durable manifest, then pruning and receipt; one crash can interrupt any stage.
A matching orphan can resume after a later append; stale competing candidates
cannot win that frontier. A later append remains retained. Exact retries do not
rewrite replacement bytes. Mutants acknowledge early, prune before replacement,
or rewrite an identical retry. Successful file/manifest actions assume successful
file+directory fsync; the separate upload model distinguishes failed directory sync.

Mapping: `src/blind.rs` (`BlindStore::save`, `atomic_write`, `sync_directory`),
`src/checkpoint.rs` (`checkpoint`, `recover_checkpoint_scopes`, pruning).
`visible_object_retry_requires_directory_durability_before_receipt` and
`checkpoint_retry_confirms_visible_replacement_and_manifest_before_pruning`
inject failure after rename and keep it active through retry. They require refusal
of a receipt/pruning until directory sync recovers, with unchanged object bytes and
sequence. Existing native tests cover checkpoint CAS, orphan/expiry recovery,
current owner policy, retained-floor validation and restart.

Authority and cryptography are abstract Booleans; immutable IDs are symbols.
This model checks safety only, not service availability, network timing, arbitrary
fsync/power-loss semantics, quotas, receipt signatures, browser encryption or
client cursor updates. The upload model bounds two attempts; checkpoint model
bounds two competing candidates, one later append and one crash at frontier 2.

CI installs official TLC 1.7.4 with SHA-256 verification, requires exact expected
counterexamples, and retains logs for seven days. Run locally with Java and Python:

```sh
python3 formal/tla/run_models.py --jar /absolute/path/tla2tools.jar --logs /tmp/rusty-tlc
```

Never accept any nonzero exit as a successful negative check: parser errors,
unspecified states and unexpected invariant failures are failures of the runner.
