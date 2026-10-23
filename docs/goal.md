# Goal: go-passkey implementation

[Documentation map](index.md) · [Repository README](../README.md)
[Next: go-passkey](../README.md)

Status: in progress; incomplete and non-releasable

The authorized identity-platform implementation supersedes the planning-only
restriction below. Current component APIs and their limitations are described
in the [README](../README.md). They do not close the full passkey goal.

Required end state: authenticated enrollment, passkey-first registration,
identified and discoverable/usernameless signin, conditional option generation,
safe metadata listing, fresh-proof rename/deletion and last-recovery-method
policy. Preserve stable opaque handles and credential-ID uniqueness across the
complete RP namespace, exact tenant isolation, UV, original remember policy,
backup/counter semantics and typed selected extension outputs. Protocol
verification and credential state remain with WebAuthn; identity mappings and
required session effects commit through the sole existing coordinator.

The complete consumer journey, denial/replay/concurrency/rollback/recovery,
real authenticator interoperability, public adoption, independent review and
mandatory final qualification remain required. No helper or component test is
whole-workflow completion.

## Preserved planning baseline

The following records the earlier planning-only scope; it does not prohibit
the authorized implementation above or establish current runtime completion.

The coordination plan identifies `github.com/faustbrian/go-passkey` as the
future storage-neutral owner of identity-facing passkey enrolment,
discoverable credentials, passwordless signup and sign-in, synced and backup
state, credential naming, listing, deletion, and passkey-first policy.

The source planning record is
`.ai/identity-platform/goals/passkey.md` in the Golib coordination tree, with
SHA-256
`b2ffab7746ee7a8f984d6861efb8c08c547bbcc8aeda9f741e05be9d75b840fb`.
That record contains proposed contracts; it is not implementation evidence.

## Current planning acceptance

- Keep this repository visibly planned and absent from installable consumer
  catalogs.
- Record the frozen Service Edge family, passkey capabilities, ownership, and
  delivery lifecycle in schema-v2 engineering metadata.
- Validate the metadata locally and in hosted CI with immutable,
  checksum-verified public `go-library-tools` v2.1.2 tooling. Ordinary checks
  retain offline structure/links and every-change secrets; scheduled/manual
  checks retain online authority refresh. No runtime or release proof follows.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, or released behavior.
- Keep the module non-releasable and its delivery release-blocked until the
  private reporting process, planned trust boundary, and deferred security
  risks in [`SECURITY.md`](../SECURITY.md) are resolved by an authorized
  implementation goal.

## Deferred implementation

Source packages, nested modules, dependencies, protocol and API contracts,
behavior, hardening evidence, compatibility commitments, tags, and releases
remain outside this planning-only goal. They require separately authorized
work and their own executable acceptance evidence.
