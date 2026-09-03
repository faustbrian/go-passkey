# Goal: planned go-passkey boundary

Status: planned

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
  checksum-verified `go-library-tools` v1.4.0 tooling.
- Do not claim a public package identifier, installation path, runtime API,
  compatibility promise, or released behavior.

## Deferred implementation

Source packages, nested modules, dependencies, protocol and API contracts,
behavior, hardening evidence, compatibility commitments, tags, and releases
remain outside this planning-only goal. They require separately authorized
work and their own executable acceptance evidence.
