# go-passkey

> **Experimental, incomplete and unreleased.** Selected native existing-account
> enrollment, identified/discoverable signin and session APIs exist. Passkey-first
> signup, complete management and platform qualification remain work.

`go-passkey` implements the Golib boundary for identity-facing passkey
enrolment, discoverable credentials, passwordless signup and sign-in, synced
and backup state, credential naming, listing, deletion, and passkey-first
policy. The plan keeps those concepts separate from WebAuthn verification,
browser interfaces, non-discoverable security-key policy, and session
persistence.

## Current API

- `UserHandlePolicy.Generate` creates a random opaque 32-byte handle for first
  enrollment. Persist and reuse the first committed identity/RP mapping; never
  regenerate an existing handle on ordinary reads or retries.
- `NewUserHandle` imports exact stored bytes without normalization or aliasing.
  Protocol/storage projection is explicit; implicit JSON/text export and
  diagnostic disclosure are prohibited.
- `NewDeviceLabel` preserves bounded UTF-8 display text. A label is not device
  identity, authenticator provenance or authorization. Escape its explicitly
  projected text for the output medium.
- The [PostgreSQL module](postgres/README.md) owns RP-wide mappings and current
  passkey session authority through the existing kernel and MFA owners. Its
  experimental APIs compose fresh-proof enrollment, explicit identified or
  identifier-free resident login and safe
  inventory with actual protocol, risk and session owners. Public-consumer
  qualification and complete independent workflow review remain unfinished.

These are implementation prerequisites, not a complete authentication product.
The modules remain non-releasable. [Documentation map](docs/index.md).

## Planned responsibility

The root package owns the storage-neutral boundary for passkey policy,
registration and authentication flows, credential profiles, stable user-handle
policy, backup state, device labels, account-recovery policy, and coordination
through caller-supplied resources. Complete workflows, public adoption,
interoperability and final qualification remain unfinished.

## Non-goals

The root boundary does not own:

- WebAuthn wire parsing, cryptographic verification, or ceremony storage;
- non-discoverable security-key policy or browser user interfaces;
- identity, risk, authentication, identifier, audit, or session policy; or
- database clients, migrations, transactions, caches, or background workers.

The native adapter must compose actual WebAuthn, identity, risk and session
owners atomically; it cannot supply a private verifier or transaction engine.

## Lifecycle and ownership

Implementation is in progress. No tagged release or complete authentication
journey is claimed.

The implementation requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. No release follows from these component contracts.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Non-releasable state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` release declared in `.golib.yaml`.

Passing structural checks does not prove authentication behavior. Focused
native tests cover bounded values, real mapping constraints and owner checks;
full protocol/workflow composition and consumer journeys remain required.

Security reports must use the private process, and the planned trust boundary
and unresolved release-blocking risks are recorded in the
[security policy](SECURITY.md).

Use Go 1.27.2 and the checksum-pinned public Tools binary in `.golib.yaml`; the
module minimum remains Go 1.27.0. `make check`, `make ci` and `make fast-check`
validate configuration, repository structure, cohesion, offline specification
decisions, local documentation links and whole-tree/history secrets.
CI uses the same structural commands plus validated PR-base or push-before
changed-content secret checks on every change. Ordinary Required has a
five-minute job limit; changed secrets have a forty-second fatal timeout.
Scheduled/manual runs retain whole-tree secrets and online authority refresh.
`make check-full` explicitly preserves the previous full/online contract.
These commands do not run application tests or establish runtime/release proof.
See [contributing](CONTRIBUTING.md) for public tooling installation and scope.

See the versioned [Golib ecosystem index](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/README.md)
and [package-family guidance](https://github.com/faustbrian/go-library-tools/blob/v1.8.4/docs/ecosystem/design-language.md#package-families-and-selection)
for the shared design language.

## License

MIT. See [LICENSE](LICENSE).
