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

`SigninResult.Challenge` is the explicit, private TOTP challenge alternative to
`Session` and `CSRF`. It carries the original child identity and expiry; its
proof is available only to the fresh committed native winner. Replays never
renew that proof or reveal session credentials. These transport records grant
no assertion, factor or session authority: selecting and executing the native
MFA composition remains the PostgreSQL owner's responsibility. Existing
known-empty-factor signin and signup APIs keep their behavior.

- `ConditionalAssertionOptions` explicitly projects an existing anonymous
  discoverable assertion as `{mediation:"conditional",publicKey:...}`. It
  retains the protocol owner's original ceremony, UV requirements, expiry and
  reveal-once challenge custody; copies share the same reveal. It is not a new
  server authentication mode or proof that a browser used conditional UI.
  Native conditional option methods and ordinary `DiscoverableSignin` compose
  the real session path; browser UI and interoperability remain separate.
- `SignupRequest`, `SignupCompletion`, `SignupResult` and
  `KeyedSignupOptionsRequest` carry adapter-neutral intent and secret custody
  for an explicitly enabled no-email/no-password passkey-first profile. They
  cannot select a user, RP, tenant, actor or proof, and do not implement signup.
  Keep the original session-owned flow, cookie and remember policy, trusted
  ingress and each phase's original command on retries. Keyed options require
  an empty incoming command ID and reuse `KeyedRegistrationOptionsResult`;
  only its fresh committed winner may reveal options. Completion borrows raw
  response bytes: the native owner must bound and copy them before parsing or
  retaining them. Actual resident-required, UV-required, none-attestation
  verification under the exact selected algorithm profile must precede coherent
  account/credential/MFA/session creation. No authentication or CSRF secret may
  be returned before acknowledged
  commit or from an aborted, unknown or historical result. Implicit JSON/text
  export is denied and ordinary formatting is redacted; explicit fields are
  still sensitive and are not an audit or wire projection.
- `DeleteRequest`/`DeleteResult` carry keyed self-user removal intent and original
  durability metadata only. Use the safe List reference and metadata version,
  leave primary command/record IDs empty and preserve exact input/custody on
  retries. Native execution must require genuine `identity.passkey.delete`
  proof and current usable recovery authority, then remove protocol/reference
  authority and emit required lifecycle effects atomically. The records grant
  no authority, return no credentials and do not claim authenticator-local
  erasure; matching retries recover metadata without repeating effects.
- `UpdateRequest`/`UpdateResult` carry keyed self-user label-management intent and
  original durability metadata without importing a database. Use the safe List
  reference and its management metadata version, not RP credential bytes or
  authority versions. This keyed native profile requires empty incoming primary
  command/record IDs: the existing request-key owner allocates the one original
  command before genuine `identity.passkey.update` action-proof preparation.
  That original ID is returned for fresh execution, replay and recovery. Matching
  retries carry identical custody/input and return metadata only; no proof,
  mutation or required effect is repeated. Native implementation remains a
  separate adapter boundary; these records grant no execution authority.
- Enrollment, identified/discoverable signin, keyed-options and inventory
  request/result records live in the root module for adapter-neutral transport
  ports. The PostgreSQL names are exact aliases, so no conversion is needed.
  Their established diagnostic labels and serialization errors are unchanged;
  reflection reports `github.com/faustbrian/go-passkey` as their defining
  package. `RegistrationRequest.Primary` is the password owner's neutral
  `password.ActionPrimaryRequest`. These data records select no database,
  configuration, runtime store or transport.
- `CeremonyRateSource` carries only an original ceremony ID, immutable original
  policy lifetime and one user, identifier or anonymous-flow rate dimension.
  It is sensitive metadata, not an authentication result or validity lease.
  Consumed historical metadata cannot authorize another native mutation or
  reveal. Implicit JSON/text serialization and ordinary diagnostics redact it.
  `SignupCeremonyRateRequest` borrows the original signup browser request and
  committed ceremony ID; native reads return only the original anonymous-flow
  dimension, never the prospective identity or an authenticated user.
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
