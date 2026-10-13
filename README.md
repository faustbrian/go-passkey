# go-passkey

> **Status: planned.** This repository does not currently provide an
> installable package, a released version, or a runtime API.

`go-passkey` reserves the planned Golib boundary for identity-facing passkey
enrolment, discoverable credentials, passwordless signup and sign-in, synced
and backup state, credential naming, listing, deletion, and passkey-first
policy. The plan keeps those concepts separate from WebAuthn verification,
browser interfaces, non-discoverable security-key policy, and session
persistence.

## Planning documentation

This repository remains planned and non-releasable. The
[documentation map](docs/index.md) links its proposed contracts and security
boundaries; it is not an installation or runtime guide.

## Planned responsibility

The future root package is intended to own storage-neutral passkey policy,
registration and authentication flows, credential profiles, stable user-handle
policy, backup state, device labels, account-recovery policy, and coordination
through caller-supplied resources. Its contracts remain proposals until they
are implemented, reviewed, verified, and released.

## Non-goals

The planned root boundary does not own:

- WebAuthn wire parsing, cryptographic verification, or ceremony storage;
- non-discoverable security-key policy or browser user interfaces;
- identity, risk, authentication, identifier, audit, or session policy; or
- database clients, migrations, transactions, caches, or background workers.

Those concerns may become separate modules or compose existing Golib packages.
Their presence in planning material does not make them available here.

## Lifecycle and ownership

Implementation, hardening, and release have not started. The current module
declaration exists only so repository tooling can validate the planned module
identity, family, ownership, and lifecycle metadata.

The plan requires caller-owned configuration and runtime resources, copied
mutable inputs, context-bounded external operations, and no package-owned
background work. These are design constraints, not claims about released
behavior.

## Planning and verification

The [repository goal](docs/goal.md) and `modules.json` record the planning scope
and schema-v2 engineering inventory. Planned lifecycle state excludes this
module from installable and released consumer catalogs. The local
`make cohesion` target validates that boundary with the exact checksum-pinned
`go-library-tools` release declared in `.golib.yaml`.

Passing repository checks proves only that the planning scaffold and metadata
are internally consistent. It does not prove passkey behavior or an API.

Security reports must use the private process, and the planned trust boundary
and unresolved release-blocking risks are recorded in the
[security policy](SECURITY.md).

Use Go 1.27.2 and the qualified public Tools v2.1.2 binary; the planned
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
