# Security policy

## Supported versions

There are no supported releases. This checkpoint provides experimental root
handle/label contracts only. Native PostgreSQL workflow work is unpublished;
complete passkey authentication is not available. The root remains
non-releasable; full workflow/security boundaries must be proven before release.

## Private reporting

Do not open a public issue for a suspected vulnerability. Report it privately
through [GitHub Security Advisories for
`faustbrian/go-passkey`](https://github.com/faustbrian/go-passkey/security/advisories/new).
Include the affected planning record or commit, the potential impact, a minimal
reproducer when one exists, and a proposed mitigation when available.

Do not include production challenges, credential IDs, user handles, public-key
credentials, attestation objects, authenticator data, signatures, session
tokens, recovery material, or unredacted service output. Use synthetic fixtures
and redact account, relying-party, origin, device, and transport identifiers.

## Security boundary

The root package owns the storage-neutral boundary for passkey registration and
authentication flows, credential profiles, stable opaque user-handle policy,
backup state, device labels, credential lifecycle, passkey-first decisions, and
account-recovery coordination. It must not implement WebAuthn wire parsing or
cryptographic verification, retain ceremony state, render browser interfaces,
issue sessions, or own persistence and infrastructure resources. The planned
native PostgreSQL adapter must own identity-facing mappings, not protocol
records or an independent factor/session authority; it is not delivered by
this root-contract checkpoint.

The caller and composed WebAuthn implementation remain responsible for HTTPS,
origin and relying-party binding, challenge entropy and single use, ceremony
expiry, authenticator and attestation policy, signature verification, replay
protection, secure storage, authorization, audit redaction, session issuance,
rate limits, abuse controls, and incident response. Planning text is not a
security control and must not be used as an authentication dependency.

## Risk disposition and release blockers

No production risk acceptance follows from the experimental implementation.
The following obligations block release until their contracts, bounds, tests,
ownership and complete consumer composition are proven:

| Risk | Disposition required before release |
| --- | --- |
| Bypassed or incomplete WebAuthn verification | Require a maintained verifier boundary; define and test fail-closed origin, relying-party, challenge, ceremony, and signature outcomes without wrapping cryptographic primitives. |
| Replay, stale ceremonies, duplicate credentials, and account confusion | Define caller-owned ceremony storage and atomic consumption, opaque user-handle rules, credential uniqueness, expiry, and concurrent registration or deletion semantics. |
| Recovery or passkey-first downgrade | Define explicit caller policy and authorization for recovery, fallback, credential replacement, deletion, and last-credential handling; silent downgrade is prohibited. |
| Counter, backup-state, attestation, and device metadata ambiguity | Define privacy-preserving storage and disclosure, clone-signal policy, backup-state transitions, attestation trust ownership, and behavior for authenticators with limited counters. |
| Sensitive data disclosure | Bound and redact errors, logs, traces, diagnostics, fixtures, and callbacks; prohibit secret, challenge, credential, authenticator, and recovery material from diagnostic output. |
| Resource exhaustion and lifecycle leaks | Bound input sizes, collection cardinality, storage work, callbacks, and diagnostics before allocation; require context cancellation and caller-owned resource lifetimes. |
| Dependency or specification drift | Pin maintained dependencies, record license and vulnerability review, bind behavior to the selected WebAuthn specification profile, and require interoperability evidence for claimed support. |

Passing component tests or structural checks does not establish a working
authentication backend. Non-releasable manifests, release-blocked delivery and
the public incomplete-status notice remain until full qualification. No tags,
release or deployment are authorized by implementation progress.
