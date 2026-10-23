# Passkey PostgreSQL adapter

Experimental, incomplete and unreleased. The selected existing-account flow
does not substitute for a complete passkey authentication platform.

`MigrationSource` installs only identity-facing RP bindings, stable opaque
handles, credential references, labels and original enrollment admission context.
The latter retains the options phase's session and authority generations; it
does not copy a challenge, protocol ceremony, consumption state or command
journal. Install the public identity kernel
and credential-reference histories first. WebAuthn owns its separate protocol
history; MFA owns factor authority. Never copy their tables into this adapter.

`NewSessionAuthority` borrows the primary pool and a trusted fixed tenant,
RP namespace, RP ID and bounded duration. Select the same authority in native
session issuance, reads and revocation. It checks the original active mapping
and known-empty MFA generation, not merely absence of a second-factor record.
Missing, revoked, compromised, mismatched and newer authority denies.

Reads begin their immutable twenty-second window before contributing IO.
Protected checks use the original registered coordinator Work, with factor
locks before mapping locks. Every error must abort that Work; this adapter does
not claim to poison a transaction when its caller ignores a returned error.

`NewEnrollmentService` selects existing-account enrollment with known-empty MFA,
resident-required UV/none/ES256 policy and separate genuine signed fresh action
proofs for options and completion. Configure the actual native password action
sources and protected risk owner; no boolean freshness, private store or fake
verifier is accepted. The browser receives options only after commit. Completion
atomically consumes the original proof/ceremony and persists the protocol
credential, kernel reference, mapping, `identity.passkey.create_credential`
audit and lifecycle. Newer account/factor/mapping authority or another original
session cannot rebase an existing ceremony. Errors must abort the sole Work.
The total duration is at most five seconds. Policy callbacks run before Work,
not while holding mapping/proof locks; the original authorization generation
remains fenced through commit. Policy versions must match coordinator admission.
Enrollment accepts up to 100 existing exclusion descriptors in this selected
protocol profile. That options bound does not cap usable signin credentials:
adding the 101st passkey cannot disable the existing or newly enrolled keys.

`RecoverEnrollment` uses the existing coordinator and current disclosure policy
to read or reconcile the original command. It returns historical metadata only,
never another challenge, verified credential, token or permission to replay.
An unavailable COMMIT acknowledgment is not rollback. Retain original command
and caller scope; do not mint a new operation to retry an ambiguous mutation.

`NewInventoryService` composes an explicitly selected native password or passkey
session reader, self-user authorization and the existing risk safe-read counters.
`List` returns at most 100 safe metadata rows, with an exclusive reference-ID
cursor; an owner failure returns no partial page. AAGUID and backup flags come
from the protocol owner, not another key/counter store. Raw credential IDs,
handles, keys, counters and authentication custody are never exported.

`NewSigninService` composes UV/ES256 login. First use `PrepareFlow` and
`IssueFlow` to retain the real session-owned browser cookie and remember choice;
then pass that original flow to `AuthenticationOptions` and `Signin`. Trusted
configuration fixes tenant, RP, origin, policy and ingress service actor.
Options use the actual WebAuthn resident-discovery ceremony and expose no
account-specific user handle or credential descriptors. Eligible, absent,
unverified and no-passkey identifiers receive the same public options profile.
The original optional account snapshot and keyed identifier binding remain
private; a suppressed snapshot cannot later become authenticating. Completion
still requires that original email and unchanged identity/factor/policy epochs
to match the real root-verified credential. These identified methods retain
their original admission contract and do not claim constant-time execution.

For explicit identifier-free resident login, enable `risk.PolicyConfig`'s
`PasskeyDiscovery` at trusted startup in the actual durable PostgreSQL risk
composition, then call `DiscoverableAuthenticationOptions` and
`DiscoverableSignin` with the identifier-free request/completion types. Reuse
`PrepareFlow`/`IssueFlow`; the original cookie, remember choice and absolute
expiry remain authoritative. Options neither select nor require an account,
user handle, email or credential descriptor. Risk counts the real anonymous
tenant/network/device dimensions without fabricating an identifier. Missing
opt-in fails closed. After genuine cryptographic credential/handle verification,
native mapping and public identity/MFA/policy owners admit the current target;
its captured epochs are fenced through commit. Existing identified or
suppressed ceremonies cannot be promoted into this mode, and discoverable
ceremonies cannot switch into identified completion. This profile adds no
signup, conditional UI or secondary-MFA fallback.

The genuine protocol verifier alone admits the assertion. Ceremony consumption,
counter/backup transition, mapping last-use, original browser-flow consumption
and new session/audit/lifecycle effects share the existing coordinator Work.
Do not call options again to retry an ambiguous command. `RecoverSignin` returns
historical outcome metadata only, never a replacement credential or challenge.
Append `SigninMigrationSource` and the session owner's selected issuance,
preauthentication, CSRF and passkey suffixes to actual installed histories.
The original browser-flow expiry is checked again at primary precommit time
after later effects. A genuine synced-counter warning is exposed as
`SigninResult.CounterRisk`, not falsely turned into account compromise;
non-backup positive-counter regressions are denied by WebAuthn itself.

Use `NewSessionAuthority` with the session owner's `NewPasskeySessionService`
to read the issued credential. For browser logout, select that same authority
in `NewCookieRevokeOneExecutor`, retain current caller admission with
`PrepareRevokeOneWithCSRF`, and invoke `ExecuteRevokeOneWithCSRF`. Legacy direct
dispatch intentionally denies cookie requests. Missing/wrong synchronizer
custody cannot revoke or clear a session.

Current native integration tests cover genuine action-proof/UV enrollment,
real owner constraints, denial, contention, required-effect rollback and actual
before/after-COMMIT connection loss. Existing active session rows are explicit
fixture input, not evidence of signup/signin provenance. External public-
consumer qualification, independent final review and full release
qualification remain unfinished. The selected flows do not enable
passkey-first signup, completed MFA, organization authority,
rename/delete, HTTP/reference routes or a UI. Those retained goals remain work;
no complete authentication backend is claimed by this adapter yet.
