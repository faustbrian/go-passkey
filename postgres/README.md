# Passkey PostgreSQL adapter

Experimental, incomplete and unreleased. The selected existing-account flow
does not substitute for a complete passkey authentication platform.

`NewDeletionService` selects native self-user removal under the existing
single-factor password-session profile. `DeletionConfig.ManagementConfig`
supplies the fixed tenant/RP, password reader, original-key, policy and risk
owners, but its concrete action source must select exactly
`identity.passkey.delete`. `Recovery` must be the password owner's concrete
`NewPasskeyRemovalRecoverySource` backed by a full configured native emailed
password-reset request/completion service on the same primary, session schema,
account realm and policy. Another passkey, a boolean or directory metadata
without matching usable password material and verified recovery email is not a
replacement. Unknown or missing current factor/recovery authority denies.

Use the dependency baselines pinned in this module's `go.mod`. Append the
password-owned `PasskeyDeletionReauthenticationMigrationSource` after every
installed selected proof suffix; do not replace or reorder that history.
For mapping1/signin2/metadata3 and enrollment-proof11/management-proof12,
deletion proof13 is the next selected fixture suffix. Allocate the next unused
version for other installed histories. The existing kernel request-key and
mapping/metadata histories remain required; this adapter adds no new journal,
protocol store or removal migration.

`Delete` accepts root `passkey.DeleteRequest`: a safe List reference and observed
management metadata version, genuine original session/action/CSRF custody and
exact `IdempotencyKey`. Leave incoming command, record and target overrides
empty. Unlike the historical repeat/raw-credential catalog shape, this selected
native profile admits one server-allocated original key before preparation.
Reference, protocol and management versions are independent: deletion fences
all three, while the canonical `identity.passkey.remove_credential` receipt and
lifecycle advance the **reference** version, not `ExpectedVersion`.

Fresh commitment atomically consumes the proof, checks usable recovery and
removes protocol verification material. It disables the reserved reference,
advances its version and mapping metadata, increments the RP/user passkey
generation and persists required audit/outbox effects.
Removed mappings disappear from inventory before pagination; IDs and
handles remain reserved to prevent resurrection. The shared passkey generation
denies previously issued RP/user passkey sessions on their next authoritative
comparison. User-wide credential epochs and the independent password session
remain unchanged. No authenticator-local credential erasure is claimed.

`DeleteResult` contains only command durability metadata. Preserve identical
key/input and original password-session custody on retry, including after
proof expiry or consumption. Matching retries recover the original receipt
without rechecking recovery, consuming another proof, repeating removal or
projecting credentials. Revoked/expired original sessions cannot disclose it.
Unknown COMMIT acknowledgement is not rollback; retain the original key and
command. This API does not enable passkey-session management, passkey-first
signup, conditional signin, HTTP composition or complete platform qualification.

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

Transport-facing data types are owned by root `go-passkey`; existing names in
this adapter remain exact aliases, not wrappers. Native method signatures and
existing field/diagnostic/serialization behavior are unchanged. Reflection now
reports their root defining package. No pool, SQL or native configuration has
moved into the neutral module.

`RegistrationRateSource`, `SigninRateSource` and
`DiscoverableSigninRateSource` authenticate the original source custody and
return sensitive original rate metadata only. Supply the genuine completion
phase's session/action proof for registration, or the original browser cookie,
flow and exact identified/identifier-free mode for signin. The retained native
admission must match the original committed ceremony and trusted deployment.
Identified metadata returns the exact original canonical identifier even when
its original account lookup was suppressed; it never projects account
eligibility or a resolved user. Identifier-free metadata returns only its
original anonymous flow dimension. These reads do no account lookup, risk
admission, proof consumption, challenge transfer or session issuance.

The original ceremony policy lifetime is fixed; a read never renews its expiry.
Malformed, foreign, expired or wrong-mode custody returns no dimensions.
Historical consumed metadata may remain readable while original custody and
time remain valid. It is not a validity lease or permission to execute:
completion independently repeats current authority checks and atomically
consumes proof/flow/ceremony in the existing coordinator Work. A metadata read
cannot permit a repeated mutation, challenge or authentication reveal.

`RecoverEnrollment` uses the existing coordinator and current disclosure policy
to read or reconcile the original command. It returns historical metadata only,
never another challenge, verified credential, token or permission to replay.
An unavailable COMMIT acknowledgment is not rollback. Retain original command
and caller scope; do not mint a new operation to retry an ambiguous mutation.

For keyed HTTP or native options admission, construct `OptionsRequestConfig`
with `NewOptionsRequestConfig`, the kernel's `RequestKeyConfig`, and dedicated
independent `session.DigestKey`/`session.CSRFKey` values used only for original
input correlation. Configure it as `EnrollmentConfig.OptionsRequests` and/or
`SigninConfig.OptionsRequests`. Install the kernel's public
`RequestKeyMigrationSource` after the installed kernel history; this adapter
does not add another journal or correlation table. Keep namespace and digest
keys fixed while original mappings are retained. The kernel retains immutable
mappings without expiry; changing keys fails closed instead of silently issuing
a replacement challenge.

Call `KeyedRegistrationOptions`, `KeyedAuthenticationOptions` or
`KeyedDiscoverableAuthenticationOptions` with the matching typed request and
the exact `identity.IdempotencyKey`. Leave its native CommandID empty (and
registration's RecordID empty); the request-key owner allocates one random
original command. Preserve the original session/proof/CSRF or flow/cookie and
all operation input on retries. A fresh acknowledged winner has committed
`Receipt` metadata and reveal-once `Options`. Matching replays have that same
`CommandID`, `Replayed=true`, and metadata only, including after proof/flow
consumption. Pending metadata returns `identity.InProgressError`; an unresolved
outcome returns `identity.UnknownCommitError`. No error or replay permits a
challenge transfer or new authentication. A zero receipt establishes no command
outcome; retry the same key/input rather than minting a replacement.

Current coordinator admission and query policies authorize metadata separately
from native execution. Enrollment retains trusted authenticated self-user
attribution; signin retains the configured service actor and exact browser
possession. Signin metadata policy uses `identity.anonymous-flow`/FlowID, the
kernel query owner's required resource, while native execution uses
`identity.preauth`. The request-key owner independently requires
`identity.request-admission` with the canonical options operation ID. The
adapter selects only that resource for the admission decision, not a new actor
or authorization service. Existing keyless methods and one-use completion
methods retain their prior contracts.

`NewInventoryService` composes an explicitly selected native password or passkey
session reader, self-user authorization and the existing risk safe-read counters.
`List` returns at most 100 safe metadata rows, with an exclusive reference-ID
cursor; an owner failure returns no partial page. AAGUID and backup flags come
from the protocol owner, not another key/counter store. Raw credential IDs,
handles, keys, counters and authentication custody are never exported.

`NewManagementService` selects self-user label rename with a genuine fresh
signed `identity.passkey.update` action proof. Configure its concrete password
session reader, exact proof source/audience, trusted tenant/RP, existing risk
owner and coordinator admission/query policies. Install the password owner's
`PasskeyManagementReauthenticationMigrationSource` after the complete installed
passkey enrollment proof history, the kernel's request-key history and this
adapter's explicitly allocated `MetadataVersionMigrationSource` before enabling
it or using updated inventory. Preserve mapping `MigrationSource` version1 and
any installed `SigninMigrationSource` version2 unchanged; append metadata at
the actual next free slot (version3 for that history), never reuse signin's slot.
The forward suffix adds `metadata_version`, backfilling existing records to one. Safe inventory
`Version` is now this metadata CAS, not the kernel credential-reference fence.
Protocol credential bytes, counters and authenticating reference versions do
not change when a label changes; old signin consumers remain compatible. Old
inventory readers can return stale versions after a rename and must be upgraded
to obtain the current metadata version.

Call `Update` with root `passkey.UpdateRequest`, the safe inventory ReferenceID,
positive ExpectedVersion, a 1..128-byte UTF-8 label, exact typed IdempotencyKey
and trusted bounded Network dimension. Leave Primary.CommandID and RecordID
empty: the existing request-key owner allocates and binds the original command
before proof preparation. This native keyed profile does not accept a second
caller-selected command or a raw WebAuthn credential ID. Keep request namespace,
dedicated token/CSRF digest keys and all original input fixed across retries.
Matching retries authenticate the original current self session, retain the
original command and return historical receipt metadata only, even after proof
consumption or expiry. Another key cannot reuse a consumed/expired proof.

One sole Work consumes the signed proof, fences current session/account/factor,
authorization and exact RP credential ownership, charges owned mutation risk,
CAS-updates label/metadata version and persists required
`identity.passkey.rename_credential` audit/outbox effects. A concurrent stale
version cannot overwrite the winner. Only a fresh acknowledged commit returns
`Credential`; every replay/unknown returns no updated credential projection.
An unavailable commit acknowledgment is not rollback: retry the exact original
key/input to use the existing coordinator's retained receipt/recovery policy.
Changed or contradictory recovery evidence stays unknown, never reconstructed
as success from current label state. This API does not delete a credential or
alter recovery eligibility and does not expose HTTP routes.

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
deletion, HTTP/reference routes or a UI. Those retained goals remain work;
no complete authentication backend is claimed by this adapter yet.
