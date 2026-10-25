# Passkey PostgreSQL adapter

Experimental, incomplete and unreleased. The selected existing-account flow
does not substitute for a complete passkey authentication platform.

## Explicit passkey-primary and TOTP challenge

`NewSigninService` still denies enrolled factors. Select
`NewMFASigninService(pool, signinConfig, mfaConfig)` explicitly to use a genuine
UV assertion as the non-final primary for an already confirmed TOTP account.
Known-empty accounts retain the ordinary session result. Identified and
discoverable options bind that exact selection before a browser assertion;
completion cannot switch from the default profile or change the selected issuer,
key ID, lifetime or attempt limit.

The enrolled branch returns `SigninResult.Receipt` and `Challenge`, never a
session, bearer or CSRF credential. The genuine WebAuthn transition, original
continuation, child issuance, audit and lifecycle effect commit atomically.
Original browser pre-authentication stays active for the independent factor
owner to consume later. Parse the incoming cookie into a fresh `session.Token`
per request: this selected branch uses its one-time input reveal to bind the
existing command's browser custody, not to issue another cookie.

Install existing kernel (including `PreparationMigrationSource`), passkey,
WebAuthn, MFA TOTP/continuation and capability
histories, then append the MFA owner's `PasskeyContinuationMigrationSource` with
flags describing the already installed predecessor profiles. The passkey owner
does not migrate or duplicate another owner's tables. `SigninMFAConfig` borrows
an envelope service and retains its configured key ID for the original journal's
recovery lifetime; signing, replay, child-checkpoint and primary-envelope keys
must be independently managed under their existing owner contracts.

`ReadMFAPasskeyPrimary` authenticates the actual issued child and committed
parent before restoring the unchanged encrypted primary. Original issue time,
expiry, remember choice, subject, credential and authority epochs are never
renewed. It is provenance for the MFA completion owner, not permission to issue
a session: that owner must verify actual TOTP and repeat current authority and
original-browser checks atomically. `RecoverSignin` remains metadata-only and
never reveals a historical child proof. Lost, unavailable or retired custody
denies; it does not authorize regenerating a challenge or assuming rollback.

## Selected algorithms

`Protocol.Algorithms` selects ES256 (`-7`), EdDSA (`-8`, Ed25519 only), or an
ordered unique combination of both. Nil preserves the released ES256 default;
explicit empty, duplicate, unknown and RS256 profiles deny construction. The
exact order and nil representation remain bound to original requests and
ceremonies. Do not change the selected profile while continuing a ceremony.

The same selection applies to password-proof enrollment, prospective passkey-
only signup, identified/discoverable signin and current-session enrollment,
rename and removal. Cryptographic verification, COSE/UV/backup/counters remain
owned by WebAuthn. Removal can count only another usable resident key in the
**current selected signin profile**. A stored key with an unselected algorithm
does not make removing the last selected key safe; an earlier unselected
mapping does not hide a later selected recovery key. Existing protocol and
mapping histories are unchanged. Native signed-authenticator integration does
not establish browser/platform interoperability for Ed25519.

## Current-session removal with another resident key

Explicitly construct `NewSessionDeletionService(pool, SessionDeletionConfig)`
with the actual current passkey-session, CSRF, policy, risk and protocol owners
used by session management. This selected algorithm profile requires another
usable resident key; it never invents password, email or OTP recovery. The existing
password-proof `DeletionService` remains separate and unchanged.

Install the selected kernel/MFA/passkey histories and WebAuthn migration 6
before selecting it. The native module supplies no HTTP routes by itself.

1. Build `passkey.NewSessionDeleteRequest` with the current session credential,
   original cookie CSRF when selected, self-user delete caller, safe inventory
   reference/metadata version and trusted ingress. Call `DeleteOptions` with
   an original `IdempotencyKey`.
2. Obtain genuine UV for those identified options. Call `Delete` with
   `passkey.NewSessionDeleteCompletion`, unchanged intent, the original ceremony
   and a **different** completion key. Do not substitute a reusable proof or
   a signin assertion. Kernel reference and protocol versions are independent
   of the inventory metadata version.
3. The sole Work consumes the assertion and erases the target protocol key,
   disables its reserved kernel reference, revokes its mapping and advances
   this RP/user's passkey generation with required audit/lifecycle effects.
   A genuine current protocol key, original resident registration provenance
   and active native/kernel mapping must remain independently usable.

Removal may target the authenticating key or a sibling. Last-key removal,
changed intent/current authority, missing provenance and expiry deny atomically.
Existing passkey sessions bound to this generation deny on their next current
read; earlier positive evidence retains its original twenty-second ceiling.
Independent password-session authority is unchanged. No authenticator-local
erasure is claimed, and reserved RP-wide credential IDs cannot be re-enrolled.

Fresh success acknowledges only the original authenticated invocation; it does
not make its now-invalid session usable again. Preserve command, keys and input
on unknown outcomes. After authenticating with the surviving key, use
`RecoverDelete` and the original command/target query for metadata-only recovery.
It never repeats removal, reveals a session or renews old authority. Options
retries under a still-valid source are metadata-only and disclose no new options.
Metadata delivery rechecks that invocation's original positive-read deadline;
history lookup cannot renew it. Canceled or deadline-exceeded preparation reads
retain their context error classification instead of becoming eligibility denials.

Registration provenance must remain available while a key is eligible for this
profile. Missing history fails closed. This selected native behavior does not
claim HTTP composition, browser interoperability or full passkey qualification.

## Additional resident key under a passkey session

Select `NewSessionEnrollmentService(pool, SessionEnrollmentConfig{...})` with
the actual session, protocol, mapping, authorization, clock, keyed-request and
protected risk owners. Configuration uses the same explicit fields as
`SessionManagementConfig`; constructing either service enables no HTTP route.
The native owner supplies domain repositories and orchestration, not application
callbacks pretending that verification succeeded. This profile selects resident
UV/none with selected ES256/Ed25519 algorithms, known-empty MFA and one self-human
session. Enrolled-MFA and organization variants remain separate, unsupported
profiles.

Install the existing mapping/signin-context/metadata, session/MFA, kernel request-
key, risk, audit and outbox histories, plus **WebAuthn migration 5** before use.
Existing history bytes and password-proof APIs remain unchanged. The borrowed
pool/collaborators outlive calls; each invocation is bounded to the configured
protocol duration (1ms–5s), with earlier caller cancellation taking precedence.

1. Construct `passkey.NewSessionEnrollmentRequest` from its explicit
   `SessionEnrollmentRequestSpec`: actual cookie or bearer credential, original
   CSRF for cookies, self-user caller for `identity.passkey.register-options`,
   optional display label and trusted origin/network. Specs are unredacted
   deliberate projections, not safe logs. Opaque request values reject implicit
   serialization and hide custody even through nested formatting.
2. Call `EnrollmentAssertionOptions` with `SessionEnrollmentOptionsRequest` and
   the original A idempotency key. Transfer committed genuine assertion options
   once, and have the session's existing authenticator perform UV.
3. Call `RegistrationOptions` with
   `passkey.NewSessionEnrollmentAuthorization(SessionEnrollmentAuthorizationSpec)`:
   unchanged original request, a **distinct B key**, original A ceremony ID and
   its genuine assertion bytes. The native coordinator consumes that assertion/
   counter and creates registration together. Transfer the fresh resident-key
   options once; no reusable reauthentication proof is created.
   A consumer buffering output through synchronous hooks instead calls
   `RegistrationOptionsForDelivery` for the same B operation and its immutable
   original A expiry. Check that nonzero expiry after hooks alongside actual
   session/request validity and B's protocol expiry. The timestamp grants no
   authority and is zero on replay/error; do not infer it from B's later TTL.
4. Preserve intent and session, change the caller action to
   `identity.passkey.register-verify`, and call `Register` with
   `passkey.NewSessionEnrollmentCompletion(SessionEnrollmentCompletionSpec)`.
   Supply one stable original `CommandID`, original B ceremony ID and genuine
   registration response. **C has no IdempotencyKey.** Protocol consumption,
   initial kernel reference, mapping/label, protected risk and required audit/
   creation lifecycle share the existing transaction. Use the result's explicit
   `Bindings` projection to inspect durability and safe fresh metadata.

Each phase authenticates actual current session/CSRF and self-user policy before
work, and fences the original directory/credential/factor/passkey/session and
authorization generations again through final commit. Original A authorization
expiry remains the ceiling for B and C; the later registration protocol TTL
cannot extend it. No session, device cookie, password fallback or renewed proof
is issued. The original session and both valid authenticators remain usable.

Before a transport admits C to its canonical challenge-verification budget, call
`SessionRegistrationRateSource(ctx, originalRequest, bCeremonyID)`. The request
uses the exact original intent, actual session/CSRF and `register-verify` caller.
This authenticates native retained intent and genuine A/B records, returning
only the original user/ceremony dimensions and fixed five-minute policy duration
(not remaining TTL or a validity lease). Repeated reads create no command/risk/
protocol effects and consume nothing. Original A expiry remains the ceiling;
`Register` still independently verifies, revalidates and consumes atomically.
Historical consumed metadata may remain readable only under current custody.

After uncertainty preserve the exact A/B keys or C command, ceremony and input;
never allocate a replacement to escape an unknown result. Reserved/committed
history returns metadata only. If the reservation never committed, an unchanged
retry may perform that command's first work; challenge generation occurs only
after acknowledged reservation, never before. Once options or completion have
committed, retries cannot reconstruct them. A current session is still required
for disclosure, so logout/withdrawal denies old-session retries. This native
profile is not HTTP/reference integration or browser interoperability proof.

## Current-passkey-session label management

`NewSessionManagementService` explicitly enables label rename under a real
current passkey session, without password configuration or a separately issued
reauthentication proof. Supply `SessionManagementConfig` with the existing
protocol, passkey admission profile, session validation/repository, request-key,
coordinator, authorization, protected risk and clock owners. Configuration is
frozen; the borrowed pool and collaborators must outlive calls. Each call has
the protocol's bounded 1ms–5s budget. Install the existing mapping, signin-context
and metadata histories plus the selected request-key/session/MFA/risk/audit/
outbox histories; this profile adds no migration or parallel proof store.

1. Read safe credential references and positive metadata versions through
   `InventoryService` under the current session.
2. Call `UpdateOptions` with `passkey.SessionUpdateOptionsRequest`: actual
   session custody, a self-user `identity.passkey.update` authorization context,
   target reference/version, intended label, trusted origin/network and one
   original idempotency key. Transfer the returned genuine assertion options
   once. They require fresh UV from the session's authenticating credential.
3. Complete the authenticator response through `Update` with
   `passkey.SessionUpdateCompletion`, preserving that original request and
   ceremony ID but using a **distinct completion idempotency key**. Both phases
   occupy the same protected update namespace, so one key cannot represent both
   request bodies. The native owner verifies the actual assertion; session
   freshness timestamps or caller-supplied booleans grant no permission.
4. The sole coordinator atomically consumes the ceremony/counter transition,
   current directory/session/factor/passkey/policy fences, label metadata CAS,
   protected mutation counters, audit and rename lifecycle. No new session or
   reusable proof is issued; inventory and subsequent signin keep working.

Select bearer **or** cookie transport in configuration. Cookie selection
requires retained original CSRF keys and each request's actual synchronizer
token; bearer selection accepts no CSRF material. An assertion cannot move to a
sibling session, target/version/label, RP, origin or network. A matching retry
requires current authenticated custody and returns the original receipt only,
never another challenge, assertion, secret or mutation. After an uncertain
COMMIT, retry the same original request/key: recovery classifies the original
outcome without re-executing it. A different request needs a different key.

This native profile does not expose HTTP endpoints, implement browser UI or
certify authenticator/browser interoperability. Existing password-proof rename
remains supported. Additional enrollment is selected separately above;
passkey-only deletion/recovery and MFA/organization variants remain required.

## Conditional assertion option generation

`ConditionalAuthenticationOptions` and
`KeyedConditionalAuthenticationOptions` explicitly select conditional browser
presentation of the existing identifier-free assertion. Both require the
existing risk owner's `PasskeyDiscovery` policy opt-in; keyed options also
require `OptionsRequests`. They accept the existing discoverable requests and
return root-owned conditional options. No synthetic identifier, separate
ceremony/history, secondary verifier, new policy flag or fallback is introduced.

The protocol interpretation follows [WebAuthn Level 3, CR 26 May 2026,
§5.1.4](https://www.w3.org/TR/2026/CR-webauthn-3-20260526/#sctn-getAssertion):
conditional mediation selects browser presentation on the outer request, not a
different signed assertion or server verification protocol. `TransferJSON`
reveals `{mediation:"conditional",publicKey:...}` once and preserves the entire
native `publicKey`, including required UV and no account allowlist. A browser
consumer checks conditional-mediation availability, deserializes `publicKey`
with `PublicKeyCredential.parseRequestOptionsFromJSON` (or an equivalent
supported decoder), and calls `navigator.credentials.get` with the explicit
outer mediation. Browser capability checks, HTML autofill and actual UI remain
the consumer's responsibility; no browser interoperability is certified here.

Complete the returned genuine assertion through **`DiscoverableSignin`** and
read original rate metadata through **`DiscoverableSigninRateSource`**. Original
flow/cookie, tenant/RP, current identity/risk, expiry and remember policy remain
unchanged. An open browser conditional request does not extend server expiry.
The backend cannot authenticate which browser mediation was used. Conditional
and ordinary discoverable presentations intentionally share one keyed command:
matching retries, including switches between those presentations, recover only
original metadata, never a replacement challenge. Identified signin remains a
distinct immutable admission and cannot reuse that key or ceremony. Ambiguous
options/completion retain existing metadata-only recovery without new secrets.

Focused native PostgreSQL tests exercise conditional options through actual
signed assertion verification, session read and logout for browser-only and
persistent choices, plus policy/UV/expiry denial and replay. HTTP/Reference
composition and real browser/platform/roaming-authenticator proof remain
separate qualification boundaries.

## Explicit passkey-first signup

`NewSignupService` selects a fixed tenant/RP's resident-required, UV-required,
none-attestation registration in the selected ES256/Ed25519 profile without an
email or password. It exposes
no HTTP routes. Supply the real protocol, kernel coordinator, authorization,
session, protected risk and counter configuration; use the public dependency
baselines pinned in this module. `Flow.Action` is
`identity.passkey.register-verify`. The registration counter policy remains
CredentialMutation: five attempts per fifteen minutes with transaction-owned
denial, projected onto the actual tenant/browser flow/network/device.

1. `PrepareFlow` -> `IssueFlow` uses the session owner's original cookie,
   origin, expiry and remember choice. Neither step authenticates a user.
2. `RegistrationOptions` commits genuine protocol options and prospective
   intent only. It creates no account, stable handle, credential or auth session.
3. `Signup` verifies the original authenticator and atomically creates the user,
   initial passkey reference, protocol credential, RP-wide mapping, known-empty
   MFA generation, authorization authority and session/family/issuance. Required
   credential, `user.created.v1` and `session.created.v1` events share that Work.
4. Only the new acknowledged winner receives bearer/CSRF custody. The common
   passkey session reader and cookie logout work for that new account, and its
   passkey can sign in again through the selected identifier-free signin API.
   Consumer authorization must admit that actual new account, not only seed users.

Install the common kernel/credential/directory histories and selected kernel
registration/acceptance/passkey-registration suffixes, protocol registration
history (including protocol migration4), MFA's passkey-signup suffix, session
issuance/pre-auth/CSRF and selected passkey-signup purpose suffix, and the risk
owner's passkey-signup counter suffix. Each owner retains its own migration
history. Append `SignupMigrationSource` at the next unused native slot after
mapping history; mapping1/signin2/metadata3 installations select4. Unselected
signin/metadata histories are not signup bootstrap dependencies. Do not rewrite
old SQL or run optional purpose suffixes out of their selected order. Real
three-event-capable audit/outbox owners are required, not application stubs.

`OptionsRequests` is separately opt-in. Configure `NewOptionsRequestConfig` and
the existing kernel request-key history, then call `KeyedRegistrationOptions`
with root `passkey.KeyedSignupOptionsRequest`. Leave `CommandID` empty and retain
the exact key/browser/input. Its trusted service caller addresses the original
`identity.anonymous-flow`. The existing request-key owner allocates one command;
matching retries return only its metadata, including after flow expiry or
consumption. Another key cannot bypass original expiry. No second request journal
or challenge reconstruction is introduced.

Retain original commands and browser custody across ambiguous outcomes.
`RecoverRegistrationOptions(request, caller)` and
`RecoverSignup(request, ceremonyID, caller)` require the original cookie/origin
and current coordinator query policy. The native owner reads the original
credential reference; consumers need no private SQL. Recovery does not require
live flow or current account epochs, renew freshness, repeat registration or
redeliver authentication. Retain original flow records and their lookup key
while supporting this metadata recovery. Account/session administration remains
separate from historical outcome disclosure.

For a disposable PostgreSQL test cluster with the documented test-role
privileges, the executable native journey and failure/recovery checks are:

```sh
go test -tags=integration -race -count=1 \
  -run '^(TestPasskeySignup|TestKeyedPasskeySignup)' .
```

Set `IDENTITY_POSTGRES_TEST_DSN` to that isolated cluster, never an existing
application database. Tests create/drop their own databases and audit roles.
Reference/HTTP composition, conditional option presentation and passkey-session
management are distinct profiles; signup alone does not claim them or full M16.

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
signup, conditional option presentation, HTTP composition or complete platform
qualification.

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

The same `SessionAuthority` separately implements the session owner's
`MFAPasskeySessionAuthority` for completed UV-passkey plus TOTP records.
`ObserveMFAPasskeySession` checks only the original native RP, handle generation
and active credential reference/version. Its bounded mapping observation has no
factor version: the native MFA owner independently checks the exact confirmed
enrollment and factor generation. Projecting completed-session metadata does not
authenticate an assertion or TOTP, issue a session or grant mapping authority.
Kernel credential eligibility (including disabled references) remains the
session/MFA consumer's independent responsibility.

`RequireMFAPasskeySession` accepts only the original live registered native
TOTP-completion or self-session-revoke-one invocation. The completion owner
independently binds the exact frozen subject and stored session, including its
final check; the mapping adapter preserves the original anonymous command rather
than substituting a user-scoped Work. The caller must hold its actual factor
fence **before** the RP/handle/credential mapping locks, as in native signin and
enrollment. It must repeat the check before commit and abort on every error.
Neither MFA method initializes authority, verifies a factor, retains Work or
widens the legacy known-empty-factor methods.

Reads begin their immutable twenty-second window before contributing IO.
Protected checks use the original registered coordinator Work, with factor
locks before mapping locks. Every error must abort that Work; this adapter does
not claim to poison a transaction when its caller ignores a returned error.

`NewEnrollmentService` selects existing-account enrollment with known-empty MFA,
resident-required UV/none with the selected ES256/Ed25519 policy and separate
genuine signed fresh action
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

`RegistrationRateSource`, `SigninRateSource`,
`DiscoverableSigninRateSource` and `SignupRateSource` authenticate original
source custody and return sensitive original rate metadata only. Supply genuine completion
phase's session/action proof for registration, or the original browser cookie,
flow and exact identified/identifier-free mode for signin. The retained native
admission must match the original committed ceremony and trusted deployment.
Signup reads require the original live signup cookie/flow, configured origin,
current directory generations, canonical prospective registration context and
matching native create ceremony. They return only the original anonymous flow,
ceremony ID and immutable five-minute policy lifetime, never the prospective
user or handle. Device/network remain bounded trusted ingress, not additional
original-flow authentication factors. No risk admission, command, challenge,
proof, account or session is created or consumed. `Signup` still revalidates
all current authority and consumes the original flow/ceremony atomically.
Identified metadata returns the exact original canonical identifier even when
its original account lookup was suppressed; it never projects account
eligibility or a resolved user. Identifier-free metadata returns only its
original anonymous flow dimension. These reads do no account lookup, risk
admission, proof consumption, challenge transfer or session issuance.
Identified options created by `NewMFASigninService` retain that exact selected
MFA profile and custody binding for rate reads as well as completion. Reading
them through the default or a differently configured MFA service denies; an
enrolled and a suppressed account expose the same identifier-only dimensions.

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

`NewSigninService` composes UV login in the selected ES256/Ed25519 profile. First
use `PrepareFlow` and
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
ceremonies cannot switch into identified completion. Conditional presentation
uses this same discovery admission and completion, not a new server mode.
This profile adds no signup, browser UI or secondary-MFA fallback.

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

Native integration tests cover genuine action-proof/UV enrollment,
real owner constraints, denial, contention, required-effect rollback and actual
before/after-COMMIT connection loss. Existing active session rows are explicit
fixture input, not evidence of signup/signin provenance. Full release
qualification and complete platform composition remain separate obligations;
this adapter is not a UI or a complete identity platform by itself.

### Credential management after passkey/TOTP signin

`InventoryConfig.MFAPasskey` explicitly adds the native session owner's completed
passkey/TOTP admission alongside `Passkey`. Supply its matching trusted profile
and native mapping authority. Both selections share the `Passkey` repository
and validation configuration, and stored provenance selects exactly one reader.
There is no retry through another method after denial. Password inventory
cannot also select this extension; omitted MFA admission retains prior behavior.

For fresh UV label rename, set `SessionManagementConfig.TOTP` to true. This
selects completed passkey/TOTP sessions instead of known-empty sessions; it is
not a secondary-factor fallback. Use the existing `UpdateOptions` and `Update`
APIs with original request keys, exact CSRF where selected, and a genuine new
WebAuthn assertion bound to the intended target/version/label and source session.
The original confirmed factor ID, enrollment and account generation remain
current alongside credential/directory/policy, RP mapping and session authority.
Factor locks precede mapping locks. Neither inventory nor management consumes a
TOTP, adopts a newer generation or resets positive authority evidence freshness.

Install the existing completed-passkey/MFA session, confirmed TOTP, mapping,
metadata, request-key and protocol histories before selecting this profile.
These additions create no new migration or private proof/session engine.
Retries preserve the original outcome without another challenge or credential
redisclosure. Set `SessionEnrollmentConfig.TOTP` to true independently to add
another key through the existing three-phase enrollment API. The current key's
fresh action-bound UV authorizes registration, not a signin assertion or reusable
proof. Original confirmed TOTP, credential/session and assertion expiry remain
fenced in each phase and final checks; the new key does not bypass account MFA.
Set `SessionDeletionConfig.TOTP` separately to remove a key through the existing
`DeleteOptions`, `Delete` and metadata-only `RecoverDelete` APIs. It requires
fresh action-bound UV and another independently usable resident key, and fences
the original confirmed factor/enrollment in Apply and final checks. Removal
advances native passkey authority, invalidating prior sessions. Sign in with the
surviving key and complete TOTP before recovering the original removal metadata;
the removed generation cannot regain disclosure authority. This profile creates
no additional mapping, session or replay store. OTP/recovery-code primary
completion and organization-session profiles remain excluded.
