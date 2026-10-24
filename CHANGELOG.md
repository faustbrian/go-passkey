# Changelog

## Unreleased

- Add opaque current-passkey-session removal request/completion custody and
  durability projection. Options and completion retain distinct original keys
  under the deletion action; native owners must supply genuine UV, atomic
  removal and last-recovery-path enforcement. These carriers grant no authority
  and preserve the existing password-proof deletion API.

- Add non-serializable current-session enrollment command carriers. Assertion
  options and authorization retain distinct original keys; single-use
  registration retains its original command and ceremony identity without a
  second key. These values carry custody, not verified enrollment authority.

- Add private-by-default current-session update request, keyed options and
  assertion-completion carriers for native action-bound UV label management.
  These data records grant no freshness or permission: the native owner must
  verify the original assertion and finalize the mutation atomically. Existing
  password-proof update records retain their API and behavior.

- Add explicit conditional browser assertion options over the existing
  discoverable protocol. The projection adds outer conditional mediation while
  retaining the original ceremony, public-key options and one-reveal challenge
  custody. Keyed results preserve original command metadata without creating
  another assertion, authentication mode or replay authority.
- Add a redacted, nonserializable signup ceremony rate request retaining only
  borrowed original signup custody and the committed ceremony reference.
- Add adapter-neutral passkey-first signup request, completion, session-result
  and keyed-options carriers. They retain original flow and session-owned
  custody, deny implicit JSON/text export and redact diagnostics. They are
  prerequisites only: actual opt-in signup, verification and atomic durable
  account/session creation remain native-owner work.
- Add neutral keyed self-deletion request/result records. They preserve original
  signed-action/session custody and safe management versions; native removal
  requires current recovery authority. Results carry durability metadata only,
  never reauthentication material or a credential projection.
- Add neutral keyed self-label update request/result records. They use safe
  management references and metadata versions, preserve original command
  ownership through existing keyed admission and require genuine native action
  custody. Historical retries return no fresh credential metadata or effects.
- Expose adapter-neutral enrollment, identified/discoverable signin, keyed
  options and inventory data records for optional transports. Existing
  PostgreSQL names remain exact aliases with unchanged field, diagnostic and
  serialization behavior. Reflection now reports root-package ownership;
  `RegistrationRequest.Primary` uses the password owner's neutral exact alias.
- Add sensitive original-ceremony rate metadata contracts. They carry no
  execution authority, authenticator response, challenge or account-eligibility
  result; native completion remains the one-use authority.
- Begin the identity-facing passkey implementation with lossless opaque
  RP-user handles and bounded, non-normalizing display labels. Complete passkey
  enrollment, authentication and management are not yet available.
