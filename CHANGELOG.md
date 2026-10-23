# Changelog

## Unreleased

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
