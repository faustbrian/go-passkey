# Changelog

## Unreleased

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
