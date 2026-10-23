# Changelog

## Unreleased

- Add opt-in keyed native registration and identified/discoverable signin
  options through the existing kernel request-key and recovery owners.
  Exact original input and browser/session possession retain one random
  command; matching retries return metadata only, never another challenge.
  Configure dedicated correlation digest keys and install the kernel's
  request-key history before enabling the additive APIs. Existing keyless
  methods and one-use completion semantics remain unchanged.
- Add explicitly selected identifier-free resident UV/ES256 signin with genuinely
  account-independent options and the risk owner's trusted anonymous-profile
  opt-in. The root-verified credential and opaque handle jointly select the
  current native identity/factor authority before atomic session issuance.
  Preserve original browser/remember/expiry custody, reveal-once issuance,
  metadata-only recovery and existing identified admission; ceremonies cannot
  switch between those modes.
  Reuse the existing installed signin context history. Signup, conditional UI
  and secondary-MFA fallback remain outside this selected profile.
- Add forward-only RP/handle/credential mapping history with RP-wide
  uniqueness and exact tenant/user partitions. Add current passkey session
  authority using the existing MFA owner, without adopting newer generations.
  Add selected existing-account resident/UV enrollment through genuine native
  action proofs and WebAuthn participation, with atomic initial references,
  retained original options context, exact creation events and metadata-only
  original-command recovery.
- Add explicitly selected native identified signin through the original
  preauthentication browser/remember flow, counted risk, genuine WebAuthn and
  atomic session effects. Add safe session-authenticated credential inventory.
  Keep anonymous options account-independent through the protocol owner's
  resident discovery, retaining the original private identifier admission and
  current-owner fences before session issuance. Signin checks active presence
  and one exact credential rather than applying enrollment's descriptor bound
  to all stored keys. These experimental APIs do
  not enable passkey-first signup, identifier-free login, MFA fallback or
  complete release-qualified workflow composition.
