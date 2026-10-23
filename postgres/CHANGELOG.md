# Changelog

## Unreleased

- Add native keyed self-user deletion through genuine signed delete proof and
  the configured password-reset recovery owner. Proof consumption, current
  factors/recovery, protocol key erasure, disabled reference, separate metadata
  and passkey authority successors, and exact removal audit/lifecycle share one
  transaction. Passkey sessions lose authority; the independent password
  session retains metadata-only original-key retry. Install the password
  deletion proof suffix after all selected histories and use the pinned kernel,
  MFA and WebAuthn removal owners. Removed IDs remain reserved, and inventory
  excludes their tombstones before bounded pagination.
- Add keyed self-user passkey label rename through a genuine fresh signed
  update action proof and the existing request-key/coordinator owners. Safe
  reference IDs and expected metadata versions bind one original command;
  matching retries return metadata only. Proof consumption, current authority,
  mutation risk, label CAS and exact required rename audit/outbox effects share
  one Work. Install the password management proof suffix, request-key history
  and explicitly allocated `MetadataVersionMigrationSource` before enabling
  this API or updated inventory. Preserve installed mapping/signin histories;
  append the next free version (3 after mapping1/signin2). Inventory versions
  now track label metadata separately from unchanged authenticating credential
  versions; old signin remains compatible, while inventory readers need the
  updated projection after a rename.

- Retain existing transport data names as exact root-module aliases, including
  the password owner's adapter-neutral primary request. Fields, native method
  signatures, diagnostic labels and serialization errors remain compatible;
  reflection now reports the defining root package.
- Add authenticated original-ceremony rate metadata reads for registration,
  identified signin and identifier-free signin. They preserve original browser,
  mode, identifier and expiry binding without account lookup, risk admission,
  challenge regeneration or proof consumption. Historical metadata is not a
  current-validity lease: native completion still revalidates and consumes once.
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
