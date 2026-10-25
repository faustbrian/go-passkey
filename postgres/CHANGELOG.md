# Changelog

## Unreleased

- Explicitly select completed passkey/TOTP sessions for safe credential inventory
  and fresh action-bound UV label rename. Preserve original confirmed enrollment,
  factor generation, native mapping and session authority through protected
  mutation and final checks. Ordinary known-empty and other secondary-factor
  profiles do not become fallback paths; enrollment/removal are not enabled.

- Preserve original identified signin rate metadata for the explicitly selected
  passkey-primary/TOTP profile. Require the original canonical MFA selection and
  custody binding without account lookup, risk admission or consumption; a rate
  read still cannot issue a challenge or authenticate a user. Default and
  discoverable signin behavior is unchanged.

- Add an explicit native UV-passkey-primary to confirmed-TOTP challenge profile
  for identified and discoverable signin. Consume the genuine assertion and
  persist the original child atomically without any provisional session or
  CSRF credential. Retain original browser, remember, primary expiry and epochs
  through authenticated journal recovery; default enrolled-factor denial and
  known-empty signin/signup remain unchanged. Install the MFA owner's selected
  passkey-continuation migration and retain original journal envelope keys.

- Support explicitly selected Ed25519 and ordered mixed ES256/Ed25519 profiles
  through enrollment, passkey-only signup, signin and current-session key
  enrollment, rename and removal. Nil keeps ES256; empty, duplicate, unknown and
  RS256 selections deny. Original profile order remains bound to continuations.
  Last-key recovery counts only keys admitted by the current signin profile and
  finds a later selected key after earlier unselected mappings. Existing
  migrations, protocol verification and session/recovery custody are unchanged.

- Add explicit current-passkey-session UV removal with an independently usable
  resident ES256 key, atomic protocol/reference/mapping removal and affected
  passkey-session invalidation. Last-key removal and stale/substituted authority
  deny. Preserve original options/completion keys and metadata-only recovery
  under a newly authenticated surviving-key session. Install WebAuthn migration
  6 and selected kernel/MFA admissions before use; password-proof removal and
  independent password-session authority remain unchanged.

- Add `RegistrationOptionsForDelivery`, preserving the existing B API while
  exposing its genuine original UV authorization expiry alongside fresh options.
  B's later protocol TTL cannot substitute for that final delivery ceiling.
  Replays/errors return zero expiry and no options; no lease or proof is renewed.

- Expose original session-enrollment ceremony rate metadata through
  `SessionRegistrationRateSource`. Authenticate current session/CSRF and exact
  native intent against genuine assertion/registration records, without command
  admission, risk charging, consumption or expiry renewal. This is a read-only
  input to canonical HTTP verification throttling, not completion authority.

- Add explicitly selected additional resident-passkey enrollment under a current
  passkey session, without password proofs. Genuine action-bound UV consumes the
  assertion and creates registration options in one transaction; finalization
  atomically persists protocol/kernel/mapping and required lifecycle effects.
  Preserve original session/CSRF, intended label/origin/network, current factor
  and policy authority and the original assertion's absolute expiry. A/B retain
  distinct retry keys; C retains its stable original command without a key.
  Committed retries reveal metadata only, never another credential or session.
  Install WebAuthn migration 5; native mapping histories are unchanged. HTTP and
  reference selection remain separate work, and password-proof APIs are intact.

- Add opt-in current-passkey-session label management without a password
  credential or reusable proof. Original keyed options bind the session, target,
  metadata version, label, RP, origin and network; a genuine UV assertion is
  consumed atomically with the label CAS, protocol counter, current owners,
  protected risk and required audit/lifecycle. Matching retries and uncertain
  commits recover metadata only. Existing password-proof APIs remain unchanged;
  HTTP/reference selection and passkey-only deletion are separate work.

- Add explicit conditional assertion options, including keyed admission,
  through the existing discovery policy and protocol owners. Conditional
  presentation preserves original flow, UV, expiry, remember and reveal-once
  semantics and completes through genuine discoverable signin/session issuance.
  Ordinary discovery shares its original keyed command; identified admission
  remains distinct. No new migration, server protocol mode or browser-UI
  certification is introduced.
- Add read-only signup ceremony rate sources bound to genuine original browser
  custody, current directory and canonical prospective registration context.
  Return only anonymous-flow metadata with the original five-minute lifetime;
  reads neither expose prospective users nor admit risk or consume/create state.
- Add explicitly selected native passkey-only signup, original pre-auth cookie
  and remember custody, genuine resident/UV registration and atomic account,
  credential, RP mapping, known-empty MFA, authorization and session creation.
  Persist all three required lifecycle events; failures roll back together and
  only a newly acknowledged winner receives bearer/CSRF. Append selected owner
  migrations and native `SignupMigrationSource` before use; old histories remain
  unchanged. No email, password or recovery factor is invented.
- Add opt-in keyed signup options through the existing request-key owner and
  original-browser metadata recovery for options/completion. Matching retries,
  consumed/expired flows and ambiguous commits do not reconstruct challenges,
  repeat effects or redeliver authentication. Reference/HTTP and conditional
  signin remain separate composition work.

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
