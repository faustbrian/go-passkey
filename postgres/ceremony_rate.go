package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// SessionRegistrationRateSource authenticates current completion-action session
// and original enrollment intent before returning the B ceremony's user rate
// metadata. It reads genuine A/B records and retains A's absolute expiry; a
// later registration TTL cannot renew authorization. It issues no proof, options,
// command reservation or risk admission and consumes nothing. Historical consumed
// metadata may remain readable, but Register independently revalidates all
// authority and atomically consumes. Custody is borrowed for the call; the pool
// and owners must outlive concurrent calls. Earlier cancellation takes precedence
// over Protocol.MaximumDuration. Denial returns no metadata.
func (s *SessionEnrollmentService) SessionRegistrationRateSource(ctx context.Context, custody passkey.SessionEnrollmentRequest, ceremonyID string) (passkey.CeremonyRateSource, error) {
	if ctx == nil || s == nil || s.owner == nil {
		return passkey.CeremonyRateSource{}, identity.InvalidInputError{Field: "passkey_rate_source"}
	}
	c := s.owner.config()
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	r, err := custody.Bindings()
	if err != nil || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Origin) == 0 || len(r.Origin) > 2048 || !slices.Contains(c.Protocol.RelyingParty.Origins, r.Origin) {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	if _, err := identity.ParseCommandID(ceremonyID); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	read, record, err := s.owner.authenticateAction(ctx, passkey.SessionUpdateRequest{Credential: r.Credential, CSRFToken: r.CSRFToken, Caller: r.Caller}, "identity.passkey.register-verify")
	if err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	// Unlike prepare, this projection never resolves a request key or observes/
	// recovers a command. The existing original-context reader performs only IO
	// reads and matches the actual session, profile, intent and credential handle.
	p := &sessionEnrollmentInvocation{service: s, request: r, read: read, record: record, stage: 2, id: identity.CommandID(ceremonyID), ceremonyID: ceremonyID}
	if err := p.prepareOriginal(ctx); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	var now time.Time
	if err := s.owner.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !now.Before(p.ceiling) || !c.Clock.Now().Before(p.ceiling) {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	registration, err := readRateCeremony(ctx, s.owner.protocol, c.Protocol, p.protocolContext(), ceremonyID, r.Origin, "create", now)
	if err != nil || !bytes.Equal(registration.Intent.UserHandle, p.authProtocol.UserHandle) {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	assertion, err := readRateCeremony(ctx, s.owner.protocol, c.Protocol, p.protocolContext(), p.parent.Parent, r.Origin, "get", now)
	if err != nil || !assertion.ExpiresAt.Equal(p.ceiling) || !bytes.Equal(assertion.Intent.UserHandle, p.authProtocol.UserHandle) || len(assertion.Intent.AllowedCredentials) != 1 || !bytes.Equal(assertion.Intent.AllowedCredentials[0], p.authProtocol.ID) {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	// Both protocol reads can cross an expiry boundary. A session observation
	// remaining valid does not extend either ceremony, so sample time again only
	// after those reads and fence each original expiry before disclosing metadata.
	if err := s.owner.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil || !p.rateFresh(now, c.Clock.Now(), registration.ExpiresAt) || ctx.Err() != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	return passkey.CeremonyRateSource{CeremonyID: ceremonyID, Lifetime: originalCeremonyLifetime, Kind: passkey.RateSourceUser, UserID: record.UserID}, nil
}

func (p *sessionEnrollmentInvocation) rateFresh(databaseNow, observedNow, registrationExpiry time.Time) bool {
	return databaseNow.Before(p.ceiling) && observedNow.Before(p.ceiling) && databaseNow.Before(registrationExpiry) && observedNow.Before(registrationExpiry) && p.read.ValidateAt(databaseNow.UTC()) == nil && p.read.ValidateAt(observedNow.UTC()) == nil
}

// RegistrationRateSource authenticates genuine completion-phase session/action
// custody and the original committed native ceremony context. It returns only
// sensitive rate metadata, not a current-validity lease. Historical consumed
// metadata may remain readable; Register still revalidates/consumes atomically.
// No proof, challenge, risk admission, credential or account lookup is created.
// Calls are bounded by Protocol.MaximumDuration and preserve cancellation.
func (s *EnrollmentService) RegistrationRateSource(ctx context.Context, r passkey.RegistrationCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil {
		return passkey.CeremonyRateSource{}, identity.InvalidInputError{Field: "passkey_rate_source"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	if _, err := identity.ParseCommandID(r.CeremonyID); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	p, err := s.preparePrimary(ctx, r.RegistrationRequest, true)
	if err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	vector, err := p.record.Authority.Bindings()
	if err != nil || vector.Organization.Present || vector.Passkey.Present {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	var one int
	err = s.pool.Raw().QueryRow(ctx, `SELECT 1 FROM identity_passkey.enrollment_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4 AND session_id=$5 AND session_version=$6 AND user_epoch=$7 AND identifier_epoch=$8 AND credential_epoch=$9`, s.config().RPNamespace, r.CeremonyID, string(p.record.TenantID), string(p.record.UserID), p.record.SessionID, p.record.Version, vector.User.Version, vector.Identifier.Version, vector.Credential.Version).Scan(&one)
	if err != nil || one != 1 {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	var now time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	if _, err := readRateCeremony(ctx, s.protocol, s.config().Protocol, p.ceremonyContext(), r.CeremonyID, r.Origin, "create", now); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	return passkey.CeremonyRateSource{CeremonyID: r.CeremonyID, Lifetime: originalCeremonyLifetime, Kind: passkey.RateSourceUser, UserID: p.record.UserID}, nil
}

// SigninRateSource authenticates original identified browser/ceremony custody,
// including the exact originally suppressed identifier. It performs no account
// lookup, assertion parsing, risk admission or consumption, and reveals no user
// or eligibility. Metadata is not a validity lease; Signin remains authoritative.
// Concurrent calls borrow the native pool and are bounded by MaximumDuration.
func (s *SigninService) SigninRateSource(ctx context.Context, r passkey.SigninCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	return s.signinRateSource(ctx, r.SigninRequest, r.CeremonyID, false)
}

// DiscoverableSigninRateSource authenticates the original identifier-free
// browser/mode without selecting an account or manufacturing a UserID. Only
// original anonymous-flow rate metadata is returned. Discovery completion must
// still verify, revalidate and consume once; a read issues/renews nothing.
func (s *SigninService) DiscoverableSigninRateSource(ctx context.Context, r passkey.DiscoverableCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	return s.signinRateSource(ctx, discoverableSigninRequest(r.DiscoverableSigninRequest), r.CeremonyID, true)
}

// SignupRateSource authenticates original signup cookie/flow possession, current
// directory authority and canonical prospective registration context. It returns
// only anonymous-flow metadata: no user is authenticated or exposed. No risk,
// command, proof, challenge, account or session state is created or consumed.
// Metadata never renews the ceremony or authorizes Signup, which revalidates and
// consumes atomically. Calls borrow the native pool and are bounded/cancelable.
func (s *SignupService) SignupRateSource(ctx context.Context, r passkey.SignupCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	if ctx == nil || s == nil || s.core == nil || s.core.config == nil || s.core.pool == nil {
		return passkey.CeremonyRateSource{}, identity.InvalidInputError{Field: "passkey_rate_source"}
	}
	ctx, stop := context.WithTimeout(ctx, s.core.config().Protocol.MaximumDuration)
	defer stop()
	if _, err := identity.ParseCommandID(r.CeremonyID); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	p, err := s.prepare(ctx, r.SignupRequest, true)
	if err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	p.ceremonyID = r.CeremonyID
	if err := p.readContext(ctx); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	record, err := readRateCeremony(ctx, s.core.protocol, s.core.config().Protocol, p.ceremonyContext(), r.CeremonyID, r.Origin, "create", s.core.config().Clock.Now())
	if err != nil || !bytes.Equal(record.Intent.UserHandle, p.handle) || len(record.Intent.AllowedCredentials) != 0 {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	return passkey.CeremonyRateSource{CeremonyID: r.CeremonyID, Lifetime: originalCeremonyLifetime, Kind: passkey.RateSourceAnonymousFlow, AnonymousFlowID: r.FlowID}, nil
}

func (s *SigninService) signinRateSource(ctx context.Context, r SigninRequest, ceremonyID string, discoverable bool) (passkey.CeremonyRateSource, error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil {
		return passkey.CeremonyRateSource{}, identity.InvalidInputError{Field: "passkey_rate_source"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	if _, err := identity.ParseCommandID(ceremonyID); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	p, err := s.prepareFlow(ctx, r, true, discoverable)
	if err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	p.ceremonyID = ceremonyID
	if err := p.prepareDirectory(ctx); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	if err := p.readRateContext(ctx); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	if _, err := readRateCeremony(ctx, s.protocol, s.config().Protocol, p.ceremonyContext(), ceremonyID, r.Origin, "get-discoverable", s.config().Clock.Now()); err != nil {
		return passkey.CeremonyRateSource{}, rateSourceError(ctx)
	}
	result := passkey.CeremonyRateSource{CeremonyID: ceremonyID, Lifetime: originalCeremonyLifetime}
	if discoverable {
		result.Kind, result.AnonymousFlowID = passkey.RateSourceAnonymousFlow, r.FlowID
	} else {
		result.Kind, result.Identifier = passkey.RateSourceIdentifier, r.Identifier
	}
	return result, nil
}

func (p *signinInvocation) prepareDirectory(ctx context.Context) error {
	c := p.service.config()
	directory, err := p.service.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.Profile.GlobalAuthorityID, TenantID: c.Protocol.TenantID})
	if err != nil || !directory.Enabled {
		return identity.ForbiddenError{}
	}
	p.directory = directory
	return nil
}

func (p *signinInvocation) readRateContext(ctx context.Context) error {
	if p.discoverable {
		return p.readContext(ctx)
	}
	var wire []byte
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3`, p.service.config().Profile.RPNamespace, p.ceremonyID, string(p.service.config().Protocol.TenantID)).Scan(&wire)
	if err != nil {
		return identity.ForbiddenError{}
	}
	original, err := p.service.decodeIdentifiedRateContext(wire)
	if err != nil || original.Flow != string(p.request.FlowID) || original.Namespace != p.service.config().Profile.RPNamespace || original.Global != p.directory.Query.GlobalAuthorityID || original.Policy != p.service.config().Profile.PolicyNamespace || original.Input != p.identifier || original.GlobalVersion != p.directory.GlobalVersion || original.TenantVersion != p.directory.TenantVersion {
		return identity.ForbiddenError{}
	}
	return nil
}

func (s *SigninService) decodeIdentifiedRateContext(wire []byte) (identifiedSigninContext, error) {
	invalid := func() (identifiedSigninContext, error) { return identifiedSigninContext{}, identity.ForbiddenError{} }
	if len(wire) == 0 || len(wire) > 4096 {
		return invalid()
	}
	input := wire
	if s.mfa != nil {
		var selected struct{ Original json.RawMessage }
		if json.Unmarshal(wire, &selected) != nil {
			return invalid()
		}
		input = selected.Original
	}
	var original identifiedSigninContext
	if json.Unmarshal(input, &original) != nil {
		return invalid()
	}
	canonical, err := json.Marshal(original)
	if err != nil {
		return invalid()
	}
	// contextWire stores the selected MFA wrapper, not just the identified
	// payload. Reuse its encoder to bind the current selection/custody digest
	// while exact bytes reject unknown, duplicate and noncanonical fields.
	canonical, err = s.signinMFAContext(canonical)
	if err != nil || !bytes.Equal(canonical, wire) {
		return invalid()
	}
	return original, nil
}

// CeremonyCreation.Generate in the pinned WebAuthn owner fixes this original
// policy duration at five minutes. It is not remaining TTL, and consumption
// does not renew it. A future owner profile change requires an explicit adapter
// update rather than deriving a fresh duration from the time of this read.
const originalCeremonyLifetime = 5 * time.Minute

func readRateCeremony(ctx context.Context, store *webauthnpg.Store, c webauthn.Config, scope webauthn.CeremonyContext, id, origin, kind string, now time.Time) (webauthn.CeremonyRecord, error) {
	if _, err := identity.ParseCommandID(id); err != nil || !slices.Contains(c.RelyingParty.Origins, origin) {
		return webauthn.CeremonyRecord{}, identity.ForbiddenError{}
	}
	record, err := store.LoadCeremony(ctx, webauthn.Lookup{Context: scope, RPID: c.RelyingParty.ID, CeremonyID: id})
	if err != nil {
		return webauthn.CeremonyRecord{}, identity.ForbiddenError{}
	}
	i := record.Intent
	if (i.Algorithms == nil) != (c.Algorithms == nil) {
		return webauthn.CeremonyRecord{}, identity.ForbiddenError{}
	}
	if record.ID != id || string(i.Context.CommandID) != id || record.Version != 1 || i.Kind != kind || i.Context.TenantID != scope.TenantID || i.Context.UserID != scope.UserID || i.Context.ActorID != scope.ActorID || i.Context.AnonymousFlowID != scope.AnonymousFlowID || i.RPID != c.RelyingParty.ID || i.RPVersion != c.RelyingParty.Version || i.Origin != origin || i.Extensions != c.Extensions || !slices.Equal(i.Algorithms, c.Algorithms) || record.ChallengeDigest == ([32]byte{}) || record.ExpiresAt.IsZero() || !now.Before(record.ExpiresAt) || now.Before(record.ExpiresAt.Add(-originalCeremonyLifetime)) {
		return webauthn.CeremonyRecord{}, identity.ForbiddenError{}
	}
	if kind == "create" && (len(i.UserHandle) != 32 || !i.ResidentKeyRequired) || kind == "get-discoverable" && (len(i.UserHandle) != 0 || len(i.AllowedCredentials) != 0 || i.ResidentKeyRequired) {
		return webauthn.CeremonyRecord{}, identity.ForbiddenError{}
	}
	return record, nil
}

func rateSourceError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return identity.ForbiddenError{}
}
