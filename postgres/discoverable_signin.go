package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

// DiscoverableSigninRequest is the adapter-neutral passkey data contract.
type DiscoverableSigninRequest = passkey.DiscoverableSigninRequest

// DiscoverableSigninCompletion is the adapter-neutral passkey data contract.
type DiscoverableSigninCompletion = passkey.DiscoverableSigninCompletion

func discoverableSigninRequest(r DiscoverableSigninRequest) SigninRequest {
	return SigninRequest{CommandID: r.CommandID, FlowID: r.FlowID, Cookie: r.Cookie, Origin: r.Origin, Network: r.Network, Device: r.Device, CorrelationID: r.CorrelationID}
}

// DiscoverableAuthenticationOptions selects identifier-free resident signin.
// It requires the risk owner's explicit PasskeyDiscovery policy opt-in; no
// synthetic identifier or weaker lane substitutes when unavailable. Options
// bind original browser, expiry and deployment authority, not any account. The
// selected mode cannot change at completion. No signup/conditional UI is enabled.
func (s *SigninService) DiscoverableAuthenticationOptions(ctx context.Context, r DiscoverableSigninRequest) (webauthn.AssertionOptions, error) {
	if ctx == nil || s == nil || s.config == nil {
		return webauthn.AssertionOptions{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepareProfile(ctx, discoverableSigninRequest(r), false, true)
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	protocol, err := webauthn.NewDiscoverable(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	return protocol.BeginDiscoverableAssertion(ctx, webauthn.BeginDiscoverableAssertionRequest{Context: p.ceremonyContext(), Origin: r.Origin})
}

// DiscoverableSignin cryptographically resolves credential and resident handle
// together, then admits the current identity, exact native mapping and known-
// empty secondary-factor policy. Original flow, root counter transition, session,
// CSRF and required audit/outbox effects finalize in the existing sole Work.
// No provisional, historical or ambiguous result reveals authentication. Use
// RecoverSignin for metadata-only reconciliation; it never reissues secrets.
func (s *SigninService) DiscoverableSignin(ctx context.Context, r DiscoverableSigninCompletion) (SigninResult, error) {
	if ctx == nil || s == nil || s.config == nil || len(r.CeremonyID) != 22 || len(r.Response) == 0 || len(r.Response) > 262144 {
		return SigninResult{}, identity.InvalidInputError{Field: "passkey_signin"}
	}
	ctx, stop := context.WithTimeout(ctx, s.config().Protocol.MaximumDuration)
	defer stop()
	p, err := s.prepareProfile(ctx, discoverableSigninRequest(r.DiscoverableSigninRequest), true, true)
	if err != nil {
		if ctx.Err() != nil {
			return SigninResult{}, ctx.Err()
		}
		return SigninResult{}, identity.ForbiddenError{}
	}
	p.ceremonyID = r.CeremonyID
	if err := p.readContext(ctx); err != nil {
		return SigninResult{}, err
	}
	protocol, err := webauthn.NewDiscoverable(s.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return SigninResult{}, err
	}
	verified, err := protocol.VerifyDiscoverableAssertion(ctx, webauthn.VerifyDiscoverableAssertionRequest{Context: p.ceremonyContext(), CeremonyID: r.CeremonyID, Origin: r.Origin, Response: bytes.Clone(r.Response), ExpectedVersion: 1})
	if err != nil {
		if p.finalization == nil {
			if ctx.Err() != nil {
				return SigninResult{}, ctx.Err()
			}
			return SigninResult{}, identity.ForbiddenError{}
		}
		out := p.output
		out.Session.Token, out.Session.Session, out.Session.Cookie = session.Token{}, session.Session{}, http.Cookie{}
		out.CSRF = session.CSRFToken{}
		return out, err
	}
	p.output.CounterRisk = verified.CounterRisk()
	return p.output, nil
}

func (p *signinInvocation) user() identity.User {
	if p.discoverable {
		return p.selectedUser
	}
	return p.recipient.User
}

func (p *signinInvocation) userAuthority() kernel.UserAuthorityAdmission {
	if p.discoverable {
		return kernel.UserAuthorityAdmission{UserAuthorityVersion: p.selected.UserAuthorityVersion, IdentifierAuthorityVersion: p.selected.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.selected.CredentialAuthorityVersion}
	}
	return kernel.UserAuthorityAdmission{UserAuthorityVersion: p.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: p.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.recipient.CredentialAuthorityVersion}
}

// The root's opaque transition is the first authority for target selection.
// Passkey SQL reads only our own mapping; security epochs come from public
// identity owner reads, then RequireActiveCredential fences them under Work.
func (p *signinInvocation) selectDiscovered(ctx context.Context, m webauthn.AssertionMutation) error {
	c := p.service.config()
	if m.Before.TenantID != c.Protocol.TenantID || m.Before.UserID == "" || string(m.Before.UserID) == string(c.Flow.ActorID) || m.Before.RPID != c.Protocol.RelyingParty.ID || len(m.Before.UserHandle) != 32 || m.Before.Version == 0 {
		return identity.ForbiddenError{}
	}
	var ref, referenceVersion, authorityVersion string
	var handle []byte
	err := p.service.pool.Raw().QueryRow(ctx, `SELECT c.reference_id,c.version::text,h.authority_version::text,h.user_handle
FROM identity_passkey.relying_parties p
JOIN identity_passkey.user_handles h USING(rp_namespace)
JOIN identity_passkey.credentials c USING(rp_namespace,tenant_id,user_id)
WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4
AND c.credential_id=$5 AND h.user_handle=$6 AND c.state='active'`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(c.Protocol.TenantID), string(m.Before.UserID), m.Before.ID, m.Before.UserHandle).Scan(&ref, &referenceVersion, &authorityVersion, &handle)
	if err != nil || !bytes.Equal(handle, m.Before.UserHandle) {
		return identity.ForbiddenError{}
	}
	version, ve := strconv.ParseUint(referenceVersion, 10, 64)
	passkey, pe := strconv.ParseUint(authorityVersion, 10, 64)
	if ve != nil || pe != nil || version == 0 || passkey == 0 || strconv.FormatUint(version, 10) != referenceVersion || strconv.FormatUint(passkey, 10) != authorityVersion {
		return identity.ForbiddenError{}
	}
	reference := identity.CredentialRef{ID: identity.CredentialID(ref), TenantID: c.Protocol.TenantID, UserID: m.Before.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: version}
	status, err := p.service.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: c.Protocol.TenantID, UserID: m.Before.UserID})
	if err != nil || status.User.Status != identity.StatusActive {
		return identity.ForbiddenError{}
	}
	identifiers, err := p.service.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: c.Protocol.TenantID, UserID: m.Before.UserID, MaximumIdentifiers: 128})
	if err != nil || identifiers.User != status.User {
		return identity.ForbiddenError{}
	}
	credential, err := p.service.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: c.Protocol.TenantID, UserID: m.Before.UserID, CredentialID: reference.ID})
	if err != nil || credential.User != status.User || identity.CheckCredentialAuthority(credential, reference, credential.AuthorityVersion, c.Clock.Now()) != nil {
		return identity.ForbiddenError{}
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, p.service.pool, c.Protocol.TenantID, m.Before.UserID, c.Protocol.MaximumDuration)
	if err != nil || enrolled {
		return identity.ForbiddenError{}
	}
	pol, err := p.service.policy.Get(ctx, policy.AuthorityScope{TenantID: authorization.TenantID(c.Protocol.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(m.Before.UserID)})
	if err != nil {
		return identity.ForbiddenError{}
	}
	p.selectedUser = status.User
	p.selected = kernel.CredentialAdmission{Credential: reference, UserAuthorityVersion: status.AuthorityVersion, IdentifierAuthorityVersion: identifiers.AuthorityVersion, CredentialAuthorityVersion: credential.AuthorityVersion}
	p.reference, p.factor, p.passkey, p.policy, p.protocolVersion = reference, factor, passkey, pol.Version, m.Before.Version
	p.handle = bytes.Clone(handle)
	return nil
}

func (p *signinInvocation) discoverableContextWire(target bool) ([]byte, error) {
	flow, err := p.flow.Bindings()
	if err != nil {
		return nil, err
	}
	c := p.service.config()
	// This domain is distinct from the retained identified admission encoding,
	// including its suppressed NULL-user form. No client completion mode switch
	// can reinterpret that historical ceremony as genuinely identifier-free.
	deployment, err := json.Marshal(struct {
		Tenant, Namespace, RP, Global, Policy, Audience string
		Actor, FlowPolicy, Origin, Callback             string
	}{string(c.Protocol.TenantID), c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, p.directory.Query.GlobalAuthorityID, c.Profile.PolicyNamespace, c.Profile.Audience, string(c.Flow.ActorID), c.Flow.PolicyID, c.Flow.Origin, c.Flow.CallbackURL})
	if err != nil {
		return nil, err
	}
	// signin_contexts.admission has a published 4096-byte bound. Session-owned
	// callbacks allow 2048 bytes and JSON HTML escaping can expand them sixfold.
	// A domain-separated digest binds every exact trusted string without copying
	// expandable configuration into that row; this is not authentication proof.
	deploymentDigest := sha256.Sum256(append([]byte("passkey-discovery-deployment-v1\x00"), deployment...))
	original := struct {
		Mode, Flow                                                 string
		Deployment                                                 [32]byte
		RPVersion, GlobalVersion, TenantVersion, FlowPolicyVersion uint64
		IssuedAt, ExpiresAt                                        time.Time
	}{"resident-discoverable-v1", string(flow.Binding.ID), deploymentDigest, c.Protocol.RelyingParty.Version, p.directory.GlobalVersion, p.directory.TenantVersion, c.Flow.PolicyVersion, flow.Binding.IssuedAt, flow.Binding.ExpiresAt}
	if !target || p.selectedUser.ID == "" {
		return json.Marshal(original)
	}
	return json.Marshal(struct {
		Original                                                                                     any
		User, Reference                                                                              string
		UserVersion, IdentifierVersion, CredentialVersion, ReferenceVersion, Factor, Passkey, Policy uint64
	}{original, string(p.selectedUser.ID), string(p.reference.ID), p.selected.UserAuthorityVersion, p.selected.IdentifierAuthorityVersion, p.selected.CredentialAuthorityVersion, p.reference.Version, p.factor, p.passkey, p.policy})
}
