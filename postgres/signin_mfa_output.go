package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	webauthn "github.com/faustbrian/go-webauthn"
)

// These closed projections are only authenticated encrypted journal output.
// The primary is verified-assertion provenance, never a second proof engine or
// an independently usable primary capability. No bearer is persisted here.
type signinStoredPrimary struct {
	SessionID, FamilyID      string
	TenantID                 identity.TenantID
	UserID                   identity.UserID
	Audience                 string
	Version, FamilyVersion   uint64
	Remember                 session.RememberPolicySpec
	Authority                session.AuthoritySnapshotSpec
	Authentication           session.AuthenticationMetadata
	IssuedAt, LastActivityAt time.Time
}
type signinStoredFlow struct {
	ID                               identity.PreAuthTransactionID
	Tenant                           identity.TenantID
	Action, Origin, Callback, Policy string
	PolicyVersion, Version           uint64
	Nonce, Identifier                [32]byte
	Remember                         session.RememberPolicySpec
	Purpose                          session.PreAuthPurpose
	IssuedAt, ExpiresAt              time.Time
	Cookie                           session.TokenDigest
}
type signinStoredScope mfa.ContinuationSpec
type signinStoredGrant kernel.CapabilityPlan
type signinMFAOutput struct {
	Schema        uint8
	Primary       signinStoredPrimary
	PrimaryDigest [32]byte
	Flow          signinStoredFlow
	Scope         signinStoredScope
	Issuer        kernel.ContributorDescriptor
	Grant         signinStoredGrant
	Checkpoint    []byte
}

const maximumSigninMFAOutput = 64 << 10

func signinPrimaryProjection(s session.SessionSpec) (signinStoredPrimary, error) {
	r, err := s.Remember.Bindings()
	if err != nil {
		return signinStoredPrimary{}, err
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return signinStoredPrimary{}, err
	}
	return signinStoredPrimary{s.SessionID, s.FamilyID, s.TenantID, s.UserID, s.Audience, s.Version, s.FamilyVersion, r, a, s.Authentication, s.IssuedAt, s.LastActivityAt}, nil
}
func (s signinStoredPrimary) restore() (session.SessionSpec, error) {
	r, err := session.NewRememberPolicy(s.Remember)
	if err != nil {
		return session.SessionSpec{}, err
	}
	a, err := session.NewAuthoritySnapshot(s.Authority)
	if err != nil {
		return session.SessionSpec{}, err
	}
	return session.SessionSpec{SessionID: s.SessionID, FamilyID: s.FamilyID, TenantID: s.TenantID, UserID: s.UserID, Audience: s.Audience, Version: s.Version, FamilyVersion: s.FamilyVersion, Remember: r, Authority: a, Authentication: s.Authentication, IssuedAt: s.IssuedAt, LastActivityAt: s.LastActivityAt}, nil
}
func signinFlowProjection(f session.PreAuthTransaction) (signinStoredFlow, error) {
	s, err := f.Bindings()
	if err != nil {
		return signinStoredFlow{}, err
	}
	b, i := s.Binding, s.Binding.Intent
	r, err := i.Remember.Bindings()
	if err != nil {
		return signinStoredFlow{}, err
	}
	return signinStoredFlow{b.ID, i.TenantID, i.Action, i.Origin, i.CallbackURL, i.PolicyID, i.PolicyVersion, s.Version, i.Nonce, i.IdentifierBinding, r, i.Purpose, b.IssuedAt, b.ExpiresAt, s.Cookie}, nil
}
func (s *SigninService) mfaOutputAAD(b identity.CommandBinding, generation uint64) (envelope.Context, error) {
	if s == nil || s.config == nil || s.mfa == nil || generation == 0 || b.ValidateFor(signinOperation(true)) != nil {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	c := s.config()
	frame, err := json.Marshal(struct {
		Binding                                                identity.CommandBinding
		Generation                                             uint64
		Namespace, RP, Audience, Origin, Callback, Issuer, Key string
		Global, PolicyNamespace                                string
		Algorithms                                             []webauthn.Algorithm
		RPVersion                                              uint64
		Lifetime                                               time.Duration
		Attempts                                               uint32
	}{b, generation, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, c.Profile.Audience, c.Flow.Origin, c.Flow.CallbackURL, s.mfa.issuerURL, s.mfa.envelopeKey, c.Profile.GlobalAuthorityID, c.Profile.PolicyNamespace, c.Protocol.Algorithms, c.Protocol.RelyingParty.Version, s.mfa.lifetime, s.mfa.attempts})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, err
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-passkey-mfa-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *signinInvocation) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if p == nil || p.mfa == nil || c != p.mfa.original || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	s := p.service
	if err := p.risk.CheckAt(ctx, s.config().Clock.Now()); err != nil {
		return nil, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return nil, err
	}
	flow, err := signinFlowProjection(p.flow)
	if err != nil {
		return nil, err
	}
	primary, err := signinPrimaryProjection(p.mfa.primary)
	if err != nil {
		return nil, err
	}
	issued := primary.Authentication.Proof.IssuedAt
	expires := issued.Add(s.mfa.lifetime)
	for _, cap := range []time.Time{primary.Authentication.Proof.ExpiresAt, flow.ExpiresAt} {
		if cap.Before(expires) {
			expires = cap.Truncate(time.Second)
		}
	}
	b := p.binding()
	continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(id), PrimaryProofID: primary.Authentication.Proof.ID, PrimaryProofDigest: p.mfa.digest, PrimaryProofExpiresAt: primary.Authentication.Proof.ExpiresAt, TenantID: b.TenantID, SubjectID: identity.SubjectID(b.UserID), SourcePreAuthID: flow.ID, Origin: flow.Origin, AllowedMethods: []string{"totp"}, PolicyVersion: b.PolicyVersion, FactorVersion: p.factor, RememberPolicy: p.mfa.primary.Remember, Purpose: "identity.mfa.complete", Audience: primary.Audience, IssuedAt: issued, ExpiresAt: expires, MaxAttempts: s.mfa.attempts, AttemptsRemaining: s.mfa.attempts, State: mfa.Pending, Version: 1, PasskeyCommandID: b.CommandID})
	if err != nil {
		return nil, err
	}
	payload, err := continuation.CapabilityPayload(s.mfa.issuerURL)
	if err != nil {
		return nil, err
	}
	prepared, err := s.mfa.issuer.PreparePasskeyMFAContinuation(ctx, b, payload)
	if err != nil {
		return nil, err
	}
	checkpoint, err := s.mfa.codec.CheckpointPreparation(ctx, prepared, generation, func(_ context.Context, index uint16, raw []byte) error {
		if index != 0 {
			return identity.ForbiddenError{}
		}
		var e error
		p.mfa.proof, e = capability.ParseProof(string(raw), capability.DefaultLimits())
		return e
	})
	defer clear(checkpoint)
	if err != nil {
		return nil, err
	}
	metadata, err := prepared.Plan()
	if err != nil || len(metadata.Grants) != 1 {
		return nil, identity.ForbiddenError{}
	}
	scope, _ := continuation.Bindings()
	scope.RememberPolicy = session.RememberPolicy{}
	stored := signinMFAOutput{Schema: 1, Primary: primary, PrimaryDigest: p.mfa.digest, Flow: flow, Scope: signinStoredScope(scope), Issuer: metadata.Contributor, Grant: signinStoredGrant(metadata.Grants[0]), Checkpoint: checkpoint}
	// The private alias bypasses only ContinuationSpec's public export denial.
	// Remember's actual scalar projection is retained separately, never defaulted.
	plain, err := marshalSigninMFAOutput(stored)
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumSigninMFAOutput-4096 {
		return nil, identity.ForbiddenError{}
	}
	aad, err := s.mfaOutputAAD(b, generation)
	if err != nil {
		return nil, err
	}
	sealed, err := s.mfa.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: s.mfa.envelopeKey, Context: aad})
	if err != nil {
		return nil, err
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSigninMFAOutput {
		return nil, identity.ForbiddenError{}
	}
	return wire, nil
}

func marshalSigninMFAOutput(s signinMFAOutput) ([]byte, error) {
	return json.Marshal(s)
}
func (s *SigninService) readMFAOutput(ctx context.Context, b identity.CommandBinding, generation uint64, wire []byte) (out signinMFAOutput, err error) {
	defer func() {
		if err != nil {
			clear(out.Checkpoint)
			out = signinMFAOutput{}
		}
	}()
	if ctx == nil || len(wire) == 0 || len(wire) > maximumSigninMFAOutput {
		return out, identity.ForbiddenError{}
	}
	aad, err := s.mfaOutputAAD(b, generation)
	if err != nil {
		return out, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	plain, err := s.mfa.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumSigninMFAOutput-4096 {
		return out, identity.ForbiddenError{}
	}
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, identity.ForbiddenError{}
	}
	canonical, err := marshalSigninMFAOutput(out)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) || out.Schema != 1 || out.PrimaryDigest == ([32]byte{}) || out.Scope.PasskeyCommandID != b.CommandID || out.Scope.VerificationCommandID != "" || string(out.Scope.PrimaryProofID) != string(b.CommandID) {
		return out, identity.ForbiddenError{}
	}
	return out, nil
}

func (p *signinInvocation) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	deny := func() (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	if p == nil || p.mfa == nil || c != p.mfa.original || c == (identity.Command{}) {
		return deny()
	}
	f, _ := c.Feature()
	stored, err := p.service.readMFAOutput(ctx, f.Binding, generation, wire)
	if err != nil {
		return deny()
	}
	defer clear(stored.Checkpoint)
	primary, err := signinPrimaryProjection(p.mfa.primary)
	if err != nil {
		return deny()
	}
	flow, err := signinFlowProjection(p.flow)
	if err != nil || stored.PrimaryDigest != p.mfa.digest || !reflect.DeepEqual(primary, stored.Primary) || flow != stored.Flow {
		return deny()
	}
	scope := mfa.ContinuationSpec(stored.Scope)
	scope.RememberPolicy = p.mfa.primary.Remember
	continuation, err := mfa.NewPartialAuthContinuation(scope)
	proof := primary.Authentication.Proof
	if err != nil || scope.State != mfa.Pending || scope.Version != 1 || scope.PasskeyCommandID != f.Binding.CommandID || scope.VerificationCommandID != "" || scope.AttemptsRemaining != p.service.mfa.attempts || scope.MaxAttempts != p.service.mfa.attempts || scope.PrimaryProofID != proof.ID || scope.PrimaryProofDigest != stored.PrimaryDigest || !scope.PrimaryProofExpiresAt.Equal(proof.ExpiresAt) || scope.TenantID != f.Binding.TenantID || scope.SubjectID != identity.SubjectID(f.Binding.UserID) || scope.SourcePreAuthID != flow.ID || scope.Origin != flow.Origin || scope.PolicyVersion != f.Binding.PolicyVersion || scope.FactorVersion != p.factor || !reflect.DeepEqual(scope.AllowedMethods, []string{"totp"}) || !scope.IssuedAt.Equal(proof.IssuedAt) || scope.ExpiresAt.After(proof.ExpiresAt) || scope.ExpiresAt.After(flow.ExpiresAt) || scope.ExpiresAt.Sub(scope.IssuedAt) > p.service.mfa.lifetime || scope.Audience != primary.Audience {
		return deny()
	}
	metadata := kernel.CapabilityIssuancePlan{Contributor: stored.Issuer, MFAContinuationUserID: f.Binding.UserID, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(stored.Grant)}}
	prepared, err := p.service.mfa.codec.RestorePreparation(ctx, f.Binding, generation, metadata, stored.Checkpoint)
	if err != nil {
		return deny()
	}
	f.Fields = append(f.Fields, identity.FeatureField{Name: "mfa.challenge-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(scope.ID)}})
	command, err := identity.NewFeaturePreAuthCommand(f, p.mfa.browser)
	if err != nil {
		return deny()
	}
	p.command, p.mfa.continuation, p.mfa.prepared = command, continuation, prepared
	p.mfa.outputGeneration, p.mfa.outputDigest = generation, sha256.Sum256(wire)
	plan, err := p.mfaPlan(true)
	if err != nil {
		return deny()
	}
	plan, err = p.mfa.coordinator.PrepareCommandPlan(f.Binding, command, plan)
	if err != nil {
		return deny()
	}
	return command, plan, nil
}
