package postgres

import (
	"context"
	"fmt"
	"reflect"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// MFAPasskeyPrimary is unchanged committed assertion provenance for the native
// factor-completion owner. It is not a session or a completed factor proof.
// Completion must fence Directory, Credential, policy, factor and RP mapping in
// its sole Work, preserving Authentication's original primary time and expiry.
type MFAPasskeyPrimary struct {
	CommandID  identity.CommandID
	Primary    session.SessionSpec
	Directory  kernel.DirectoryAuthorityAdmission
	Credential kernel.CredentialAdmission
}

func (MFAPasskeyPrimary) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.MFAPasskeyPrimary(redacted)"))
}
func (MFAPasskeyPrimary) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (MFAPasskeyPrimary) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// ReadMFAPasskeyPrimary authenticates the issued child, committed native parent
// and original encrypted preparation before returning original primary custody.
// It never signs, regenerates, renews or issues authentication. Flow must be the
// original browser record; possession and pending lifecycle are independently
// checked by MFA completion. Caller must be trusted self-user query attribution.
// Current authority and original expiry are preliminary fences, not a substitute
// for the completion owner's same-transaction rechecks. Earlier cancellation
// bounds every borrowed read; unavailable, foreign or retired keys fail closed.
func (s *SigninService) ReadMFAPasskeyPrimary(ctx context.Context, proof capability.Proof, continuation mfa.PartialAuthContinuation, flow session.PreAuthTransaction, caller authorization.DecisionContext) (out MFAPasskeyPrimary, err error) {
	deny := func() (MFAPasskeyPrimary, error) { return MFAPasskeyPrimary{}, identity.ForbiddenError{} }
	if ctx == nil || s == nil || s.config == nil || s.mfa == nil || caller.Validate() != nil {
		return deny()
	}
	c := s.config()
	ctx, stop := context.WithTimeout(ctx, c.Protocol.MaximumDuration)
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out = MFAPasskeyPrimary{}
		}
	}()
	scope, err := continuation.Bindings()
	if err != nil || scope.TenantID != c.Protocol.TenantID || scope.VerificationCommandID != "" || caller.Request.Tenant != authorization.TenantID(scope.TenantID) || caller.Request.Subject.Kind != authorization.SubjectUser || string(caller.Request.Subject.ID) != string(scope.SubjectID) {
		return deny()
	}
	grant, origin, _, err := s.mfa.issuer.ReadIssuanceOrigin(ctx, s.pool, proof, "identity.mfa.complete")
	if err != nil {
		return out, err
	}
	if continuation.Authorize(grant, s.mfa.issuerURL, c.Clock.Now()) != nil || scope.PasskeyCommandID != origin || string(scope.PrimaryProofID) != string(origin) || grant.Payload().CorrelationID != string(origin) {
		return deny()
	}
	q := identity.RecoveryQuery{CommandID: origin, TenantID: scope.TenantID, UserID: identity.UserID(scope.SubjectID), ActorID: identity.ActorID(scope.SubjectID), ActorKind: authorization.SubjectUser, RecordID: string(origin), OperationID: signinOperation(true).OperationID}
	disclosure := caller.Clone()
	disclosure.PolicyRevision = authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion)
	disclosure.Request.Action = authorization.Action(q.OperationID)
	disclosure.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(q.UserID)}
	p := &signinInvocation{Store: s.protocol, service: s, operation: signinOperation(true), mfa: &signinMFAState{}}
	coordinator, _, err := p.runtime()
	if err != nil {
		return out, err
	}
	expected, record, present, err := coordinator.QueryPasskeyMFAChallenge(ctx, q, disclosure)
	digest, digestErr := continuation.ScopeDigest()
	if err != nil || digestErr != nil || !present || record.Outcome != identity.CommitOutcomeCommitted || expected.ID != identity.CommandID(scope.ID) || expected.UserID != q.UserID || expected.ScopeDigest != digest || expected.PolicyVersion != scope.PolicyVersion || expected.FactorVersion != scope.FactorVersion || !expected.IssuedAt.Equal(scope.IssuedAt) || !expected.ExpiresAt.Equal(scope.ExpiresAt) {
		return deny()
	}
	wire, generation, err := coordinator.QueryFeaturePreparation(ctx, q, disclosure, kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: signinOperation(true)}, p)
	defer clear(wire)
	if err != nil {
		return out, err
	}
	stored, err := s.readMFAOutput(ctx, record.Binding, generation, wire)
	if err != nil {
		return out, err
	}
	defer clear(stored.Checkpoint)
	originalScope := mfa.ContinuationSpec(stored.Scope)
	originalScope.RememberPolicy, err = session.NewRememberPolicy(stored.Flow.Remember)
	if err != nil {
		return deny()
	}
	original, err := mfa.NewPartialAuthContinuation(originalScope)
	if err != nil {
		return deny()
	}
	originalDigest, err := original.ScopeDigest()
	if err != nil || originalDigest != digest || originalScope.PrimaryProofDigest != stored.PrimaryDigest || !reflect.DeepEqual(stored.Primary.Remember, stored.Flow.Remember) {
		return deny()
	}
	supplied, err := signinFlowProjection(flow)
	if err != nil || supplied != stored.Flow || flow.Check(c.Clock.Now(), flowBinding(flow), supplied.Cookie) != nil {
		return deny()
	}
	primary, err := stored.Primary.restore()
	if err != nil {
		return deny()
	}
	provenance := primary.Authentication.Proof
	if provenance.Purpose != session.PasskeyMFAPrimaryPurpose || provenance.Method != "passkey" || provenance.Assurance != auth.AssurancePhishingResistant || primary.Authentication.Kind != session.AuthenticationVerified || primary.Authentication.ProofVersion != 1 || string(provenance.ID) != string(origin) || primary.SessionID != string(origin) || provenance.Tenant != string(scope.TenantID) || provenance.Subject != string(scope.SubjectID) || primary.TenantID != scope.TenantID || primary.UserID != identity.UserID(scope.SubjectID) || primary.Audience != c.Profile.Audience || scope.PrimaryProofID != provenance.ID || !scope.PrimaryProofExpiresAt.Equal(provenance.ExpiresAt) || !scope.IssuedAt.Equal(provenance.IssuedAt) || !c.Clock.Now().Before(provenance.ExpiresAt) {
		return deny()
	}
	vector, err := primary.Authority.Bindings()
	if err != nil {
		return deny()
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.Profile.GlobalAuthorityID, TenantID: primary.TenantID})
	if err != nil || !directory.Enabled || directory.GlobalVersion != vector.Global.Version || directory.TenantVersion != vector.Tenant.Version {
		return deny()
	}
	status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: primary.TenantID, UserID: primary.UserID})
	if err != nil || status.User.Status != identity.StatusActive || status.AuthorityVersion != vector.User.Version {
		return deny()
	}
	identifiers, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: primary.TenantID, UserID: primary.UserID, MaximumIdentifiers: 128})
	if err != nil || identifiers.AuthorityVersion != vector.Identifier.Version {
		return deny()
	}
	ref := identity.CredentialRef{ID: identity.CredentialID(primary.Authentication.CredentialID), TenantID: primary.TenantID, UserID: primary.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: primary.Authentication.CredentialVersion}
	credential, err := s.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: primary.TenantID, UserID: primary.UserID, CredentialID: ref.ID})
	if err != nil || credential.AuthorityVersion != vector.Credential.Version || identity.CheckCredentialAuthority(credential, ref, vector.Credential.Version, c.Clock.Now()) != nil {
		return deny()
	}
	factor, enrolled, err := mfapg.ReadPasswordSigninFactors(ctx, s.pool, primary.TenantID, primary.UserID, c.Protocol.MaximumDuration)
	if err != nil || !enrolled || !vector.Factor.Present || factor != vector.Factor.Binding.Version || factor != scope.FactorVersion {
		return deny()
	}
	pol, err := s.policy.Get(ctx, policy.AuthorityScope{TenantID: authorization.TenantID(primary.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(primary.UserID)})
	if err != nil || pol.Version != vector.Authorization.Version {
		return deny()
	}
	if !vector.Passkey.Present {
		return deny()
	}
	if err := requireMappingAuthority(ctx, s.pool.Raw().Query, SessionAuthorityConfig{TenantID: primary.TenantID, RPNamespace: c.Profile.RPNamespace, RPID: c.Protocol.RelyingParty.ID, MaximumDuration: c.Protocol.MaximumDuration}, primary, vector.Passkey.Binding.Version, false); err != nil {
		return out, err
	}
	return MFAPasskeyPrimary{CommandID: origin, Primary: primary, Directory: kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}, Credential: kernel.CredentialAdmission{Credential: ref, UserAuthorityVersion: vector.User.Version, IdentifierAuthorityVersion: vector.Identifier.Version, CredentialAuthorityVersion: vector.Credential.Version}}, nil
}

func flowBinding(flow session.PreAuthTransaction) session.PreAuthBinding {
	s, _ := flow.Bindings()
	return s.Binding
}
