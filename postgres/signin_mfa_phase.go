package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	webauthn "github.com/faustbrian/go-webauthn"
)

type signinMFAState struct {
	original         identity.Command
	browser          auth.BearerCredential
	primary          session.SessionSpec
	digest           [32]byte
	continuation     mfa.PartialAuthContinuation
	prepared         issuerpg.PreparedIssuance
	proof            capability.Proof
	coordinator      *kernel.Coordinator
	registry         *kernel.ContributorRegistry
	outputGeneration uint64
	outputDigest     [32]byte
}

var _ kernel.PasskeyMFAChallengeContributor = (*signinInvocation)(nil)
var _ kernel.FeaturePreparationContributor = (*signinInvocation)(nil)

func (p *signinInvocation) finalizeMFAChallenge(ctx context.Context) (webauthn.Credential, identity.CommitOutcome, error) {
	if p.service.mfa == nil || !p.enrolled || p.finalization == nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	if err := p.authorize(ctx); err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	spec, err := p.sessionSpec()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	browser, err := p.request.Cookie.Reveal()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.mfa = &signinMFAState{primary: spec, browser: auth.NewBearerCredential(browser)}
	fields, err := p.finalization.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	primary, err := signinPrimaryProjection(spec)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	wire, err := json.Marshal(struct {
		Primary   signinStoredPrimary
		Assertion []identity.FeatureField
	}{primary, fields})
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.mfa.digest = sha256.Sum256(wire)
	clear(wire)
	fields = append(fields, identity.FeatureField{Name: "passkey.mfa.primary", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(p.mfa.digest[:])}})
	command, err := p.makeCommand(fields)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	f, _ := command.Feature()
	p.mfa.original, err = identity.NewFeaturePreAuthCommand(f, p.mfa.browser)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.command = p.mfa.original
	p.mfa.coordinator, p.mfa.registry, err = p.runtime()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	declaration, err := p.mfaPlan(false)
	if err == nil {
		declaration, err = p.mfa.coordinator.PrepareFeaturePreparationPlan(p.command, declaration)
	}
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.result, err = p.mfa.coordinator.ExecutePreparedFeature(ctx, p.mfa.original, declaration)
	p.output.Receipt = p.result
	if p.result.Outcome == identity.CommitOutcomeCommitted {
		scope, e := p.mfa.continuation.Bindings()
		if e != nil {
			return webauthn.Credential{}, p.result.Outcome, identity.UnavailableError{}
		}
		p.output.Replayed = !p.applied || p.mfa.proof == (capability.Proof{})
		p.output.Challenge = &passkey.SigninMFAChallenge{ID: identity.CommandID(scope.ID), Method: "totp", ExpiresAt: scope.ExpiresAt}
		if err == nil && !p.output.Replayed && p.mfa.continuation.RequirePending(p.service.config().Clock.Now()) == nil {
			p.output.Challenge.Proof = p.mfa.proof
		}
	}
	if err != nil {
		return webauthn.Credential{}, p.result.Outcome, err
	}
	if p.result.Outcome != identity.CommitOutcomeCommitted || !p.applied {
		return webauthn.Credential{}, p.result.Outcome, identity.ForbiddenError{}
	}
	credential, err := p.finalization.Result(p.result)
	return credential, p.result.Outcome, err
}

func (p *signinInvocation) mfaScope() (kernel.MFAContinuationPlan, error) {
	if p == nil || p.mfa == nil {
		return kernel.MFAContinuationPlan{}, identity.ForbiddenError{}
	}
	s, err := p.mfa.continuation.Bindings()
	if err != nil {
		return kernel.MFAContinuationPlan{UserID: p.user().ID, PolicyVersion: p.binding().PolicyVersion, FactorVersion: p.factor}, nil
	}
	d, err := p.mfa.continuation.ScopeDigest()
	return kernel.MFAContinuationPlan{ID: identity.CommandID(s.ID), UserID: identity.UserID(s.SubjectID), PolicyVersion: s.PolicyVersion, FactorVersion: s.FactorVersion, ScopeDigest: d, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt}, err
}

func (p *signinInvocation) ValidatePasskeyMFAChallenge(c identity.Command, scope kernel.MFAContinuationPlan) error {
	if p == nil || p.mfa == nil || p.finalization == nil || c == (identity.Command{}) || c != p.mfa.original && c != p.command {
		return identity.ForbiddenError{}
	}
	expected := kernel.MFAContinuationPlan{UserID: p.user().ID, PolicyVersion: p.binding().PolicyVersion, FactorVersion: p.factor}
	if c != p.mfa.original {
		var err error
		expected, err = p.mfaScope()
		if err != nil {
			return err
		}
	}
	if scope != expected {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinInvocation) validateMFACommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.mfa == nil || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != signinOperation(true) || plan.SubjectType != "authentication_attempt" || plan.MFAContinuation == nil || plan.Lifecycle == nil || *plan.Lifecycle != (kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}) || plan.Capability != nil || plan.MFACompletion != nil {
		return identity.ForbiddenError{}
	}
	if err := p.ValidatePasskeyMFAChallenge(c, *plan.MFAContinuation); err != nil {
		return err
	}
	if err := p.finalization.Validate(c, plan); err != nil {
		return err
	}
	if c == p.mfa.original {
		if plan.CapabilityIssuance != nil {
			return identity.ForbiddenError{}
		}
		return nil
	}
	metadata, err := p.mfa.prepared.Plan()
	if err != nil || plan.CapabilityIssuance == nil || !reflect.DeepEqual(metadata, *plan.CapabilityIssuance) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinInvocation) mfaPlan(generated bool) (kernel.CommandPlan, error) {
	b := p.binding()
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.mfa.primary.IssuedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation, "authentication_attempt", record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	scope, err := p.mfaScope()
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	contributors := p.mfa.registry.Descriptors()
	if !generated {
		contributors = contributors[:len(contributors)-1]
	}
	plan := kernel.CommandPlan{Contributors: contributors, SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "mfa.challenge.created.v1", AfterVersion: 1}, MFAContinuation: &scope, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
	if generated {
		metadata, err := p.mfa.prepared.Plan()
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		plan.CapabilityIssuance = &metadata
	}
	return plan, nil
}

func (p *signinInvocation) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.validateMFACommand(c, plan)
}
func (p *signinInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mfa == nil || c != p.mfa.original {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	return sessionpg.RequirePreAuth(ctx, w, p.service.config().Repository, p.flow)
}

func (p *signinInvocation) checkMFAChallenge(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p.mfa == nil || c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if err := p.mfa.continuation.RequirePending(now); err != nil {
		return err
	}
	if now.Before(p.mfa.primary.Authentication.Proof.IssuedAt) || !now.Before(p.mfa.primary.Authentication.Proof.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.service.config().Repository, p.flow); err != nil {
		return err
	}
	if err := p.context(ctx, w, false); err != nil {
		return err
	}
	return p.finalization.Check(ctx, w, p, c)
}

func (p *signinInvocation) applyMFAChallenge(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || p.mfa.outputGeneration == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest := sha256.Sum256(wire)
	clear(wire)
	if generation != p.mfa.outputGeneration || digest != p.mfa.outputDigest {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := sessionpg.RequirePreAuth(ctx, w, p.service.config().Repository, p.flow); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.context(ctx, w, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.finalization.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.PersistPasskeyContinuation(ctx, w, p, c, p.mfa.continuation); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.service.mfa.issuer.Stage(ctx, w, p.mfa.prepared); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET last_used_at=clock_timestamp() WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND version=$5 AND state='active'`, p.service.config().Profile.RPNamespace, string(p.user().TenantID), string(p.user().ID), string(p.reference.ID), p.reference.Version); err != nil || n != 1 {
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.operation, AfterVersion: 1}, nil
}

func (p *signinInvocation) recoverMFAChallenge(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return mfapg.RecoverPasskeyContinuation(ctx, w, p)
}
