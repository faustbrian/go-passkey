package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
	"github.com/jackc/pgx/v5"
)

type signupInvocation struct {
	*webauthnpg.Store
	service           *SignupService
	request           passkey.SignupRequest
	operation         identity.FeatureOperation
	flow              session.PreAuthTransaction
	cookie            session.TokenDigest
	directory         kernel.DirectoryAuthorityRecord
	user              identity.UserID
	handle            []byte
	credentialID      identity.CredentialID
	ceremonyID, label string
	risk              risk.ProtectedProviderAdmission
	counters          kernel.CommandCounterPlan
	creation          *webauthnpg.RegistrationCreation
	finalization      *webauthnpg.RegistrationFinalization
	mutation          webauthn.RegistrationMutation
	command           identity.Command
	prepared          session.PreparedIssuance
	record            session.Session
	issuer            *session.SessionIssuer
	output            passkey.SignupResult
	result            identity.CommandResult
	applied           bool
}

func (*signupInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (p *signupInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation}
}
func (p *signupInvocation) ceremonyContext() webauthn.CeremonyContext {
	c := p.service.core.config()
	return webauthn.CeremonyContext{CommandID: p.request.CommandID, TenantID: c.Protocol.TenantID, UserID: p.user, ActorID: c.Flow.ActorID, CorrelationID: p.request.CorrelationID}
}
func (p *signupInvocation) binding() identity.CommandBinding {
	c := p.service.core.config()
	record := string(p.request.CommandID)
	if p.finalization != nil {
		record = string(p.credentialID)
	}
	return identity.CommandBinding{CommandID: p.request.CommandID, TenantID: c.Protocol.TenantID, AnonymousFlowID: string(p.request.FlowID), ActorID: c.Flow.ActorID, ActorKind: authorization.SubjectServiceAccount, RecordID: record, OperationID: p.operation.OperationID, SchemaID: p.operation.SchemaID, SchemaVersion: 1, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion, CorrelationID: p.request.CorrelationID}
}
func (p *signupInvocation) prepareRisk(ctx context.Context) error {
	scope := risk.Context{Tenant: string(p.service.core.config().Protocol.TenantID), Operation: risk.Action(p.operation.OperationID), Attempt: string(p.request.CommandID)}
	result, err := p.service.evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return err
	}
	p.risk, err = p.service.risk.Prepare(ctx, result, scope)
	return err
}
func (p *signupInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.CommandCounters == nil || *plan.CommandCounters != p.counters {
		return identity.ForbiddenError{}
	}
	if err := p.service.counters.ValidateCommandCounters(c, p.counters); err != nil {
		return err
	}
	if p.creation != nil {
		return p.creation.Validate(c, plan)
	}
	if p.finalization == nil || plan.PasskeyRegistration == nil {
		return identity.ForbiddenError{}
	}
	if _, err := sessionpg.PasskeySignupSession(c); err != nil {
		return err
	}
	return p.finalization.Validate(c, plan)
}
func (p *signupInvocation) PasskeyRegistration(c identity.Command) (kernel.PasskeyRegistrationIntent, error) {
	if c != p.command || p.finalization == nil {
		return kernel.PasskeyRegistrationIntent{}, identity.ForbiddenError{}
	}
	return p.registrationIntent(), nil
}
func (p *signupInvocation) registrationIntent() kernel.PasskeyRegistrationIntent {
	b := p.binding()
	b.OperationID, b.UserID, b.AnonymousFlowID, b.RecordID = "identity.user.create", p.user, "", ""
	b.SchemaID, b.SchemaVersion = "passkey-signup-account-v1", 1
	return kernel.PasskeyRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}, Credential: identity.CredentialRef{ID: p.credentialID, TenantID: b.TenantID, UserID: p.user, Owner: "passkey", Kind: identity.CredentialPasskey, Version: 1}}
}
func (p *signupInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	creation, err := p.service.core.protocol.SignupRegistrationCreation(input, string(p.request.FlowID))
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	p.creation = creation
	defer creation.Discard()
	id, err := identity.NewSubjectID()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	p.credentialID = identity.CredentialID(id)
	fields, err := creation.Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	fields = append(fields, identity.FeatureField{Name: "registration.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.user)}})
	command, err := p.makeCommand(ctx, fields)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, command)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, err
	}
	record, challenge, err := creation.Result(result)
	return record, challenge, result.Outcome, err
}
func (p *signupInvocation) FinalizeRegistration(ctx context.Context, input webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, err := input.Mutation()
	if err != nil || m.Context != p.ceremonyContext() || m.Credential.UserID != p.user || !bytes.Equal(m.Credential.UserHandle, p.handle) {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	final, err := p.service.core.protocol.SignupRegistrationFinalization(input, string(p.request.FlowID))
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.finalization, p.mutation = final, m
	p.issuer, err = session.NewPasskeySignupSessionIssuerWithCSRF(p, p.service.core.config().Session, p.service.core.config().CSRF)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	spec, err := p.sessionSpec()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.prepared, err = p.issuer.PreparePasskeySignup(p.binding(), spec)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	var ok bool
	p.record, ok = p.prepared.Session()
	if !ok {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	fields, err := final.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	creationFields, err := kernel.PasskeyRegistrationFields(p.registrationIntent())
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	sessionFields, err := sessionpg.PasskeySignupSessionFields(p.record)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	command, err := p.makeCommand(ctx, append(append(fields, creationFields...), sessionFields...))
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.prepared, err = p.issuer.BindPasskeySignup(p.prepared, command)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.output.Session, err = p.issuer.Issue(ctx, p.prepared)
	if err != nil {
		return webauthn.Credential{}, p.output.Session.CommitOutcome, err
	}
	if p.output.Session.CommitOutcome != identity.CommitOutcomeCommitted || p.output.Session.Replayed {
		return webauthn.Credential{}, p.output.Session.CommitOutcome, identity.ForbiddenError{}
	}
	p.output.CSRF, err = p.prepared.CSRFToken()
	if err != nil {
		return webauthn.Credential{}, p.output.Session.CommitOutcome, err
	}
	credential, err := final.Result(p.result)
	return credential, p.output.Session.CommitOutcome, err
}
func (*signupInvocation) FinalizeAssertion(context.Context, webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
}
func (p *signupInvocation) makeCommand(ctx context.Context, fields []identity.FeatureField) (identity.Command, error) {
	wire, err := p.contextWire()
	if err != nil {
		return identity.Command{}, err
	}
	hash := sha256.Sum256(wire)
	fields = append(fields, identity.FeatureField{Name: "passkey.signup.context", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: hash[:]}}, identity.FeatureField{Name: "passkey.signup.label", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.label}})
	riskFacts := p.risk.Prepared()
	fields = append(fields, identity.FeatureField{Name: "passkey.signup.risk", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(riskFacts.Signature[:])}})
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: p.operation, Fields: fields})
	if err != nil {
		return identity.Command{}, err
	}
	var now time.Time
	if err := p.service.core.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return identity.Command{}, identity.UnavailableError{}
	}
	p.command, p.counters, err = p.service.counters.PreparePasskeySignupCommandCounters(command, risk.Subject{Network: p.request.Network, Device: p.request.Device}, now.UTC())
	return p.command, err
}
func (p *signupInvocation) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	c, record, ok := r.PasskeySignupCommand()
	if !ok || c != p.command || p.finalization == nil {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	expected, err := sessionpg.PasskeySignupSessionFields(p.record)
	if err != nil {
		return session.IssueExecution{}, err
	}
	actual, err := sessionpg.PasskeySignupSessionFields(record)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	mapped, err := sessionpg.PasskeySignupSession(c)
	if err != nil {
		return session.IssueExecution{}, err
	}
	actual, err = sessionpg.PasskeySignupSessionFields(mapped)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	p.result, err = p.execute(ctx, c)
	out := session.IssueExecution{Receipt: p.result, Replayed: p.result.Outcome == identity.CommitOutcomeCommitted && !p.applied}
	if p.result.Outcome == identity.CommitOutcomeCommitted {
		out.Session = p.record
	}
	return out, err
}
func (*signupInvocation) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

func (p *signupInvocation) sessionSpec() (session.SessionSpec, error) {
	c := p.service.core.config()
	now := c.Clock.Now().UTC().Truncate(time.Microsecond)
	if !now.Before(p.mutation.Ceremony.ExpiresAt) {
		return session.SessionSpec{}, identity.ForbiddenError{}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return session.SessionSpec{}, err
	}
	family, err := identity.NewCommandID()
	if err != nil {
		return session.SessionSpec{}, err
	}
	k, err := kernel.KernelAuthorityKeys(p.directory.Query, p.user)
	if err != nil {
		return session.SessionSpec{}, err
	}
	sk, err := sessionpg.SessionAuthorityKeys(c.Protocol.TenantID, p.user, string(family), string(id))
	if err != nil {
		return session.SessionSpec{}, err
	}
	pk, err := p.policyScope().Key()
	if err != nil {
		return session.SessionSpec{}, err
	}
	fk, err := mfapg.FactorAuthorityKey(c.Protocol.TenantID, p.user)
	if err != nil {
		return session.SessionSpec{}, err
	}
	passkeyKey, err := PasskeyAuthorityKey(c.Profile.RPNamespace, c.Protocol.TenantID, p.user)
	if err != nil {
		return session.SessionSpec{}, err
	}
	a := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(k.Global, p.directory.GlobalVersion), Tenant: a(k.Tenant, p.directory.TenantVersion), User: a(k.User, 1), Identifier: a(k.Identifier, 1), Credential: a(k.Credential, 1), Session: a(sk.Session, 1), SessionFamily: a(sk.Family, 1), Authorization: a(pk, 1), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(fk, 1)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: a(passkeyKey, 1)}})
	if err != nil {
		return session.SessionSpec{}, err
	}
	flow, _ := p.flow.Bindings()
	proof := auth.Proof{ID: auth.ProofID(p.request.CommandID), Tenant: string(c.Protocol.TenantID), Subject: string(p.user), Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: "session-issue", Audience: c.Profile.Audience, IssuedAt: now, ExpiresAt: p.mutation.Ceremony.ExpiresAt}
	return session.SessionSpec{SessionID: string(id), FamilyID: string(family), TenantID: c.Protocol.TenantID, UserID: p.user, Audience: c.Profile.Audience, Version: 1, FamilyVersion: 1, Remember: flow.Binding.Intent.Remember, Authority: vector, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: string(p.credentialID), CredentialVersion: 1}, IssuedAt: now, LastActivityAt: now}, nil
}
func (p *signupInvocation) policyScope() policy.AuthorityScope {
	c := p.service.core.config()
	return policy.AuthorityScope{TenantID: authorization.TenantID(c.Protocol.TenantID), PolicyNamespace: c.Profile.PolicyNamespace, SubjectID: authorization.SubjectID(p.user)}
}

func (p *signupInvocation) runtime() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{p.service.core.directory, a, l, p.service.counters, p})
	if err != nil {
		return nil, nil, err
	}
	c, err := kernel.NewCoordinator(p.service.core.pool, r, p.service.core.config().Coordinator)
	return c, r, err
}
func (p *signupInvocation) execute(ctx context.Context, c identity.Command) (identity.CommandResult, error) {
	config := p.service.core.config()
	b := p.binding()
	decision, err := config.Authorization.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.preauth", ID: authorization.ResourceID(b.AnonymousFlowID)}}})
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	coordinator, registry, err := p.runtime()
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := p.plan(coordinator, registry, c)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, c, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.creation != nil {
		var now time.Time
		if err := p.service.core.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, identity.UnavailableError{}
		}
		if err := p.creation.Generate(ctx, now.UTC()); err != nil {
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
		}
	}
	w, err := coordinator.Begin(ctx, reservation)
	if err != nil {
		return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown}, err
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	result, err = coordinator.ApplyFeature(ctx, w, c)
	if err != nil {
		return coordinator.Abort(w, err)
	}
	return coordinator.Commit(w, result)
}
func (p *signupInvocation) plan(coordinator *kernel.Coordinator, r *kernel.ContributorRegistry, c identity.Command) (kernel.CommandPlan, error) {
	b := p.binding()
	subject, event := "passkey", "passkey.registration-options.created.v1"
	if p.finalization != nil {
		subject, event = "credential", "identity.passkey.create_credential"
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	seed, err := builder.Build(audit.RecordInput{OccurredAt: p.service.core.config().Clock.Now().UTC().Truncate(time.Microsecond), Action: event, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation, subject, seed)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	plan := kernel.CommandPlan{Contributors: r.Descriptors(), Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation}, SubjectType: subject, Lifecycle: &kernel.LifecyclePlan{EventType: event, AfterVersion: 1}, CommandCounters: &p.counters, Audits: []kernel.AuditPlan{{EventType: event, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionClass: "protected", RetentionPolicyVersion: 1, BindingDigest: digest}}}
	if p.finalization != nil {
		d, err := kernel.PasskeyRegistrationDigest(p.registrationIntent())
		if err != nil {
			return kernel.CommandPlan{}, err
		}
		plan.PasskeyRegistration = &kernel.PasskeyRegistrationPlan{UserID: p.user, CredentialID: p.credentialID, CreationDigest: d, CreationEventIndex: 1}
	}
	return coordinator.PrepareCommandPlan(b, c, plan)
}

func (p *signupInvocation) current(ctx context.Context, w kernel.Work) error {
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: p.directory.Query, GlobalVersion: p.directory.GlobalVersion, TenantVersion: p.directory.TenantVersion}); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	f, err := p.flow.Bindings()
	if err != nil {
		return err
	}
	if err := p.flow.Check(now, f.Binding, p.cookie); err != nil {
		return err
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *signupInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	return sessionpg.RequirePreAuth(ctx, w, p.service.core.config().Repository, p.flow)
}
func (p *signupInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.creation != nil {
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.core.config().Repository, p.flow); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.creation.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.context(ctx, w, true); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else if p.finalization != nil {
		if err := p.context(ctx, w, false); err != nil {
			return identity.FeatureReceipt{}, err
		}
		b, fp, generation, err := w.FeatureCommandIdentity(p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		use := sessionpg.PreAuthUse{Command: b, Fingerprint: fp, Generation: generation}
		if err := sessionpg.ReservePreAuth(ctx, w, p.service.core.config().Repository, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := p.service.domain.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.finalization.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := mfapg.InitializePasskeySignup(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := policy.InitializeAuthority(ctx, w, p.policyScope(), p.service.core.config().Protocol.MaximumDuration); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.insertMapping(ctx, w); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := p.service.effect.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := sessionpg.FinalizePreAuth(ctx, w, p.service.core.config().Repository, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.operation, AfterVersion: 1}, nil
}
func (p *signupInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return err
	}
	if err := p.context(ctx, w, false); err != nil {
		return err
	}
	if p.creation != nil {
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.core.config().Repository, p.flow); err != nil {
			return err
		}
		return p.creation.Check(ctx, w, p, c)
	}
	if p.finalization == nil {
		return identity.ForbiddenError{}
	}
	if err := p.finalization.Check(ctx, w, p, c); err != nil {
		return err
	}
	return p.service.effect.Check(ctx, w, p, c)
}
func (p *signupInvocation) insertMapping(ctx context.Context, w kernel.Work) error {
	c := p.service.core.config()
	if _, err := w.Exec(ctx, `INSERT INTO identity_passkey.relying_parties(rp_namespace,rp_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID); err != nil {
		return err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity_passkey.user_handles(rp_namespace,tenant_id,user_id,user_handle,authority_version) VALUES($1,$2,$3,$4,1)`, c.Profile.RPNamespace, string(c.Protocol.TenantID), string(p.user), p.handle); err != nil {
		return err
	}
	var label any
	if p.label != "" {
		label = p.label
	}
	_, err := w.Exec(ctx, `INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,display_label,created_at) VALUES($1,$2,$3,$4,$5,1,'active',$6,clock_timestamp())`, c.Profile.RPNamespace, string(c.Protocol.TenantID), string(p.user), string(p.credentialID), p.mutation.Credential.ID, label)
	return err
}
func (p *signupInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.core.protocol.RecoverRegistration(ctx, w, p)
	if err != nil || status == kernel.RecoveryUnknown {
		return status, err
	}
	if p.operation == signupOperation(true) {
		sessions, err := p.service.effect.Recover(ctx, w, p)
		if err != nil || sessions != status {
			return kernel.RecoveryUnknown, err
		}
	}
	return status, nil
}

type signupContext struct {
	Profile, Flow, User, Credential, Namespace, RP, Actor, Global, Policy string
	Handle                                                                []byte
	GlobalVersion, TenantVersion, PolicyVersion                           uint64
}

func (p *signupInvocation) contextWire() ([]byte, error) {
	c := p.service.core.config()
	return json.Marshal(signupContext{"passkey-signup-context-v1", string(p.request.FlowID), string(p.user), string(p.credentialID), c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(c.Flow.ActorID), c.Profile.GlobalAuthorityID, c.Profile.PolicyNamespace, bytes.Clone(p.handle), p.directory.GlobalVersion, p.directory.TenantVersion, c.Flow.PolicyVersion})
}
func (p *signupInvocation) readContext(ctx context.Context) error {
	c := p.service.core.config()
	var wire []byte
	err := p.service.core.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signup_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3`, c.Profile.RPNamespace, p.ceremonyID, string(c.Protocol.TenantID)).Scan(&wire)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.ForbiddenError{}
		}
		return identity.UnavailableError{}
	}
	original, err := decodeSignupContext(wire)
	if err != nil {
		return err
	}
	p.user, p.credentialID, p.handle = identity.UserID(original.User), identity.CredentialID(original.Credential), bytes.Clone(original.Handle)
	expected, err := p.contextWire()
	if err != nil || !bytes.Equal(wire, expected) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *signupInvocation) context(ctx context.Context, w kernel.Work, create bool) error {
	c := p.service.core.config()
	id := p.ceremonyID
	if p.creation != nil {
		id = string(p.request.CommandID)
	}
	wire, err := p.contextWire()
	if err != nil {
		return err
	}
	if create {
		if _, err := w.Exec(ctx, `INSERT INTO identity_passkey.signup_contexts(rp_namespace,ceremony_id,tenant_id,admission) VALUES($1,$2,$3,$4)`, c.Profile.RPNamespace, id, string(c.Protocol.TenantID), wire); err != nil {
			return err
		}
	}
	rows, err := w.Query(ctx, `SELECT admission FROM identity_passkey.signup_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 FOR SHARE`, c.Profile.RPNamespace, id, string(c.Protocol.TenantID))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var actual []byte
	if rows.Scan(&actual) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(actual, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}
