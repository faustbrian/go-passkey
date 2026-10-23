package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	identityoutbox "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

type signinInvocation struct {
	*webauthnpg.Store
	service                                  *SigninService
	request                                  SigninRequest
	operation                                identity.FeatureOperation
	flow                                     session.PreAuthTransaction
	cookie                                   session.TokenDigest
	recipient                                kernel.RecipientRecord
	discoverable                             bool
	selectedUser                             identity.User
	selected                                 kernel.CredentialAdmission
	directory                                kernel.DirectoryAuthorityRecord
	factor, passkey, policy, protocolVersion uint64
	handle                                   []byte
	identifier                               string
	reference                                identity.CredentialRef
	risk                                     risk.AuthenticationAdmission
	creation                                 *webauthnpg.AssertionCreation
	finalization                             *webauthnpg.AssertionFinalization
	mutation                                 webauthn.AssertionMutation
	ceremonyID                               string
	command                                  identity.Command
	prepared                                 session.PreparedIssuance
	record                                   session.Session
	issuer                                   *session.SessionIssuer
	output                                   SigninResult
	result                                   identity.CommandResult
	applied                                  bool
}

func (*signinInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
}
func (p *signinInvocation) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation}
}
func (p *signinInvocation) ceremonyContext() webauthn.CeremonyContext {
	return webauthn.CeremonyContext{CommandID: p.request.CommandID, TenantID: p.service.config().Protocol.TenantID, AnonymousFlowID: string(p.request.FlowID), ActorID: p.service.config().Flow.ActorID, CorrelationID: p.request.CorrelationID}
}
func (p *signinInvocation) binding() identity.CommandBinding {
	c := p.service.config()
	actor, kind := c.Flow.ActorID, authorization.SubjectServiceAccount
	if p.finalization != nil {
		actor, kind = identity.ActorID(p.user().ID), authorization.SubjectUser
	}
	b := identity.CommandBinding{CommandID: p.request.CommandID, TenantID: c.Protocol.TenantID, ActorID: actor, ActorKind: kind, RecordID: string(p.request.CommandID), OperationID: p.operation.OperationID, SchemaID: p.operation.SchemaID, SchemaVersion: 1, PolicyID: c.Flow.PolicyID, PolicyVersion: c.Flow.PolicyVersion, CorrelationID: p.request.CorrelationID}
	if p.finalization != nil {
		b.UserID = p.user().ID
	} else {
		b.AnonymousFlowID = string(p.request.FlowID)
	}
	return b
}
func (p *signinInvocation) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	if p.creation != nil {
		return p.creation.Validate(c, plan)
	}
	if p.finalization != nil {
		return p.finalization.Validate(c, plan)
	}
	return identity.ForbiddenError{}
}
func (p *signinInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	creation, err := p.service.protocol.DiscoverableAssertionCreation(input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	p.creation = creation
	defer creation.Discard()
	fields, err := creation.Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	command, err := p.makeCommand(fields)
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
func (*signinInvocation) FinalizeRegistration(context.Context, webauthn.RegistrationTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
}

func (p *signinInvocation) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	mutation, err := input.Mutation()
	if err != nil || mutation.Context != p.ceremonyContext() {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	if p.discoverable {
		if err := p.selectDiscovered(ctx, mutation); err != nil {
			return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
		}
	}
	if mutation.Before.UserID != p.user().ID || mutation.Before.TenantID != p.user().TenantID || mutation.Before.Version != p.protocolVersion || !bytes.Equal(mutation.Before.UserHandle, p.handle) {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	final, err := p.service.protocol.DiscoverableAssertionFinalization(input)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.finalization, p.mutation = final, mutation
	p.issuer, err = session.NewPasskeySessionIssuerWithCSRF(p, p.service.config().Session, p.service.config().CSRF)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	spec, err := p.sessionSpec()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.prepared, err = p.issuer.PreparePasskey(p.binding(), spec)
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
	sessionFields, err := sessionpg.PasskeySigninSessionFields(p.record)
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	command, err := p.makeCommand(append(fields, sessionFields...))
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	p.prepared, err = p.issuer.BindPasskey(p.prepared, command)
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
	credential, err := final.Result(p.lastResult())
	return credential, p.output.Session.CommitOutcome, err
}

func (p *signinInvocation) lastResult() identity.CommandResult { return p.result }

func (p *signinInvocation) makeCommand(fields []identity.FeatureField) (identity.Command, error) {
	wire, err := p.contextWire()
	if err != nil {
		return identity.Command{}, err
	}
	digest := sha256.Sum256(wire)
	fields = append(fields, identity.FeatureField{Name: "passkey.signin.context", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}})
	riskFacts := p.risk.Prepared()
	fields = append(fields, identity.FeatureField{Name: "passkey.signin.risk", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(riskFacts.Signature[:])}})
	p.command, err = identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding(), Operation: p.operation, Fields: fields})
	return p.command, err
}

func (p *signinInvocation) ExecuteIssue(ctx context.Context, r session.IssueRequest) (session.IssueExecution, error) {
	command, record, ok := r.PasskeyCommand()
	if !ok || p.finalization == nil || p.command != command {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	expected, err := sessionpg.PasskeySigninSessionFields(p.record)
	if err != nil {
		return session.IssueExecution{}, err
	}
	actual, err := sessionpg.PasskeySigninSessionFields(record)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	mapped, err := sessionpg.PasskeySigninSession(command)
	if err != nil {
		return session.IssueExecution{}, err
	}
	actual, err = sessionpg.PasskeySigninSessionFields(mapped)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		return session.IssueExecution{}, identity.ForbiddenError{}
	}
	result, err := p.execute(ctx, command)
	p.result = result
	out := session.IssueExecution{Receipt: result, Replayed: result.Outcome == identity.CommitOutcomeCommitted && !p.applied}
	if result.Outcome == identity.CommitOutcomeCommitted {
		out.Session = p.record
	}
	return out, err
}
func (*signinInvocation) RecoverIssue(context.Context, session.IssueRequest) (session.IssueExecution, error) {
	return session.IssueExecution{}, identity.ForbiddenError{}
}

func (p *signinInvocation) sessionSpec() (session.SessionSpec, error) {
	c := p.service.config()
	b := p.binding()
	now := c.Clock.Now().UTC().Truncate(time.Microsecond)
	if !now.Before(p.mutation.Ceremony.ExpiresAt) {
		return session.SessionSpec{}, identity.ForbiddenError{}
	}
	family, err := identity.NewCommandID()
	if err != nil {
		return session.SessionSpec{}, err
	}
	keys, err := kernel.KernelAuthorityKeys(p.directory.Query, b.UserID)
	if err != nil {
		return session.SessionSpec{}, err
	}
	sk, err := sessionpg.SessionAuthorityKeys(b.TenantID, b.UserID, string(family), b.RecordID)
	if err != nil {
		return session.SessionSpec{}, err
	}
	pk, err := p.policyScope().Key()
	if err != nil {
		return session.SessionSpec{}, err
	}
	fk, err := mfapg.FactorAuthorityKey(b.TenantID, b.UserID)
	if err != nil {
		return session.SessionSpec{}, err
	}
	passkeyKey, err := PasskeyAuthorityKey(c.Profile.RPNamespace, b.TenantID, b.UserID)
	if err != nil {
		return session.SessionSpec{}, err
	}
	a := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	ua := p.userAuthority()
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keys.Global, p.directory.GlobalVersion), Tenant: a(keys.Tenant, p.directory.TenantVersion), User: a(keys.User, ua.UserAuthorityVersion), Identifier: a(keys.Identifier, ua.IdentifierAuthorityVersion), Credential: a(keys.Credential, ua.CredentialAuthorityVersion), Session: a(sk.Session, 1), SessionFamily: a(sk.Family, 1), Authorization: a(pk, p.policy), Factor: session.OptionalAuthorityBinding{Present: true, Binding: a(fk, p.factor)}, Passkey: session.OptionalAuthorityBinding{Present: true, Binding: a(passkeyKey, p.passkey)}})
	if err != nil {
		return session.SessionSpec{}, err
	}
	flow, _ := p.flow.Bindings()
	proof := auth.Proof{ID: auth.ProofID(b.CommandID), Tenant: string(b.TenantID), Subject: string(b.UserID), Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: "session-issue", Audience: c.Profile.Audience, IssuedAt: now, ExpiresAt: p.mutation.Ceremony.ExpiresAt}
	return session.SessionSpec{SessionID: b.RecordID, FamilyID: string(family), TenantID: b.TenantID, UserID: b.UserID, Audience: c.Profile.Audience, Version: 1, FamilyVersion: 1, Remember: flow.Binding.Intent.Remember, Authority: vector, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: string(p.reference.ID), CredentialVersion: p.reference.Version}, IssuedAt: now, LastActivityAt: now}, nil
}

func (p *signinInvocation) policyScope() policy.AuthorityScope {
	return policy.AuthorityScope{TenantID: authorization.TenantID(p.user().TenantID), PolicyNamespace: p.service.config().Profile.PolicyNamespace, SubjectID: authorization.SubjectID(p.user().ID)}
}

func (p *signinInvocation) execute(ctx context.Context, command identity.Command) (identity.CommandResult, error) {
	c := p.service.config()
	b := p.binding()
	resource := authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	if b.AnonymousFlowID != "" {
		resource = authorization.Resource{Type: "identity.preauth", ID: authorization.ResourceID(b.AnonymousFlowID)}
	}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(c.Flow.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Tenant: authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID), Resource: resource}}
	decision, err := c.Authorization.Decide(ctx, caller)
	if err != nil || decision.Outcome != authorization.Allow || uint64(decision.Revision) != b.PolicyVersion {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	coordinator, registry, err := p.runtime()
	if err != nil {
		return identity.CommandResult{}, err
	}
	plan, err := p.plan(coordinator, registry, command)
	if err != nil {
		return identity.CommandResult{}, err
	}
	reservation, result, err := coordinator.ReserveCommand(ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return result, err
	}
	if p.creation != nil {
		var now time.Time
		if err := p.service.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
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
	result, err = coordinator.ApplyFeature(ctx, w, command)
	if err != nil {
		return coordinator.Abort(w, err)
	}
	return coordinator.Commit(w, result)
}

func (p *signinInvocation) runtime() (*kernel.Coordinator, *kernel.ContributorRegistry, error) {
	a, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, nil, err
	}
	l, err := identityoutbox.NewContributor()
	if err != nil {
		return nil, nil, err
	}
	r, err := kernel.NewContributorRegistry([]kernel.Contributor{p.service.directory, a, l, p})
	if err != nil {
		return nil, nil, err
	}
	coordinator, err := kernel.NewCoordinator(p.service.pool, r, p.service.config().Coordinator)
	return coordinator, r, err
}

func (p *signinInvocation) plan(coordinator *kernel.Coordinator, registry *kernel.ContributorRegistry, command identity.Command) (kernel.CommandPlan, error) {
	b := p.binding()
	subject, life, kind := "passkey", "passkey.signin-options.created.v1", audit.ActorService
	if p.finalization != nil {
		subject, life, kind = "session", "session.created.v1", audit.ActorHuman
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: p.service.config().Clock.Now().UTC().Truncate(time.Microsecond), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subject, ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": subject, "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, p.operation, subject, record)
	if err != nil {
		return kernel.CommandPlan{}, err
	}
	return coordinator.PrepareCommandPlan(b, command, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: subject, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation}, Lifecycle: &kernel.LifecyclePlan{EventType: life, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}})
}

func (p *signinInvocation) current(ctx context.Context, w kernel.Work) error {
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: p.directory.Query, GlobalVersion: p.directory.GlobalVersion, TenantVersion: p.directory.TenantVersion}); err != nil {
		return err
	}
	if p.finalization != nil {
		if p.discoverable {
			if _, err := w.RequireActiveCredential(ctx, p, p.selected); err != nil {
				return err
			}
		} else {
			if err := w.RequireRecipient(ctx, p, p.recipient); err != nil {
				return err
			}
		}
		if err := w.RequireActiveUserAuthorization(ctx, p, kernel.UserAuthorizationAdmission{Scope: p.policyScope(), Version: p.policy}); err != nil {
			return err
		}
		if err := mfapg.RequirePasskeySessionFactors(ctx, w, p, p.record); err != nil {
			return err
		}
		if err := p.lockMapping(ctx, w); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	original, err := p.flow.Bindings()
	if err != nil {
		return err
	}
	if err := p.flow.Check(now, original.Binding, p.cookie); err != nil {
		return err
	}
	return p.risk.CheckAt(ctx, now)
}

func (p *signinInvocation) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.current(ctx, w); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.creation != nil {
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.config().Repository, p.flow); err != nil {
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
		use, err := p.preAuthUse(w)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := sessionpg.ReservePreAuth(ctx, w, p.service.config().Repository, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.finalization.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if _, err := p.service.effect.Apply(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := sessionpg.FinalizePreAuth(ctx, w, p.service.config().Repository, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if n, err := w.Exec(ctx, `UPDATE identity_passkey.credentials SET last_used_at=clock_timestamp() WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND version=$5 AND state='active'`, p.service.config().Profile.RPNamespace, string(p.user().TenantID), string(p.user().ID), string(p.reference.ID), p.reference.Version); err != nil || n != 1 {
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
	} else {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: p.operation, AfterVersion: 1}, nil
}

func (p *signinInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
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
		if err := sessionpg.RequirePreAuth(ctx, w, p.service.config().Repository, p.flow); err != nil {
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

func (p *signinInvocation) preAuthUse(w kernel.Work) (sessionpg.PreAuthUse, error) {
	b, fp, generation, err := w.FeatureCommandIdentity(p)
	return sessionpg.PreAuthUse{Command: b, Fingerprint: fp, Generation: generation}, err
}

func (p *signinInvocation) lockMapping(ctx context.Context, w kernel.Work) error {
	c := p.service.config()
	sql := `SELECT h.user_handle,h.authority_version::text FROM identity_passkey.relying_parties p JOIN identity_passkey.user_handles h USING(rp_namespace) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 FOR SHARE OF p,h`
	args := []any{c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.user().TenantID), string(p.user().ID)}
	if p.discoverable {
		sql = `SELECT h.user_handle,h.authority_version::text FROM identity_passkey.relying_parties p JOIN identity_passkey.user_handles h USING(rp_namespace) JOIN identity_passkey.credentials c USING(rp_namespace,tenant_id,user_id) WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 AND c.credential_id=$5 AND c.reference_id=$6 AND c.version=$7::numeric AND c.state='active' FOR SHARE OF p,h,c`
		args = append(args, p.mutation.Before.ID, string(p.reference.ID), strconv.FormatUint(p.reference.Version, 10))
	}
	rows, err := w.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var handle []byte
	var version string
	if rows.Scan(&handle, &version) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(handle, p.handle) || version != strconv.FormatUint(p.passkey, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}

type identifiedSigninContext struct {
	Flow, User, Identifier, Namespace, Global, Policy, Input                                                                                                            string
	GlobalVersion, TenantVersion, UserVersion, IdentifierVersion, CredentialVersion, FactorVersion, PasskeyVersion, PolicyVersion, IdentifierRecord, VerificationRecord uint64
}

func (p *signinInvocation) contextWire() ([]byte, error) {
	if p.discoverable {
		return p.discoverableContextWire(true)
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return nil, err
	}
	return json.Marshal(identifiedSigninContext{string(flow.Binding.ID), string(p.recipient.User.ID), string(p.recipient.Identifier.ID), p.service.config().Profile.RPNamespace, p.directory.Query.GlobalAuthorityID, p.service.config().Profile.PolicyNamespace, p.identifier, p.directory.GlobalVersion, p.directory.TenantVersion, p.recipient.UserAuthorityVersion, p.recipient.IdentifierAuthorityVersion, p.recipient.CredentialAuthorityVersion, p.factor, p.passkey, p.policy, p.recipient.Identifier.Version, p.recipient.Verification.Version})
}
func (p *signinInvocation) context(ctx context.Context, w kernel.Work, create bool) error {
	wire, err := p.contextWire()
	if p.discoverable {
		wire, err = p.discoverableContextWire(false)
	}
	if err != nil {
		return err
	}
	id := p.ceremonyID
	if p.creation != nil {
		id = string(p.request.CommandID)
	}
	user := p.recipient.User.ID
	if p.discoverable {
		user = ""
	}
	if create {
		n, err := w.Exec(ctx, `INSERT INTO identity_passkey.signin_contexts(rp_namespace,ceremony_id,tenant_id,user_id,admission) VALUES($1,$2,$3,NULLIF($4,''),$5)`, p.service.config().Profile.RPNamespace, id, string(p.service.config().Protocol.TenantID), string(user), wire)
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	rows, err := w.Query(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND COALESCE(user_id,'')=$4 FOR SHARE`, p.service.config().Profile.RPNamespace, id, string(p.service.config().Protocol.TenantID), string(user))
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		return identity.ForbiddenError{}
	}
	var original []byte
	if rows.Scan(&original) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(original, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *signinInvocation) readContext(ctx context.Context) error {
	if p.discoverable {
		wire, err := p.discoverableContextWire(false)
		if err != nil {
			return err
		}
		var original []byte
		if err := p.service.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id IS NULL`, p.service.config().Profile.RPNamespace, p.ceremonyID, string(p.service.config().Protocol.TenantID)).Scan(&original); err != nil || !bytes.Equal(original, wire) {
			return identity.ForbiddenError{}
		}
		return nil
	}
	wire, err := p.contextWire()
	if err != nil {
		return err
	}
	var original []byte
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, p.service.config().Profile.RPNamespace, p.ceremonyID, string(p.recipient.User.TenantID), string(p.recipient.User.ID)).Scan(&original); err != nil || !bytes.Equal(original, wire) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *signinInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.protocol.RecoverAssertion(ctx, w, p)
	if err != nil || status == kernel.RecoveryUnknown {
		return status, err
	}
	if p.operation == signinOperation(true) {
		sessions, err := p.service.effect.Recover(ctx, w, p)
		if err != nil || sessions != status {
			return kernel.RecoveryUnknown, err
		}
	}
	return status, nil
}
