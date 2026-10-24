package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// SessionEnrollmentConfig selects the same concrete current-session transport,
// CSRF, protocol, policy and risk owners as session management. It enables only
// the explicit service constructed from it, never an HTTP route or password
// proof fallback. Install the selected histories, including WebAuthn migration5.
type SessionEnrollmentConfig = SessionManagementConfig

// SessionEnrollmentService adds resident UV credentials using a genuine fresh
// assertion from the current passkey session. Dependencies are borrowed and
// invocation participants are private; no goroutines, alternate proof store,
// resource lifetime or transaction owner is introduced.
type SessionEnrollmentService struct{ owner *SessionManagementService }

// NewSessionEnrollmentService freezes actual native owners without IO. The pool
// must outlive calls. Configuration cannot supply substitute domain stores or
// completed proofs; A and B use distinct keys and C retains its own command ID.
func NewSessionEnrollmentService(pool *database.Pool, c SessionEnrollmentConfig) (*SessionEnrollmentService, error) {
	if c.Protocol.Algorithms != nil && (len(c.Protocol.Algorithms) != 1 || c.Protocol.Algorithms[0] != webauthn.ES256) {
		return nil, identity.InvalidInputError{Field: "passkey_enrollment_algorithms"}
	}
	owner, err := NewSessionManagementService(pool, c)
	if err != nil {
		return nil, err
	}
	s := &SessionEnrollmentService{owner: owner}
	if _, _, err := s.runtime(&sessionEnrollmentInvocation{service: s}); err != nil {
		return nil, err
	}
	return s, nil
}

// Format excludes borrowed configuration and deployment correlation.
func (SessionEnrollmentService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeypostgres.SessionEnrollmentService(redacted)"))
}

// MarshalJSON rejects implicit owner export.
func (SessionEnrollmentService) MarshalJSON() ([]byte, error) { return nil, passkey.ErrPrivateValue }

// MarshalText rejects implicit owner export.
func (SessionEnrollmentService) MarshalText() ([]byte, error) { return nil, passkey.ErrPrivateValue }

func sessionEnrollmentOperation(stage int) identity.FeatureOperation {
	id, schema := "identity.passkey.register-options", "identity.passkey.register-options.session-assertion-options-v1"
	if stage == 1 {
		schema = "identity.passkey.register-options.session-registration-options-v1"
	} else if stage == 2 {
		id, schema = "identity.passkey.register-verify", "identity.passkey.register-verify.session-registration-v1"
	}
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// The existing native ceremony-context table stores only this commitment and
// original protocol version/expiry metadata. It is not a proof, replay journal
// or session authority. Protocol rows retain the genuine authorization lineage.
type sessionEnrollmentContext struct {
	Stage                 int
	Digest, RequestDigest [32]byte
	AuthenticationVersion uint64
	Parent                string
	AuthorizationExpires  time.Time
}

func (s *SessionEnrollmentService) prepare(ctx context.Context, custody passkey.SessionEnrollmentRequest, key identity.IdempotencyKey, id identity.CommandID, stage int, ceremony string, response []byte) (*sessionEnrollmentInvocation, passkey.SessionEnrollmentResultSpec, error) {
	var out passkey.SessionEnrollmentResultSpec
	if ctx == nil || s == nil || s.owner == nil || stage < 0 || stage > 2 {
		return nil, out, identity.InvalidInputError{Field: "passkey_session_enrollment"}
	}
	r, err := custody.Bindings()
	if err != nil || len(r.Network) == 0 || len(r.Network) > 128 || len(r.Origin) == 0 || len(r.Origin) > 2048 || len(response) > 262144 || stage < 2 && key == (identity.IdempotencyKey{}) || stage == 2 && key != (identity.IdempotencyKey{}) {
		return nil, out, identity.InvalidInputError{Field: "passkey_session_enrollment"}
	}
	if r.Label != "" {
		if _, err := passkey.NewDeviceLabel(r.Label); err != nil {
			return nil, out, err
		}
	}
	c := s.owner.config()
	if !slices.Contains(c.Protocol.RelyingParty.Origins, r.Origin) {
		return nil, out, identity.ForbiddenError{}
	}
	if stage > 0 {
		if _, err := identity.ParseCommandID(ceremony); err != nil || len(response) == 0 {
			return nil, out, identity.InvalidInputError{Field: "passkey_enrollment_response"}
		}
	}
	if stage == 2 {
		if _, err := identity.ParseCommandID(string(id)); err != nil || string(id) == ceremony {
			return nil, out, identity.InvalidInputError{Field: "passkey_enrollment_command"}
		}
	}
	op := sessionEnrollmentOperation(stage)
	read, record, err := s.owner.authenticateAction(ctx, passkey.SessionUpdateRequest{Credential: r.Credential, CSRFToken: r.CSRFToken, Caller: r.Caller}, op.OperationID)
	if err != nil {
		return nil, out, err
	}
	p := &sessionEnrollmentInvocation{service: s, request: r, read: read, record: record, stage: stage, id: id, ceremonyID: ceremony}
	coordinator, _, err := s.runtime(p)
	if err != nil {
		return nil, out, err
	}
	fields, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return nil, out, err
	}
	digest, err := r.Credential.Digest(c.OptionsRequests.state().token, string(record.TenantID))
	if err != nil {
		return nil, out, err
	}
	fields = append(fields, optionsBytes("enrollment.session", digest.Sum[:]), optionsUint("enrollment.session-key", uint64(digest.KeyVersion)), optionsUint("enrollment.stage", uint64(stage)), optionsText("enrollment.label", r.Label), optionsText("enrollment.origin", r.Origin), optionsText("enrollment.network", r.Network))
	if c.Transport == session.CredentialCookie {
		csrf, err := r.CSRFToken.Digest(c.OptionsRequests.state().csrf, session.CSRFBinding{TenantID: record.TenantID, SessionID: record.SessionID, SessionVersion: record.Version})
		if err != nil {
			return nil, out, err
		}
		bound, err := csrf.Bindings()
		if err != nil {
			return nil, out, err
		}
		fields = append(fields, optionsBytes("enrollment.csrf", bound.Digest[:]), optionsUint("enrollment.csrf-key", uint64(bound.KeyVersion)))
	}
	if stage > 0 {
		hash := sha256.Sum256(response)
		fields = append(fields, optionsText("enrollment.ceremony", ceremony), optionsBytes("enrollment.response", hash[:]))
	}
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return nil, out, err
	}
	// One canonical typed serialization retains exact native request correlation,
	// without persisting bearer/CSRF/response bytes or inventing another authority.
	wire, err := json.Marshal(fields)
	if err != nil {
		return nil, out, identity.UnavailableError{}
	}
	p.requestDigest = sha256.Sum256(wire)
	clear(wire)
	if stage < 2 {
		scope := kernel.RequestKeyScope{TenantID: record.TenantID, ActorID: identity.ActorID(record.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: op.OperationID}
		admitted, err := coordinator.ResolveRequestKey(ctx, scope, key, intent, optionsRequestCaller(r.Caller, scope, c.OptionsRequests.state().request.Policy.PolicyVersion))
		if err != nil {
			return nil, out, err
		}
		p.id = admitted.CommandID
	}
	out.CommandID = p.id
	query := identity.RecoveryQuery{CommandID: p.id, TenantID: record.TenantID, UserID: record.UserID, ActorID: identity.ActorID(record.UserID), ActorKind: authorization.SubjectUser, RecordID: string(p.id), OperationID: op.OperationID}
	out.Receipt, out.Replayed, err = optionsMetadata(ctx, coordinator, query, r.Caller)
	out.Outcome = out.Receipt.Outcome
	if err != nil || out.Replayed {
		// Keyed phases already matched exact intent. A non-keyed committed C
		// retry must also match its native context committed in the same Work.
		// Pending/failed observations reveal only classified durability, not a
		// successful match, new credential, challenge or permission to retry IO.
		if stage == 2 && out.Outcome == identity.CommitOutcomeCommitted {
			retained, e := p.loadContext(ctx, string(p.id))
			if e != nil || retained.Stage != stage || retained.RequestDigest != p.requestDigest || retained.Parent != ceremony {
				return p, passkey.SessionEnrollmentResultSpec{CommandID: p.id}, identity.ConflictError{}
			}
		}
		return p, out, err
	}
	if err := p.prepareOriginal(ctx); err != nil {
		return p, out, err
	}
	return p, out, nil
}

func (p *sessionEnrollmentInvocation) loadContext(ctx context.Context, id string) (sessionEnrollmentContext, error) {
	var out sessionEnrollmentContext
	var wire []byte
	c := p.service.owner.config()
	err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, c.Profile.RPNamespace, id, string(p.record.TenantID), string(p.record.UserID)).Scan(&wire)
	if err != nil || len(wire) == 0 || len(wire) > 4096 {
		return out, identity.ForbiddenError{}
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Stage < 0 || out.Stage > 2 || out.Digest == ([32]byte{}) || out.RequestDigest == ([32]byte{}) || out.AuthenticationVersion == 0 {
		return sessionEnrollmentContext{}, identity.ForbiddenError{}
	}
	return out, nil
}

func (p *sessionEnrollmentInvocation) prepareOriginal(ctx context.Context) error {
	c := p.service.owner.config()
	p.sourceFields, _ = sessionpg.OriginalSessionFields(p.read.Session)
	if len(p.sourceFields) == 0 {
		return identity.ForbiddenError{}
	}
	var id []byte
	if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND state='active' AND version=$5`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, p.record.Authentication.CredentialVersion).Scan(&id); err != nil {
		return identity.ForbiddenError{}
	}
	lookup := webauthn.Lookup{Context: p.protocolContext(), RPID: c.Protocol.RelyingParty.ID}
	if p.stage == 1 {
		lookup.CeremonyID = p.ceremonyID
	}
	var err error
	p.authProtocol, err = p.service.owner.protocol.LoadCredential(ctx, lookup, id)
	if err != nil || p.authProtocol.Version == 0 || p.authProtocol.TenantID != p.record.TenantID || p.authProtocol.UserID != p.record.UserID || p.authProtocol.RPID != c.Protocol.RelyingParty.ID || len(p.authProtocol.UserHandle) != 32 {
		return identity.ForbiddenError{}
	}
	profile, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(struct {
		Source, Profile        []identity.FeatureField
		Label, Origin, Network string
		ID, Handle             []byte
	}{p.sourceFields, profile, p.request.Label, p.request.Origin, p.request.Network, p.authProtocol.ID, p.authProtocol.UserHandle})
	if err != nil || len(wire) > 131072 {
		return identity.ForbiddenError{}
	}
	defer clear(wire)
	p.contextDigest = sha256.Sum256(append([]byte("golib.passkey.session-enrollment.context.v1\x00"), wire...))
	if p.stage > 0 {
		p.parent, err = p.loadContext(ctx, p.ceremonyID)
		if err != nil || p.parent.Stage != p.stage-1 || p.parent.Digest != p.contextDigest || p.stage == 1 && p.parent.AuthenticationVersion != p.authProtocol.Version {
			return identity.ForbiddenError{}
		}
		if p.stage == 2 {
			p.ceiling = p.parent.AuthorizationExpires
			if _, err := identity.ParseCommandID(p.parent.Parent); err != nil || p.ceiling.IsZero() {
				return identity.ForbiddenError{}
			}
		}
	}
	return p.read.ValidateAt(c.Clock.Now().UTC())
}

// EnrollmentAssertionOptions creates genuine identified UV options only under
// the current self-user session. A matching original key reveals metadata only.
func (s *SessionEnrollmentService) EnrollmentAssertionOptions(ctx context.Context, r passkey.SessionEnrollmentOptionsRequest) (out passkey.KeyedAssertionOptionsResult, err error) {
	if ctx == nil || s == nil || s.owner == nil {
		return out, identity.InvalidInputError{Field: "passkey_session_enrollment"}
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	p, observed, err := s.prepare(ctx, r.SessionEnrollmentRequest, r.IdempotencyKey, "", 0, "", nil)
	out.CommandID, out.Receipt, out.Replayed = observed.CommandID, observed.Receipt, observed.Replayed
	if err != nil || observed.Replayed {
		return out, err
	}
	protocol, err := webauthn.New(s.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, err
	}
	out.Options, err = protocol.BeginAssertion(ctx, webauthn.BeginAssertionRequest{Context: p.protocolContext(), UserHandle: p.authProtocol.UserHandle, Origin: p.request.Origin, AllowedCredentials: [][]byte{p.authProtocol.ID}})
	out.Receipt = p.result
	if err == nil {
		err = p.read.ValidateAt(s.owner.config().Clock.Now().UTC())
		if err != nil {
			out.Options = webauthn.AssertionOptions{}
		}
	}
	return out, err
}

// RegistrationOptions verifies the genuine A assertion and creates original
// resident registration options in the same B transaction. No reusable proof or
// session is issued. Retries retain original durability and never reveal options.
func (s *SessionEnrollmentService) RegistrationOptions(ctx context.Context, custody passkey.SessionEnrollmentAuthorization) (out passkey.KeyedRegistrationOptionsResult, err error) {
	out, _, err = s.RegistrationOptionsForDelivery(ctx, custody)
	return out, err
}

// RegistrationOptionsForDelivery performs the same B operation as
// RegistrationOptions and additionally returns A's genuine original absolute
// authorization expiry for a bounded consumer's final options-delivery check.
// This immutable ceiling is not proof, current-validity evidence or an extension
// of B's protocol TTL. Check it after synchronous hooks alongside actual session
// and request validity. Only fresh acknowledged options include a nonzero value;
// metadata-only retries and all errors return zero and reveal no options.
func (s *SessionEnrollmentService) RegistrationOptionsForDelivery(ctx context.Context, custody passkey.SessionEnrollmentAuthorization) (out passkey.KeyedRegistrationOptionsResult, authorizationExpiry time.Time, err error) {
	if ctx == nil || s == nil || s.owner == nil {
		return out, authorizationExpiry, identity.InvalidInputError{Field: "passkey_session_enrollment"}
	}
	r, err := custody.Bindings()
	if err != nil {
		return out, authorizationExpiry, err
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	p, observed, err := s.prepare(ctx, r.SessionEnrollmentRequest, r.IdempotencyKey, "", 1, r.CeremonyID, r.Response)
	out.CommandID, out.Receipt, out.Replayed = observed.CommandID, observed.Receipt, observed.Replayed
	if err != nil || observed.Replayed {
		return out, authorizationExpiry, err
	}
	protocol, err := webauthn.New(s.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, authorizationExpiry, err
	}
	_, err = protocol.VerifyAssertion(ctx, webauthn.VerifyAssertionRequest{Context: p.protocolContext(), CeremonyID: r.CeremonyID, Origin: p.request.Origin, Response: r.Response, ExpectedVersion: 1, ExpectedCredentialVersion: p.authProtocol.Version})
	out.Receipt = p.result
	if err == nil {
		now := s.owner.config().Clock.Now().UTC()
		err = p.read.ValidateAt(now)
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && !now.Before(p.ceiling) {
			err = identity.ForbiddenError{}
		}
		if err == nil {
			out.Options = p.registrationOptions
			authorizationExpiry = p.ceiling
		}
	}
	return out, authorizationExpiry, err
}

// Register consumes the genuine authorized B registration atomically with its
// initial kernel reference, mapping/label and required lifecycle. It retains C's
// original command identity (no retry key), never issues a session and returns
// only metadata for a matching historical completion.
func (s *SessionEnrollmentService) Register(ctx context.Context, custody passkey.SessionEnrollmentCompletion) (out passkey.SessionEnrollmentResult, err error) {
	var result passkey.SessionEnrollmentResultSpec
	defer func() { out = passkey.NewSessionEnrollmentResult(result) }()
	if ctx == nil || s == nil || s.owner == nil {
		return out, identity.InvalidInputError{Field: "passkey_session_enrollment"}
	}
	r, err := custody.Bindings()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, s.owner.config().Protocol.MaximumDuration)
	defer stop()
	p, observed, err := s.prepare(ctx, r.SessionEnrollmentRequest, identity.IdempotencyKey{}, r.CommandID, 2, r.CeremonyID, r.Response)
	result = observed
	if err != nil || observed.Replayed {
		return out, err
	}
	protocol, err := webauthn.New(s.owner.config().Protocol, webauthn.Dependencies{Store: p})
	if err != nil {
		return out, err
	}
	_, err = protocol.VerifyRegistration(ctx, webauthn.VerifyRegistrationRequest{Context: p.protocolContext(), CeremonyID: r.CeremonyID, Origin: p.request.Origin, Response: r.Response, ExpectedVersion: 1})
	result.Receipt, result.Outcome = p.result, p.result.Outcome
	if err != nil {
		return out, err
	}
	if err := p.read.ValidateAt(s.owner.config().Clock.Now().UTC()); err != nil || ctx.Err() != nil {
		return out, identity.UnavailableError{}
	}
	metadata := p.metadata
	result.Credential = &metadata
	return out, nil
}
