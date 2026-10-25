package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// PasskeyAuthorityKey derives the version-one RP/tenant/user mapping scope from
// exact canonical IDs. It is not authentication or current validity. The owned
// format is passkey:v1: plus unpadded base64url SHA-256 over the domain below and
// three big-endian uint16 length-prefixed IDs. Tenant never disambiguates RP-wide
// credential/handle uniqueness; it remains mandatory authorization scope here.
func PasskeyAuthorityKey(namespace string, tenant identity.TenantID, user identity.UserID) (string, error) {
	ids := []string{namespace, string(tenant), string(user)}
	for _, id := range ids {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return "", identity.InvalidInputError{Field: "passkey_authority"}
		}
	}
	h := sha256.New()
	_, _ = h.Write([]byte("golib.identity.passkey.authority.v1\x00"))
	for _, id := range ids {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(id)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(id))
	}
	return "passkey:v1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// SessionAuthorityConfig fixes one trusted tenant/RP namespace and protocol RP
// ID. Requests cannot select these values. MaximumDuration is 1ms..5s, bounded
// by the caller's earlier deadline. Install kernel, MFA and passkey histories
// first; construction neither installs nor initializes missing authority.
type SessionAuthorityConfig struct {
	TenantID        identity.TenantID
	RPNamespace     string
	RPID            string
	MaximumDuration time.Duration
}

// Format hides deployment/identity correlation in ordinary diagnostics.
func (SessionAuthorityConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SessionAuthorityConfig(redacted)"))
}

// SessionAuthority is the concrete passkey/MFA port for native session reads,
// issuance and revocation. It checks existing primary mappings; it cannot
// authenticate assertions, issue sessions, initialize factors or adopt newer
// epochs. Pool lifetime is borrowed; concurrent independent calls are supported.
// No resource, transaction, callback or goroutine is owned.
type SessionAuthority struct {
	pool   *database.Pool
	config func() SessionAuthorityConfig
}

var _ sessionpg.PasskeySessionAuthority = (*SessionAuthority)(nil)
var _ sessionpg.MFAPasskeySessionAuthority = (*SessionAuthority)(nil)

// NewSessionAuthority freezes trusted configuration without IO. The same owned
// instance/profile must be selected by session issuance, read and revocation.
func NewSessionAuthority(pool *database.Pool, c SessionAuthorityConfig) (*SessionAuthority, error) {
	_, tenantErr := identity.ParseIdentifierID(string(c.TenantID))
	_, namespaceErr := identity.ParseIdentifierID(c.RPNamespace)
	if pool == nil || pool.Raw() == nil || tenantErr != nil || namespaceErr != nil || len(c.RPID) == 0 || len(c.RPID) > 253 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second {
		return nil, identity.InvalidInputError{Field: "passkey_authority"}
	}
	for i := range len(c.RPID) {
		if c.RPID[i] < 0x21 || c.RPID[i] > 0x7e {
			return nil, identity.InvalidInputError{Field: "passkey_authority"}
		}
	}
	c.RPNamespace, c.RPID = strings.Clone(c.RPNamespace), strings.Clone(c.RPID)
	return &SessionAuthority{pool: pool, config: func() SessionAuthorityConfig { return c }}, nil
}

// Format redacts borrowed infrastructure and configuration.
func (SessionAuthority) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.SessionAuthority(redacted)"))
}

func (a *SessionAuthority) record(namespace string, record session.Session) (session.SessionSpec, uint64, uint64, error) {
	deny := func() (session.SessionSpec, uint64, uint64, error) {
		return session.SessionSpec{}, 0, 0, identity.ForbiddenError{}
	}
	if a == nil || a.pool == nil || a.config == nil {
		return deny()
	}
	c := a.config()
	spec, err := record.Bindings()
	if err != nil || namespace != c.RPNamespace || spec.TenantID != c.TenantID {
		return deny()
	}
	key, err := PasskeyAuthorityKey(namespace, spec.TenantID, spec.UserID)
	vector, vectorErr := spec.Authority.Bindings()
	ref := identity.CredentialRef{ID: identity.CredentialID(spec.Authentication.CredentialID), TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: spec.Authentication.CredentialVersion}
	if err != nil || vectorErr != nil || !vector.Passkey.Present || vector.Passkey.Binding.ScopeKey != key || !vector.Factor.Present || ref.Validate(spec.TenantID, spec.UserID) != nil {
		return deny()
	}
	return spec, vector.Passkey.Binding.Version, vector.Factor.Binding.Version, nil
}

// ObservePasskeySession compares original passkey and known-empty MFA authority
// on the primary. ReadStartedAt precedes every contributing IO; its exclusive
// twenty-second ceiling cannot be restarted after a later read. No stale state
// or newer generation is returned as a replacement for the original record.
func (a *SessionAuthority) ObservePasskeySession(ctx context.Context, namespace string, record session.Session) (sessionpg.PasskeySessionAuthorityObservation, error) {
	started := time.Now().UTC()
	spec, passkeyVersion, factorVersion, err := a.record(namespace, record)
	if err != nil || ctx == nil {
		return sessionpg.PasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	c := a.config()
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if err := mfapg.ReadPasskeySessionFactors(bounded, a.pool, record, c.MaximumDuration); err != nil {
		return sessionpg.PasskeySessionAuthorityObservation{}, err
	}
	if err := requireMappingAuthority(bounded, a.pool.Raw().Query, c, spec, passkeyVersion, false); err != nil {
		return sessionpg.PasskeySessionAuthorityObservation{}, err
	}
	until := started.Add(20 * time.Second)
	finished := time.Now().UTC()
	if finished.Before(started) || !finished.Before(until) {
		return sessionpg.PasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	return sessionpg.PasskeySessionAuthorityObservation{PasskeyVersion: passkeyVersion, FactorVersion: factorVersion, ReadStartedAt: started, ValidUntil: until}, nil
}

// RequirePasskeySession locks exact original known-empty MFA and active passkey
// mapping in the caller's original registered Work. Factor locks precede mapping
// locks, matching enrollment so opposing flows cannot reverse that lock order.
// The session owner must already fence its directory/credential/policy/session
// dimensions and call again before commit. Every error requires Work abortion.
func (a *SessionAuthority) RequirePasskeySession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, namespace string, record session.Session) error {
	spec, version, _, err := a.record(namespace, record)
	if err != nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	c := a.config()
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if err := mfapg.RequirePasskeySessionFactors(bounded, w, owner, record); err != nil {
		return err
	}
	return requireMappingAuthority(bounded, w.Query, c, spec, version, true)
}

func (a *SessionAuthority) mfaRecord(namespace string, record session.Session) (session.SessionSpec, uint64, error) {
	s, version, factorVersion, err := a.record(namespace, record)
	m, factorErr := record.MFAAuthentication().Bindings()
	if err != nil || factorErr != nil || m.Method != "totp" || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != "passkey" || s.Authentication.Proof.Purpose != session.PasskeyMFAPrimaryPurpose || s.Authentication.Proof.Assurance != auth.AssurancePhishingResistant || string(m.PrimaryCommandID) != string(s.Authentication.Proof.ID) || factorVersion != m.FactorAuthorityVersion {
		return session.SessionSpec{}, 0, identity.ForbiddenError{}
	}
	if _, continued := record.CredentialContinuation(); continued {
		return session.SessionSpec{}, 0, identity.ForbiddenError{}
	}
	v, err := s.Authority.Bindings()
	factorKey, keyErr := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	if err != nil || keyErr != nil || v.Organization.Present || v.Factor.Binding.ScopeKey != factorKey {
		return session.SessionSpec{}, 0, identity.ForbiddenError{}
	}
	return s, version, nil
}

// ObserveMFAPasskeySession compares only the original completed passkey/TOTP
// record's active native RP/handle/credential mapping on the primary. The MFA
// owner must independently check its original confirmed factor generation and
// enrollment; no known-empty FactorVersion is inferred or returned. The
// exclusive twenty-second mapping lease starts before all contributing IO.
// Missing/changed mapping denies rather than adopting a replacement version.
func (a *SessionAuthority) ObserveMFAPasskeySession(ctx context.Context, namespace string, record session.Session) (sessionpg.MFAPasskeySessionAuthorityObservation, error) {
	started := time.Now().UTC()
	if ctx == nil {
		return sessionpg.MFAPasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return sessionpg.MFAPasskeySessionAuthorityObservation{}, err
	}
	spec, version, err := a.mfaRecord(namespace, record)
	if err != nil {
		return sessionpg.MFAPasskeySessionAuthorityObservation{}, err
	}
	c := a.config()
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if err := requireMappingAuthority(bounded, a.pool.Raw().Query, c, spec, version, false); err != nil {
		return sessionpg.MFAPasskeySessionAuthorityObservation{}, err
	}
	until := started.Add(20 * time.Second)
	finished := time.Now().UTC()
	if finished.Before(started) || !finished.Before(until) {
		return sessionpg.MFAPasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
	}
	return sessionpg.MFAPasskeySessionAuthorityObservation{PasskeyVersion: version, ReadStartedAt: started, ValidUntil: until}, nil
}

// RequireMFAPasskeySession locks only the original active native mapping in
// exact registered TOTP-completion, label-update, additional-key enrollment or
// self-session-revoke-one Work. The native
// caller must already fence its current directory/credential/policy and actual
// factor authority: factor locks MUST precede these RP/handle/credential locks,
// matching signin and enrollment. This mapping-only port cannot supply factor
// authentication or known-empty authority. Completion independently binds its
// frozen subject/record through the kernel and session owner, including final
// checks. Every error requires abort; no Work or transaction is retained here.
func (a *SessionAuthority) RequireMFAPasskeySession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, namespace string, record session.Session) error {
	if ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, version, err := a.mfaRecord(namespace, record)
	if err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || b.ValidateFor(f.Operation) != nil || b.TenantID != s.TenantID {
		return identity.ForbiddenError{}
	}
	completion := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	switch {
	case f.Operation == completion && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}):
		m, _ := record.MFAAuthentication().Bindings()
		if _, ok := owner.(kernel.MFACompletionContributor); !ok || b.UserID != "" || b.AnonymousFlowID == "" || b.CommandID != m.CommandID || life != (kernel.LifecyclePlan{EventType: "session.created.v1"}) || s.Version != 1 || s.FamilyVersion != 1 || !s.LastActivityAt.Equal(s.IssuedAt) {
			return identity.ForbiddenError{}
		}
	case f.Operation == session.RevokeOneOperation() && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}):
		if b.UserID != s.UserID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(s.UserID) || life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 || b.RecordID == s.SessionID && life.BeforeVersion != s.Version {
			return identity.ForbiddenError{}
		}
	case (f.Operation == sessionUpdateOperation(false) || f.Operation == sessionUpdateOperation(true)) && f.Contributor == (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}):
		if b.UserID != s.UserID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(s.UserID) {
			return identity.ForbiddenError{}
		}
		if f.Operation == sessionUpdateOperation(false) {
			if life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
				return identity.ForbiddenError{}
			}
		} else if life.EventType != "identity.passkey.rename_credential" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
			return identity.ForbiddenError{}
		}
	case (f.Operation == sessionEnrollmentOperation(0) || f.Operation == sessionEnrollmentOperation(1) || f.Operation == sessionEnrollmentOperation(2)) && f.Contributor == (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}):
		if b.UserID != s.UserID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(s.UserID) || b.RecordID != string(b.CommandID) {
			return identity.ForbiddenError{}
		}
		event := "passkey.reauthentication.started.v1"
		if f.Operation == sessionEnrollmentOperation(1) {
			event = "passkey.registration.started.v1"
		} else if f.Operation == sessionEnrollmentOperation(2) {
			event = "identity.passkey.create_credential"
		}
		if life != (kernel.LifecyclePlan{EventType: event, AfterVersion: 1}) {
			return identity.ForbiddenError{}
		}
	default:
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, a.config().MaximumDuration)
	defer stop()
	return requireMappingAuthority(bounded, w.Query, a.config(), s, version, true)
}

type authorityRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

func requireMappingAuthority[R authorityRows](ctx context.Context, query func(context.Context, string, ...any) (R, error), c SessionAuthorityConfig, spec session.SessionSpec, expected uint64, locked bool) error {
	const base = `SELECT h.authority_version::text,c.version::text
FROM identity_passkey.relying_parties p
JOIN identity_passkey.user_handles h USING(rp_namespace)
JOIN identity_passkey.credentials c USING(rp_namespace,tenant_id,user_id)
WHERE p.rp_namespace=$1 AND p.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4
AND c.reference_id=$5 AND c.state='active'`
	sql := base
	if locked {
		sql += " FOR SHARE OF p,h,c"
	}
	rows, err := query(ctx, sql, c.RPNamespace, c.RPID, string(spec.TenantID), string(spec.UserID), string(spec.Authentication.CredentialID))
	if err != nil {
		return authorityReadError(ctx, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return authorityReadError(ctx, rows.Err())
		}
		return identity.ForbiddenError{}
	}
	var passkey, credential string
	if err := rows.Scan(&passkey, &credential); err != nil {
		return authorityReadError(ctx, err)
	}
	p, pe := strconv.ParseUint(passkey, 10, 64)
	v, ve := strconv.ParseUint(credential, 10, 64)
	if rows.Next() || rows.Err() != nil || pe != nil || ve != nil || p != expected || v != spec.Authentication.CredentialVersion || p == 0 || v == 0 || strconv.FormatUint(p, 10) != passkey || strconv.FormatUint(v, 10) != credential {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func authorityReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	return identity.UnavailableError{}
}
