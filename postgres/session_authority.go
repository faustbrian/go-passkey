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
