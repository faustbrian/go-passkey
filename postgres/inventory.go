package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	passkey "github.com/faustbrian/go-passkey"
	database "github.com/faustbrian/go-postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

// InventoryConfig selects one concrete native session reader and one trusted
// tenant/RP. Exactly one Password or Passkey profile is required. MFAPasskey
// explicitly adds completed passkey/TOTP admission to Passkey, sharing its
// repository and validation configuration. Stored provenance selects the owner;
// there is no try-another-method fallback after a denial. All histories must be installed
// in the borrowed primary pool. Rate must use the owned risk counter adapter
// and StateNeutralRead policy; zero/missing/unknown counter results deny.
// Authorization is a trusted bounded policy callback, not a domain store.
// MaximumDuration is 1ms..5s; no resources or goroutines are owned.
type InventoryConfig struct {
	TenantID          identity.TenantID
	RPNamespace, RPID string
	Password          *sessionpg.SessionServiceConfig
	Passkey           *sessionpg.PasskeySessionServiceConfig
	MFAPasskey        *sessionpg.MFAPasskeySessionAdmission
	Protocol          webauthnpg.Config
	Authorization     authorization.Service
	PolicyVersion     uint64
	Rate              *risk.CounterCoordinator
	MaximumDuration   time.Duration
}

// InventoryRequest is the adapter-neutral passkey data contract.
type InventoryRequest = passkey.InventoryRequest

// CredentialMetadata is the adapter-neutral passkey data contract.
type CredentialMetadata = passkey.CredentialMetadata

// InventoryPage is the adapter-neutral passkey data contract.
type InventoryPage = passkey.InventoryPage

// InventoryService authenticates and authorizes self-user metadata reads. It
// borrows concrete native owners, performs no credential mutation and exposes
// no protocol parser or application-written domain store. Concurrent calls are
// supported; the borrowed pool and callbacks must outlive them.
type InventoryService struct {
	pool     *database.Pool
	sessions *session.SessionService
	protocol *webauthnpg.Store
	config   func() InventoryConfig
}

func (InventoryConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.InventoryConfig(redacted)"))
}
func (InventoryService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passkeypostgres.InventoryService(redacted)"))
}

// NewInventoryService freezes concrete native readers without IO. Select the
// same trusted deployment, tenant/RP and session authority as enrollment/signin.
// An unselected authentication profile is unavailable, never approximated.
func NewInventoryService(pool *database.Pool, c InventoryConfig) (*InventoryService, error) {
	if pool == nil || pool.Raw() == nil || c.Authorization == nil || c.Rate == nil || c.PolicyVersion == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || (c.Password == nil) == (c.Passkey == nil) || c.MFAPasskey != nil && c.Passkey == nil {
		return nil, identity.InvalidInputError{Field: "passkey_inventory"}
	}
	if _, err := PasskeyAuthorityKey(c.RPNamespace, c.TenantID, "configuration"); err != nil || len(c.RPID) == 0 || len(c.RPID) > 253 {
		return nil, identity.InvalidInputError{Field: "passkey_inventory"}
	}
	var sessions *session.SessionService
	var err error
	if c.Password != nil {
		p := *c.Password
		if p.Profile.AuthenticationMethod != "password" || p.Profile.CredentialKind != identity.CredentialPassword || p.Profile.CredentialOwner != "identity/password" {
			return nil, identity.InvalidInputError{Field: "passkey_inventory"}
		}
		sessions, err = sessionpg.NewSessionService(pool, p)
	} else {
		p := *c.Passkey
		if p.Profile.RPNamespace != c.RPNamespace {
			return nil, identity.InvalidInputError{Field: "passkey_inventory"}
		}
		if c.MFAPasskey == nil {
			sessions, err = sessionpg.NewPasskeySessionService(pool, p)
		} else {
			sessions, err = sessionpg.NewSelectedSessionService(pool, sessionpg.SelectedSessionServiceConfig{
				Repository: p.Repository, Validation: p.Validation,
				Admission: sessionpg.SelectedSessionAdmissionConfig{
					Passkey:    &sessionpg.PasskeySessionAdmission{Profile: p.Profile, Authority: p.Authority},
					MFAPasskey: c.MFAPasskey,
				},
			})
		}
	}
	if err != nil {
		return nil, err
	}
	protocol, err := webauthnpg.New(pool, c.Protocol)
	if err != nil {
		return nil, err
	}
	rate := *c.Rate
	c.Rate = &rate
	// Constructors above freeze selected reader configuration. Do not retain
	// caller-mutable pointers to a profile that no longer determines admission.
	c.Password, c.Passkey = nil, nil
	c.MFAPasskey = nil
	return &InventoryService{pool: pool, sessions: sessions, protocol: protocol, config: func() InventoryConfig { return c }}, nil
}

func (s *InventoryService) admit(ctx context.Context, r InventoryRequest) (session.GetResult, session.SessionSpec, error) {
	c := s.config()
	got, err := s.sessions.Get(ctx, session.GetRequest{TenantID: c.TenantID, Credential: r.Credential})
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, err
	}
	if !got.Authenticated {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	spec, err := got.Session.Bindings()
	caller := r.Caller
	if err != nil || caller.Validate() != nil || uint64(caller.PolicyRevision) != c.PolicyVersion || caller.Request.Tenant != authorization.TenantID(spec.TenantID) || caller.Request.Subject.Kind != authorization.SubjectUser || caller.Request.Subject.ID != authorization.SubjectID(spec.UserID) || caller.Request.Action != "identity.passkey.list" || caller.Request.Resource.Type != "identity.user" || caller.Request.Resource.ID != authorization.ResourceID(spec.UserID) {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	decision, err := c.Authorization.Decide(ctx, caller)
	if ctx.Err() != nil {
		return session.GetResult{}, session.SessionSpec{}, ctx.Err()
	}
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, identity.UnavailableError{}
	}
	if decision.Outcome != authorization.Allow || uint64(decision.Revision) != c.PolicyVersion {
		return session.GetResult{}, session.SessionSpec{}, identity.ForbiddenError{}
	}
	return got, spec, nil
}

// List returns no partial data on failure. It checks genuine current session
// authority and exact self-user authorization, charges the existing safe-read
// rate owner, reads at most Limit+1 indexed mappings, obtains protocol metadata
// through its public native reader, then rechecks session/policy after IO. No
// locks span policy callbacks; no cached admission deadline is reset or reused.
func (s *InventoryService) List(ctx context.Context, r InventoryRequest) (InventoryPage, error) {
	if ctx == nil || s == nil || s.config == nil {
		return InventoryPage{}, identity.InvalidInputError{Field: "passkey_inventory"}
	}
	c := s.config()
	bounded, stop := context.WithTimeout(ctx, c.MaximumDuration)
	defer stop()
	if err := bounded.Err(); err != nil {
		return InventoryPage{}, err
	}
	if r.Limit < 1 || r.Limit > 100 {
		return InventoryPage{}, identity.InvalidInputError{Field: "passkey_inventory"}
	}
	if _, err := identity.ParseCommandID(string(r.AttemptID)); err != nil {
		return InventoryPage{}, identity.InvalidInputError{Field: "passkey_inventory"}
	}
	if r.After != "" {
		if _, err := identity.ParseIdentifierID(r.After); err != nil {
			return InventoryPage{}, identity.InvalidInputError{Field: "passkey_inventory"}
		}
	}
	admission, spec, err := s.admit(bounded, r)
	if err != nil {
		return InventoryPage{}, err
	}
	command, err := c.Rate.Prepare(risk.Context{Tenant: string(c.TenantID), Operation: "identity.passkey.list", Attempt: string(r.AttemptID)}, risk.Subject{User: string(spec.UserID)}, risk.BeforeReturn)
	if err != nil {
		return InventoryPage{}, identity.ForbiddenError{}
	}
	evaluation, err := c.Rate.Mutate(bounded, command)
	if bounded.Err() != nil {
		return InventoryPage{}, bounded.Err()
	}
	if err != nil || evaluation.Outcome != risk.CounterCommitted {
		return InventoryPage{}, identity.UnavailableError{}
	}
	if evaluation.Signal.State != risk.SignalClean {
		return InventoryPage{}, identity.ForbiddenError{}
	}
	// Removal retains RP-wide identity reservations but erases the protocol key.
	// Exclude those tombstones before pagination: asking the active protocol
	// reader to disclose their metadata would make every later list unavailable.
	rows, err := s.pool.Raw().Query(bounded, `SELECT c.reference_id,c.credential_id,c.metadata_version::text,c.state,COALESCE(c.display_label,''),c.created_at,c.last_used_at FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id>$5 AND c.state<>'revoked' ORDER BY c.reference_id LIMIT $6`, c.RPNamespace, c.RPID, string(c.TenantID), string(spec.UserID), r.After, r.Limit+1)
	if err != nil {
		if bounded.Err() != nil {
			return InventoryPage{}, bounded.Err()
		}
		return InventoryPage{}, identity.UnavailableError{}
	}
	type item struct {
		metadata CredentialMetadata
		id       []byte
	}
	items := make([]item, 0, r.Limit+1)
	for rows.Next() {
		var x item
		var version string
		if rows.Scan(&x.metadata.ReferenceID, &x.id, &version, &x.metadata.State, &x.metadata.Label, &x.metadata.CreatedAt, &x.metadata.LastUsedAt) != nil {
			rows.Close()
			return InventoryPage{}, identity.UnavailableError{}
		}
		x.metadata.Version, err = strconv.ParseUint(version, 10, 64)
		if err != nil || x.metadata.Version == 0 || strconv.FormatUint(x.metadata.Version, 10) != version || len(x.id) == 0 || len(x.id) > 1024 || len(items) > r.Limit || (x.metadata.State != "active" && x.metadata.State != "revoked" && x.metadata.State != "compromised") {
			rows.Close()
			return InventoryPage{}, identity.UnavailableError{}
		}
		if x.metadata.Label != "" {
			if _, err := passkey.NewDeviceLabel(x.metadata.Label); err != nil {
				rows.Close()
				return InventoryPage{}, identity.UnavailableError{}
			}
		}
		items = append(items, x)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		if bounded.Err() != nil {
			return InventoryPage{}, bounded.Err()
		}
		return InventoryPage{}, identity.UnavailableError{}
	}
	out := InventoryPage{Credentials: make([]CredentialMetadata, 0, min(len(items), r.Limit))}
	for i, x := range items {
		if i == r.Limit {
			out.Next = out.Credentials[len(out.Credentials)-1].ReferenceID
			break
		}
		protocol, err := s.protocol.LoadCredential(bounded, webauthn.Lookup{Context: webauthn.CeremonyContext{TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID)}, RPID: c.RPID}, x.id)
		if err != nil || protocol.TenantID != spec.TenantID || protocol.UserID != spec.UserID || protocol.RPID != c.RPID || !bytes.Equal(protocol.ID, x.id) || protocol.Version == 0 || protocol.BackupState && !protocol.BackupEligible {
			if bounded.Err() != nil {
				return InventoryPage{}, bounded.Err()
			}
			return InventoryPage{}, identity.UnavailableError{}
		}
		x.metadata.AAGUID, x.metadata.BackupEligible, x.metadata.BackupState = protocol.AAGUID, protocol.BackupEligible, protocol.BackupState
		out.Credentials = append(out.Credentials, x.metadata)
	}
	final, finalSpec, err := s.admit(bounded, r)
	if err != nil {
		return InventoryPage{}, err
	}
	if finalSpec.SessionID != spec.SessionID || finalSpec.Version != spec.Version || finalSpec.UserID != spec.UserID || admission.ValidateAt(time.Now().UTC()) != nil || final.ValidateAt(time.Now().UTC()) != nil {
		return InventoryPage{}, identity.ForbiddenError{}
	}
	if err := bounded.Err(); err != nil {
		return InventoryPage{}, err
	}
	return out, nil
}
