package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SignupMigrationSource adds bounded original prospective registration context
// after the selected mapping history. Version is a permanent unused slot greater
// than one; mapping1/signin2/metadata3 deployments select four. Unselected signin
// and metadata suffixes are not bootstrap dependencies. This is not another
// ceremony, challenge, replay or proof
// store: WebAuthn owns those. The row commits only prospective identity/handle
// and original deployment/flow intent, without creating an account or stable
// handle mapping. The protocol history remains independent and mandatory.
// Load is pure and concurrent-safe, has no destructive down path or runner.
type SignupMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only suffix; the real migration runner owns slot
// allocation/history checks. Nil/cancelled context and invalid versions deny.
func (s SignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version <= 1 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "passkey_signup_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_passkey_signup_context", migrations.TransactionModeDefault, `CREATE TABLE identity_passkey.signup_contexts (
 rp_namespace identity.directory_id NOT NULL,
 ceremony_id text COLLATE "C" NOT NULL CHECK(ceremony_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 admission bytea NOT NULL CHECK(octet_length(admission) BETWEEN 1 AND 4096),
 PRIMARY KEY(rp_namespace,ceremony_id)
);`, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}
