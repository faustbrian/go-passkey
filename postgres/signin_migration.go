package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SigninMigrationSource appends original identity admission context after the
// existing passkey mapping history. Version is a permanent free slot greater
// than one. The row binds existing WebAuthn ceremony to original browser flow
// and owner epochs; it stores no challenge, consumption state, proof, session
// or command journal. A NULL user is original suppressed identified admission
// or explicit account-independent discovery, never an authenticating placeholder.
// Their admission encodings are distinct. Owner histories remain separate.
// Forward-only, no IO; previously published SQL remains unchanged.
type SigninMigrationSource struct{ Version migrations.Version }

// Load validates allocation and returns one owned transactional suffix. Apply
// through the sole existing runner after MigrationSource and before signin.
func (s SigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version <= 1 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "passkey_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_passkey_signin_context", migrations.TransactionModeDefault, `CREATE TABLE identity_passkey.signin_contexts (
 rp_namespace identity.directory_id NOT NULL,
 ceremony_id text COLLATE "C" NOT NULL CHECK(ceremony_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id,
 admission bytea NOT NULL CHECK(octet_length(admission) BETWEEN 1 AND 4096),
 PRIMARY KEY(rp_namespace,ceremony_id),
 FOREIGN KEY(rp_namespace,tenant_id,user_id) REFERENCES identity_passkey.user_handles(rp_namespace,tenant_id,user_id)
);`, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
