// Package postgres composes durable identity-facing passkey mappings. It does
// not own WebAuthn ceremonies, cryptographic credentials, counters or sessions.
package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource supplies this adapter's forward-only mapping history. Install
// the owned identity kernel and credential-reference histories first. WebAuthn
// has its own separately installed protocol history; no private key/counter or
// ceremony table is copied here. The zero value is usable concurrently. Load
// performs no IO and owns no runner, transaction, role or background process.
type MigrationSource struct{}

// Load returns fresh migration values, preserving cancellation and returning
// no partial history on failure. No destructive down migration is provided.
func (MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, identity.InvalidInputError{Field: "migration_context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(1, "identity_passkey_mappings", migrations.TransactionModeDefault, mappingSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}

// MetadataVersionMigrationSource appends safe-label optimistic versioning to
// the actual installed mapping/signin history without reallocating its slots.
// Version is a permanent free slot greater than one; deployments with mapping1
// and signin2 select three. Existing migration bytes, names and checksums must
// remain installed unchanged. Inventory and management require this suffix.
// It performs no IO and owns no runner, transaction or resource lifetime.
type MetadataVersionMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only transactional suffix for an explicitly allocated
// free version. Allocation is validated by the actual owner's combined runner;
// this source does not inspect or reinterpret an installed ledger.
func (s MetadataVersionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version <= 1 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "passkey_metadata_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	metadata, err := migrations.NewMigration(s.Version, "identity_passkey_metadata_versions", migrations.TransactionModeDefault, metadataVersionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{metadata}, nil
}

// The released version column is an exact kernel credential-reference fence.
// Metadata CAS must not change it: doing so would disable otherwise unchanged
// protocol credentials in existing signin consumers. Preserve the installed v1
// migration byte-for-byte and backfill existing safe inventory records to one.
const metadataVersionSQL = `ALTER TABLE identity_passkey.credentials ADD COLUMN metadata_version identity.version NOT NULL DEFAULT 1;`

// RP-wide uniqueness deliberately excludes tenant: a shared RP must never
// disambiguate a credential or opaque handle by a browser-selected tenant.
// Tenant/user remain mandatory partition/foreign-key bindings on every row.
// Cryptographic verification, source custody and current owner admission must
// still occur in the sole coordinator Work before these mappings are written.
const mappingSchemaSQL = `CREATE SCHEMA identity_passkey;
CREATE TABLE identity_passkey.relying_parties (
 rp_namespace identity.directory_id PRIMARY KEY,
 rp_id text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(rp_id) BETWEEN 1 AND 253 AND rp_id !~ '[[:cntrl:] ]')
);
CREATE TABLE identity_passkey.user_handles (
	rp_namespace identity.directory_id NOT NULL REFERENCES identity_passkey.relying_parties(rp_namespace),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 user_handle bytea NOT NULL CHECK(octet_length(user_handle)=32),
 authority_version identity.version NOT NULL,
 PRIMARY KEY(rp_namespace,tenant_id,user_id),
 UNIQUE(rp_namespace,user_handle),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE TABLE identity_passkey.credentials (
 rp_namespace identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 reference_id identity.directory_id NOT NULL,
 credential_id bytea NOT NULL CHECK(octet_length(credential_id) BETWEEN 1 AND 1024),
 version identity.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK(state IN ('active','revoked','compromised')),
 display_label text COLLATE "C" CHECK(display_label IS NULL OR octet_length(display_label) BETWEEN 1 AND 128),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at) AND created_at>='0001-01-01 00:00:00+00'::timestamptz AND created_at<'10000-01-01 00:00:00+00'::timestamptz),
 last_used_at timestamptz CHECK(last_used_at IS NULL OR (isfinite(last_used_at) AND last_used_at>=created_at AND last_used_at<'10000-01-01 00:00:00+00'::timestamptz)),
 PRIMARY KEY(rp_namespace,credential_id),
 UNIQUE(tenant_id,user_id,reference_id),
 FOREIGN KEY(rp_namespace,tenant_id,user_id) REFERENCES identity_passkey.user_handles(rp_namespace,tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id,reference_id) REFERENCES identity.credential_references(tenant_id,user_id,credential_id)
);
-- Identity admission metadata only: WebAuthn retains sole ceremony/challenge,
-- consumption and protocol-recovery ownership. An old ceremony cannot renew
-- its original session or account/factor/mapping authority at completion.
CREATE TABLE identity_passkey.enrollment_contexts (
 rp_namespace identity.directory_id NOT NULL,
 ceremony_id text COLLATE "C" NOT NULL CHECK(octet_length(ceremony_id)=22),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 session_id identity.directory_id NOT NULL,
 session_version identity.version NOT NULL,
 user_epoch identity.version NOT NULL,
 identifier_epoch identity.version NOT NULL,
 credential_epoch identity.version NOT NULL,
 factor_epoch identity.version NOT NULL,
 passkey_epoch identity.version NOT NULL,
 PRIMARY KEY(rp_namespace,ceremony_id),
 FOREIGN KEY(rp_namespace,tenant_id,user_id) REFERENCES identity_passkey.user_handles(rp_namespace,tenant_id,user_id)
);
`
