//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are real mapping constraints, not authentication evidence. Workflow
// tests must separately use genuine protocol, fresh-auth and session owners.
func TestMappingHistoryEnforcesRPWideIdentityUniqueness(t *testing.T) {
	ctx, db := mappingDatabase(t)
	base := kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}
	history, err := base.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err := db.Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal("kernel history", err)
		}
	}
	steps, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, steps[0].UpSQL()); err != nil {
		t.Fatal("passkey history", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('tenant-a','user-a','active',1),('tenant-b','user-b','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant-a','user-a','ref-a',2,'passkey',1,true),('tenant-b','user-b','ref-b',2,'passkey',1,true),('tenant-b','user-b','ref-c',2,'passkey',1,true);
INSERT INTO identity_passkey.relying_parties(rp_namespace,rp_id) VALUES('shared-rp','identity.example'),('other-rp','other.example')`); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO identity_passkey.relying_parties(rp_namespace,rp_id) VALUES('alias-rp','identity.example')`)
	constraintError(t, err, "23505")
	one, two := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	insertHandle := func(rp, tenant, user string, handle []byte) error {
		_, err := db.Exec(ctx, `INSERT INTO identity_passkey.user_handles(rp_namespace,tenant_id,user_id,user_handle,authority_version) VALUES($1,$2,$3,$4,1)`, rp, tenant, user, handle)
		return err
	}
	if err := insertHandle("shared-rp", "tenant-a", "user-a", one); err != nil {
		t.Fatal(err)
	}
	constraintError(t, insertHandle("shared-rp", "tenant-b", "user-b", one), "23505")
	constraintError(t, insertHandle("shared-rp", "tenant-a", "user-a", two), "23505")
	if err := insertHandle("shared-rp", "tenant-b", "user-b", two); err != nil {
		t.Fatal(err)
	}
	if err := insertHandle("other-rp", "tenant-b", "user-b", one); err != nil {
		t.Fatal("distinct RP namespace was incorrectly globalized", err)
	}
	constraintError(t, insertHandle("shared-rp", "tenant-a", "missing-user", bytes.Repeat([]byte{3}, 32)), "23503")
	credential := bytes.Repeat([]byte{4}, 64)
	insertCredential := func(rp, tenant, user, ref string, id []byte) error {
		_, err := db.Exec(ctx, `INSERT INTO identity_passkey.credentials(rp_namespace,tenant_id,user_id,reference_id,credential_id,version,state,created_at) VALUES($1,$2,$3,$4,$5,1,'active',clock_timestamp())`, rp, tenant, user, ref, id)
		return err
	}
	if err := insertCredential("shared-rp", "tenant-a", "user-a", "ref-a", credential); err != nil {
		t.Fatal(err)
	}
	constraintError(t, insertCredential("shared-rp", "tenant-b", "user-b", "ref-b", credential), "23505")
	if err := insertCredential("other-rp", "tenant-b", "user-b", "ref-b", credential); err != nil {
		t.Fatal("credential reuse in a distinct RP denied", err)
	}
	constraintError(t, insertCredential("missing-rp", "tenant-b", "user-b", "ref-c", bytes.Repeat([]byte{5}, 64)), "23503")
	constraintError(t, insertCredential("shared-rp", "tenant-b", "user-b", "ref-a", bytes.Repeat([]byte{6}, 64)), "23503")
	for _, update := range []string{
		`UPDATE identity_passkey.user_handles SET user_handle=decode('00','hex') WHERE rp_namespace='shared-rp' AND tenant_id='tenant-a'`,
		`UPDATE identity_passkey.user_handles SET authority_version=0 WHERE rp_namespace='shared-rp' AND tenant_id='tenant-a'`,
		`UPDATE identity_passkey.credentials SET credential_id=''::bytea WHERE reference_id='ref-a'`,
		`UPDATE identity_passkey.credentials SET state='invented' WHERE reference_id='ref-a'`,
		`UPDATE identity_passkey.credentials SET created_at='infinity'::timestamptz WHERE reference_id='ref-a'`,
	} {
		_, err := db.Exec(ctx, update)
		constraintError(t, err, "23514")
	}
	var retained []byte
	if err := db.QueryRow(ctx, `SELECT user_handle FROM identity_passkey.user_handles WHERE rp_namespace='shared-rp' AND tenant_id='tenant-a' AND user_id='user-a'`).Scan(&retained); err != nil || !bytes.Equal(retained, one) {
		t.Fatal("failed writes changed original handle", err)
	}
}

func constraintError(t *testing.T, err error, code string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != code {
		t.Fatalf("expected constraint SQLSTATE %s, got %T", code, err)
	}
}

func mappingDatabase(t *testing.T) (context.Context, *pgx.Conn) {
	t.Helper()
	config, err := pgx.ParseConfig(os.Getenv("IDENTITY_POSTGRES_TEST_DSN"))
	if err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("fixture admin", err)
	}
	name := "passkey_mapping_" + rand.Text()
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal("fixture database creation", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("fixture database cleanup", err)
		}
		if err := admin.Close(cleanup); err != nil {
			t.Error("fixture admin cleanup", err)
		}
	})
	config.Database = name
	db, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("fixture database", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := db.Close(cleanup); err != nil {
			t.Error("fixture connection cleanup", err)
		}
	})
	return ctx, db
}
