//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func TestPasskeyEnrollmentRecoversActualCommitDisconnect(t *testing.T) {
	for _, before := range []bool{true, false} {
		name := "after-commit"
		if before {
			name = "before-commit"
		}
		t.Run(name, func(t *testing.T) {
			f, completion := pendingEnrollment(t)
			fault := &enrollmentCommitFault{before: before, marker: "INSERT INTO identity_passkey.credentials"}
			// ConnString retains the originally parsed DSN, not the configured
			// per-test database override. Carry that isolated target explicitly.
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal("fault pool unavailable")
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(ctx) != nil {
					t.Error("fault pool cleanup failed")
				}
			}()
			config := f.service.config()
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			var originalDB, faultDB string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT current_database()`).Scan(&originalDB); err != nil {
				t.Fatal("original fixture inaccessible")
			}
			if err := pool.Raw().QueryRow(f.ctx, `SELECT current_database()`).Scan(&faultDB); err != nil {
				t.Fatal("transport fixture inaccessible", err)
			}
			if originalDB != faultDB {
				t.Fatal("fault transport selected a different database")
			}
			interrupted, err := NewEnrollmentService(pool, config)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := interrupted.Register(f.ctx, completion)
			_, authenticated := verified.Credential()
			if err == nil || !fault.hit.Load() || authenticated {
				t.Fatal("lost COMMIT acknowledgment exposed verified enrollment", err)
			}
			restarted, err := NewEnrollmentService(f.pool, config)
			if err != nil {
				t.Fatal(err)
			}
			query := identity.RecoveryQuery{CommandID: completion.Primary.CommandID, TenantID: completion.Primary.TenantID, UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorKind: authorization.SubjectUser, OperationID: enrollmentOperation(true).OperationID, RecordID: string(completion.Primary.CommandID)}
			want := identity.CommitOutcomeCommitted
			wantCount := 1
			if before {
				want = identity.CommitOutcomeNotCommitted
				wantCount = 0
			}
			ctx, stop := context.WithTimeout(f.ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				result, err := restarted.RecoverEnrollment(ctx, query, completion.Primary.Caller)
				if result.Outcome == want {
					if result.Binding.CommandID != query.CommandID || result.Validate() != nil || !before && err != nil {
						t.Fatal("recovery changed original command/outcome", err)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original enrollment did not reconcile", err)
				case <-ticker.C:
				}
			}
			var mappings, protocols, consumed int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_passkey.credentials),(SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM webauthn.ceremonies WHERE consumed_by IS NOT NULL)`).Scan(&mappings, &protocols, &consumed); err != nil || mappings != wantCount || protocols != wantCount || consumed != wantCount {
				t.Fatal("COMMIT recovery split protected owners", err, mappings, protocols, consumed)
			}
			// Restarted recovery is metadata-only: another attempt under the
			// original command cannot emit a new verified result or credential.
			if result, err := restarted.Register(f.ctx, completion); err == nil {
				_, ok := result.Credential()
				if ok {
					t.Fatal("recovery/replay reconstructed verification")
				}
			}
		})
	}
}
