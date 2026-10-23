//go:build integration

package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func TestExistingAccountNativePasskeyEnrollment(t *testing.T) {
	f, completion := pendingEnrollment(t)
	verified, err := f.service.Register(f.ctx, completion)
	if err != nil {
		t.Fatal("native verified credential enrollment", err)
	}
	got, ok := verified.Credential()
	if !ok || got.UserID != "01ARZ3NDEKTSV4RRFFQ69G5FAW" || got.TenantID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || got.RPID != "identity.example" {
		t.Fatal("missing committed protocol result")
	}
	var mappings, references, protocols int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity_passkey.credentials),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey'),(SELECT count(*) FROM webauthn.credentials)`).Scan(&mappings, &references, &protocols); err != nil || mappings != 1 || references != 1 || protocols != 1 {
		t.Fatal("enrollment owners not committed together", err, mappings, references, protocols)
	}
	var audits, lifecycle int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.records WHERE action='identity.passkey.create_credential'),(SELECT count(*) FROM public.outbox_messages WHERE topic='identity.passkey.create_credential')`).Scan(&audits, &lifecycle); err != nil || audits != 1 || lifecycle != 1 {
		t.Fatal("missing exact passkey creation security/lifecycle events", err, audits, lifecycle)
	}
	if _, err := f.service.Register(f.ctx, completion); err == nil {
		t.Fatal("one-use ceremony/proof accepted twice")
	}
	restarted, err := NewEnrollmentService(f.pool, f.service.config())
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: completion.Primary.CommandID, TenantID: completion.Primary.TenantID, UserID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", ActorKind: authorization.SubjectUser, OperationID: enrollmentOperation(true).OperationID, RecordID: string(completion.Primary.CommandID)}
	recovered, err := restarted.RecoverEnrollment(f.ctx, query, completion.Primary.Caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding.CommandID != completion.Primary.CommandID || recovered.Feature == nil || recovered.Validate() != nil {
		t.Fatal("restart lost original enrollment receipt", err)
	}
	wrong := completion.Primary.Caller.Clone()
	wrong.Request.Subject.ID = "other-user"
	if _, err := restarted.RecoverEnrollment(f.ctx, query, wrong); err == nil {
		t.Fatal("foreign actor obtained enrollment history")
	}
}

func TestPasskeyEnrollmentDoesNotAdoptNewMappingGeneration(t *testing.T) {
	f, completion := pendingEnrollment(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.user_handles SET authority_version=authority_version+1`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Register(f.ctx, completion); err == nil {
		t.Fatal("old enrollment ceremony adopted a newer passkey authority generation")
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied enrollment persisted protocol credential", err)
	}
}

func TestPasskeyEnrollmentRequiresOriginalSelfActionCustody(t *testing.T) {
	f, original := pendingEnrollment(t)
	for _, name := range []string{"missing-proof", "changed-proof", "different-action", "different-caller", "different-session", "cross-tenant", "target-override"} {
		t.Run(name, func(t *testing.T) {
			r := original
			r.Primary.Caller = original.Primary.Caller.Clone()
			switch name {
			case "missing-proof":
				r.Primary.Proof = auth.ReauthenticationProof{}
			case "changed-proof":
				r.Primary.Proof.Proof.Method = "passkey"
			case "different-action":
				r.Primary.Proof.Action = enrollmentOperation(false).OperationID
			case "different-caller":
				r.Primary.Caller.Request.Subject.ID = "other-user"
			case "different-session":
				r.Primary.Session = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
			case "cross-tenant":
				r.Primary.TenantID = "other-tenant"
			case "target-override":
				r.Primary.TargetSubjectID = "other-user"
			}
			if _, err := f.service.Register(f.ctx, r); err == nil {
				t.Fatal("caller-authored custody enrolled a credential")
			}
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM webauthn.credentials`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied custody mutated protocol owner", err)
			}
		})
	}
	if _, err := f.service.Register(f.ctx, original); err != nil {
		t.Fatal("rejected custody consumed the real original ceremony/proof", err)
	}
}

type enrollmentReadingPolicy struct{ pool *database.Pool }

func (p enrollmentReadingPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	// A legitimate policy reader may take a shared lock while resolving its
	// source. The workflow must not invoke it while holding its own mapping
	// update lock on another connection.
	ctx, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	var one int
	if err := p.pool.Raw().QueryRow(ctx, `SELECT 1 FROM identity_passkey.user_handles WHERE rp_namespace='shared-rp' AND tenant_id='01ARZ3NDEKTSV4RRFFQ69G5FAV' AND user_id='01ARZ3NDEKTSV4RRFFQ69G5FAW' FOR SHARE`).Scan(&one); err != nil {
		return authorization.Decision{}, err
	}
	return (enrollmentPolicy{}).Decide(ctx, c)
}

func TestPasskeyEnrollmentDoesNotHoldMappingLockAcrossPolicyCallback(t *testing.T) {
	f, completion := pendingEnrollment(t)
	c := f.service.config()
	c.Authorization = enrollmentReadingPolicy{pool: f.pool}
	service, err := NewEnrollmentService(f.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Register(f.ctx, completion); err != nil {
		t.Fatal("valid bounded policy reader deadlocked behind protected mapping", err)
	}
}

func TestPasskeyEnrollmentRejectsWithdrawnOrForeignContext(t *testing.T) {
	for _, name := range []string{"factor-generation", "missing-context", "other-session-context", "origin", "challenge", "label"} {
		t.Run(name, func(t *testing.T) {
			f, completion := pendingEnrollment(t)
			switch name {
			case "factor-generation":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1`); err != nil {
					t.Fatal(err)
				}
				completion.RegistrationRequest = f.request(t, true)
			case "missing-context":
				if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM identity_passkey.enrollment_contexts`); err != nil {
					t.Fatal(err)
				}
			case "other-session-context":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity_passkey.enrollment_contexts SET session_id='sibling-session'`); err != nil {
					t.Fatal(err)
				}
			case "origin":
				completion.Origin = "https://other.example"
			case "challenge":
				var response map[string]any
				if err := json.Unmarshal(completion.Response, &response); err != nil {
					t.Fatal(err)
				}
				client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "origin": "https://identity.example", "crossOrigin": false})
				response["response"].(map[string]any)["clientDataJSON"] = base64.RawURLEncoding.EncodeToString(client)
				completion.Response, _ = json.Marshal(response)
			case "label":
				completion.Label = "private\nlabel"
			}
			if _, err := f.service.Register(f.ctx, completion); err == nil {
				t.Fatal("withdrawn or foreign enrollment accepted")
			}
			var credentials, references int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey')`).Scan(&credentials, &references); err != nil || credentials != 0 || references != 0 {
				t.Fatal("denied enrollment left credential state", err)
			}
		})
	}
}

func TestPasskeyEnrollmentConcurrentCompletionHasOneWinner(t *testing.T) {
	f, completion := pendingEnrollment(t)
	other := completion
	other.RegistrationRequest = f.request(t, true)
	var wait sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, request := range []RegistrationCompletion{completion, other} {
		wait.Go(func() { <-start; _, err := f.service.Register(f.ctx, request); results <- err })
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("expected one genuine ceremony winner", winners)
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_passkey.credentials`).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent enrollment created ambiguous mapping", err)
	}
}

func TestPasskeyEnrollmentRequiredEffectFailureRollsBack(t *testing.T) {
	f, completion := pendingEnrollment(t)
	// The real audit owner must fail after the protected mutation, not a fake
	// transaction/store returning a preselected outcome.
	if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.reject_passkey_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic required effect failure'; END $$; CREATE TRIGGER reject_passkey_audit BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_passkey_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Register(f.ctx, completion); err == nil {
		t.Fatal("required effect failure reported enrollment success")
	}
	var credentials, references, used int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM webauthn.credentials),(SELECT count(*) FROM identity.credential_references WHERE owner='passkey'),(SELECT count(*) FROM webauthn.ceremonies WHERE consumed_by IS NOT NULL)`).Scan(&credentials, &references, &used); err != nil || credentials != 0 || references != 0 || used != 0 {
		t.Fatal("required effect failure did not roll back protected owners", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_passkey_audit ON audit.records`); err != nil {
		t.Fatal(err)
	}
	// Retry uses a new mutation command, but the exact unconsumed proof and
	// original ceremony. The failed command itself remains durably failed.
	completion.Primary.CommandID, _ = identity.NewCommandID()
	if _, err := f.service.Register(f.ctx, completion); err != nil {
		t.Fatal("rollback consumed original proof or ceremony", err)
	}
}

func pendingEnrollment(t *testing.T) (*enrollmentFixture, RegistrationCompletion) {
	t.Helper()
	f := newEnrollmentFixture(t)
	request := f.request(t, false)
	options, err := f.service.RegistrationOptions(f.ctx, request)
	if err != nil {
		t.Fatal("authenticated passkey options", err)
	}
	ceremony, ok := options.Ceremony()
	if !ok {
		t.Fatal("missing committed ceremony")
	}
	var challenge string
	if err := options.TransferJSON(f.ctx, func(_ context.Context, wire []byte) error {
		var input struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(wire, &input); err != nil {
			return err
		}
		challenge = input.PublicKey.Challenge
		return nil
	}); err != nil || challenge == "" {
		t.Fatal("committed challenge delivery", err)
	}
	if err := options.TransferJSON(f.ctx, func(context.Context, []byte) error { return nil }); err == nil {
		t.Fatal("challenge revealed twice")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credential := make([]byte, 32)
	if _, err := rand.Read(credential); err != nil {
		t.Fatal(err)
	}
	completion := RegistrationCompletion{RegistrationRequest: f.request(t, true), CeremonyID: ceremony.ID, Response: residentRegistrationResponse(t, key, credential, challenge), Label: "My key"}
	return f, completion
}

// Test-only none/ES256 authenticator response, generated with standard crypto.
// The production verifier owns CBOR/COSE and UV/origin/RP validation.
func residentRegistrationResponse(t *testing.T, key *ecdsa.PrivateKey, id []byte, challenge string) []byte {
	t.Helper()
	bytesValue := func(value []byte) []byte {
		if len(value) < 24 {
			return append([]byte{0x40 | byte(len(value))}, value...)
		}
		if len(value) < 256 {
			return append([]byte{0x58, byte(len(value))}, value...)
		}
		return append(binary.BigEndian.AppendUint16([]byte{0x59}, uint16(len(value))), value...)
	}
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	cose = append(cose, bytesValue(key.X.FillBytes(make([]byte, 32)))...)
	cose = append(cose, 0x22)
	cose = append(cose, bytesValue(key.Y.FillBytes(make([]byte, 32)))...)
	rp := sha256.Sum256([]byte("identity.example"))
	auth := append([]byte{}, rp[:]...)
	auth = append(auth, 0x45)
	auth = binary.BigEndian.AppendUint32(auth, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, cose...)
	att := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a'}
	att = append(att, bytesValue(auth)...)
	client, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": "https://identity.example", "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{"id": b64(id), "rawId": b64(id), "type": "public-key", "response": map[string]string{"clientDataJSON": b64(client), "attestationObject": b64(att)}, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
