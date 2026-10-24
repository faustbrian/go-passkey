package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

func (p *sessionUpdateInvocation) prepare(ctx context.Context) error {
	c := p.service.config()
	vector, err := p.record.Authority.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	authority, err := p.service.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: p.record.TenantID, UserID: p.record.UserID, CredentialID: p.request.ReferenceID})
	if err != nil || authority.Credential.Kind != identity.CredentialPasskey || authority.Credential.Owner != "passkey" || identity.CheckCredentialAuthority(authority, authority.Credential, vector.Credential.Version, c.Clock.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	p.reference = authority.Credential
	var version, metadataVersion string
	var targetID []byte
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text,COALESCE(c.display_label,''),c.created_at,c.last_used_at FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties p USING(rp_namespace) WHERE c.rp_namespace=$1 AND p.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5 AND c.state='active'`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID), string(p.request.ReferenceID)).Scan(&targetID, &version, &metadataVersion, &p.beforeLabel, &p.metadata.CreatedAt, &p.metadata.LastUsedAt); err != nil || version != strconv.FormatUint(p.reference.Version, 10) || metadataVersion != strconv.FormatUint(p.request.ExpectedVersion, 10) {
		return identity.ConflictError{}
	}
	p.metadata.ReferenceID, p.metadata.Version, p.metadata.Label, p.metadata.State = string(p.request.ReferenceID), p.request.ExpectedVersion, p.beforeLabel, "active"
	lookup := webauthn.Lookup{Context: p.protocolContext(), RPID: c.Protocol.RelyingParty.ID}
	targetProtocol, err := p.service.protocol.LoadCredential(ctx, lookup, targetID)
	if err != nil || targetProtocol.UserID != p.record.UserID || targetProtocol.TenantID != p.record.TenantID || targetProtocol.RPID != c.Protocol.RelyingParty.ID {
		return identity.ForbiddenError{}
	}
	p.metadata.AAGUID, p.metadata.BackupEligible, p.metadata.BackupState = targetProtocol.AAGUID, targetProtocol.BackupEligible, targetProtocol.BackupState
	var authID []byte
	if err := p.service.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND state='active' AND version=$5`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, p.record.Authentication.CredentialVersion).Scan(&authID); err != nil {
		return identity.ForbiddenError{}
	}
	p.authProtocol, err = p.service.protocol.LoadCredential(ctx, lookup, authID)
	if err != nil || p.authProtocol.UserID != p.record.UserID || p.authProtocol.TenantID != p.record.TenantID || p.authProtocol.RPID != c.Protocol.RelyingParty.ID || p.authProtocol.Version == 0 || len(p.authProtocol.UserHandle) != 32 {
		return identity.ForbiddenError{}
	}
	p.sourceFields, err = sessionpg.OriginalSessionFields(p.read.Session)
	if err != nil {
		return err
	}
	profile, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return err
	}
	// The existing ceremony context table retains a commitment, not another
	// proof/session store. Canonical owner-produced fields bind the complete
	// original session and intended mutation without exceeding its 4096-byte row.
	wire, err := json.Marshal(struct {
		Source, Profile       []identity.FeatureField
		Reference             identity.CredentialID
		Version               uint64
		Name, Origin, Network string
		Authentication        []byte
		ProtocolVersion       uint64
	}{p.sourceFields, profile, p.request.ReferenceID, p.request.ExpectedVersion, p.request.Name, p.request.Origin, p.request.Network, p.authProtocol.ID, p.authProtocol.Version})
	if err != nil || len(wire) > 131072 {
		return identity.InvalidInputError{Field: "passkey_update_context"}
	}
	defer clear(wire)
	h := sha256.New()
	_, _ = h.Write([]byte("golib.passkey.session-update.context.v1\x00"))
	_, _ = h.Write(wire)
	copy(p.contextDigest[:], h.Sum(nil))
	if p.finish {
		var retained []byte
		if err := p.service.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, c.Profile.RPNamespace, p.ceremonyID, string(p.record.TenantID), string(p.record.UserID)).Scan(&retained); err != nil || !bytes.Equal(retained, p.contextDigest[:]) {
			return identity.ForbiddenError{}
		}
	}
	return p.read.ValidateAt(c.Clock.Now().UTC())
}

func (p *sessionUpdateInvocation) current(ctx context.Context, w kernel.Work, after bool) error {
	c := p.service.config()
	if err := p.read.ValidateAt(c.Clock.Now().UTC()); err != nil {
		return err
	}
	directory, credential, policy, err := sessionpg.OriginalPasskeySessionAdmission(c.Profile, p.read.Session, p.binding())
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credential); err != nil {
		return err
	}
	target := credential
	target.Credential = p.reference
	if _, err := w.RequireActiveCredential(ctx, p, target); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, c.SessionRepository, p.read.Session); err != nil {
		return err
	}
	if err := mfapg.RequirePasskeySessionFactors(ctx, w, p, p.read.Session); err != nil {
		return err
	}
	// Factor -> RP/handle -> canonical credential-pair locks avoid upgrading a
	// shared authenticating-key lock during self-rename, or opposing key order
	// when two sessions rename each other's credentials. Other native mapping
	// mutations take RP/handle locks before credential rows too.
	rows, err := w.Query(ctx, `SELECT h.authority_version::text FROM identity_passkey.relying_parties r JOIN identity_passkey.user_handles h USING(rp_namespace) WHERE r.rp_namespace=$1 AND r.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 FOR SHARE OF r,h`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	var generation string
	if !rows.Next() || rows.Scan(&generation) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	rows.Close()
	vector, _ := p.record.Authority.Bindings()
	if generation != strconv.FormatUint(vector.Passkey.Binding.Version, 10) {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT reference_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id IN($4,$5) AND state='active' ORDER BY reference_id COLLATE "C" FOR UPDATE`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, string(p.reference.ID))
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		count++
	}
	rowErr := rows.Err()
	rows.Close()
	want := 2
	if p.record.Authentication.CredentialID == string(p.reference.ID) {
		want = 1
	}
	if rowErr != nil || count != want {
		return identity.ForbiddenError{}
	}
	if err := p.service.authority.RequirePasskeySession(ctx, w, p, c.Profile.RPNamespace, p.read.Session); err != nil {
		return err
	}
	expected, label := p.request.ExpectedVersion, p.beforeLabel
	if after && p.finish {
		expected, label = expected+1, p.request.Name
	}
	rows, err = w.Query(ctx, `SELECT version::text,metadata_version::text,COALESCE(display_label,'') FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND state='active'`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID))
	if err != nil {
		return err
	}
	var version, metadata, actualLabel string
	valid := rows.Next() && rows.Scan(&version, &metadata, &actualLabel) == nil && !rows.Next() && rows.Err() == nil && version == strconv.FormatUint(p.reference.Version, 10) && metadata == strconv.FormatUint(expected, 10) && actualLabel == label
	rows.Close()
	if !valid {
		return identity.ConflictError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || p.read.ValidateAt(now.UTC()) != nil {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *sessionUpdateInvocation) originalContext(ctx context.Context, w kernel.Work, create bool) error {
	c := p.service.config()
	if create {
		_, err := w.Exec(ctx, `INSERT INTO identity_passkey.signin_contexts(rp_namespace,ceremony_id,tenant_id,user_id,admission) VALUES($1,$2,$3,$4,$5)`, c.Profile.RPNamespace, string(p.id), string(p.record.TenantID), string(p.record.UserID), p.contextDigest[:])
		return err
	}
	id := string(p.id)
	if p.finish {
		id = p.ceremonyID
	}
	rows, err := w.Query(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4 FOR SHARE`, c.Profile.RPNamespace, id, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var retained []byte
	if !rows.Next() || rows.Scan(&retained) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(retained, p.contextDigest[:]) {
		return identity.ForbiddenError{}
	}
	return nil
}
