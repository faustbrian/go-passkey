package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

func (p *sessionDeleteInvocation) epochs() kernel.UserAuthorityAdmission {
	v, _ := p.record.Authority.Bindings()
	return kernel.UserAuthorityAdmission{UserAuthorityVersion: v.User.Version, IdentifierAuthorityVersion: v.Identifier.Version, CredentialAuthorityVersion: v.Credential.Version}
}

func (p *sessionDeleteInvocation) credential(ctx context.Context, id identity.CredentialID) (identity.CredentialRef, error) {
	v, err := p.record.Authority.Bindings()
	if err != nil {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	a, err := p.service.owner.directory.GetCredentialAuthority(ctx, identity.CredentialAuthorityQuery{TenantID: p.record.TenantID, UserID: p.record.UserID, CredentialID: id})
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return identity.CredentialRef{}, err
	}
	if err != nil || a.Credential.Kind != identity.CredentialPasskey || a.Credential.Owner != "passkey" || identity.CheckCredentialAuthority(a, a.Credential, v.Credential.Version, p.service.owner.config().Clock.Now().UTC()) != nil {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	return a.Credential, nil
}

func (p *sessionDeleteInvocation) prepare(ctx context.Context) (err error) {
	// Eligibility reads deliberately normalize missing or stale records. Caller
	// cancellation must retain its classification across every preparation read.
	defer func() {
		if stopped := ctx.Err(); stopped != nil {
			err = stopped
		}
	}()
	c := p.service.owner.config()
	v, err := p.record.Authority.Bindings()
	if err != nil || !v.Passkey.Present || v.Passkey.Binding.Version == ^uint64(0) {
		return identity.ForbiddenError{}
	}
	p.reference, err = p.credential(ctx, p.request.ReferenceID)
	if err != nil {
		return err
	}
	if p.reference.Version == ^uint64(0) {
		return identity.ForbiddenError{}
	}
	var targetID, authID []byte
	var version, metadata string
	if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT c.credential_id,c.version::text,c.metadata_version::text FROM identity_passkey.credentials c JOIN identity_passkey.relying_parties r USING(rp_namespace) WHERE c.rp_namespace=$1 AND r.rp_id=$2 AND c.tenant_id=$3 AND c.user_id=$4 AND c.reference_id=$5 AND c.state='active'`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID)).Scan(&targetID, &version, &metadata); err != nil || version != strconv.FormatUint(p.reference.Version, 10) || metadata != strconv.FormatUint(p.request.ExpectedVersion, 10) {
		return identity.ConflictError{}
	}
	lookup := webauthn.Lookup{Context: p.protocolContext(), RPID: c.Protocol.RelyingParty.ID}
	p.targetProtocol, err = p.service.owner.protocol.LoadCredential(ctx, lookup, targetID)
	if err != nil || p.targetProtocol.TenantID != p.record.TenantID || p.targetProtocol.UserID != p.record.UserID || p.targetProtocol.RPID != c.Protocol.RelyingParty.ID || p.targetProtocol.Version == 0 || p.targetProtocol.Version == ^uint64(0) {
		return identity.ForbiddenError{}
	}
	if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT credential_id FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4 AND state='active' AND version=$5::numeric`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, strconv.FormatUint(p.record.Authentication.CredentialVersion, 10)).Scan(&authID); err != nil {
		return identity.ForbiddenError{}
	}
	p.authProtocol, err = p.service.owner.protocol.LoadCredential(ctx, lookup, authID)
	if err != nil || p.authProtocol.TenantID != p.record.TenantID || p.authProtocol.UserID != p.record.UserID || p.authProtocol.RPID != c.Protocol.RelyingParty.ID || p.authProtocol.Version == 0 || p.authProtocol.Version == ^uint64(0) || len(p.authProtocol.UserHandle) != 32 || !bytes.Equal(p.authProtocol.UserHandle, p.targetProtocol.UserHandle) {
		return identity.ForbiddenError{}
	}
	if err := p.selectRemaining(ctx, lookup); err != nil {
		return err
	}
	p.sourceFields, err = sessionpg.OriginalSessionFields(p.read.Session)
	if err != nil {
		return err
	}
	profile, err := optionsProtocolFields(c.Protocol, c.Profile.RPNamespace, c.PolicyID, c.PolicyVersion)
	if err != nil {
		return err
	}
	// Only a commitment goes into the existing ceremony context table. Include
	// original target and source protocol versions separately from inventory and
	// kernel versions; a later read must not silently rebase the original intent.
	wire, err := json.Marshal(struct {
		Source, Profile            []identity.FeatureField
		Reference                  identity.CredentialID
		Metadata, Kernel, Protocol uint64
		Authentication             []byte
		AuthenticationVersion      uint64
		Origin, Network            string
	}{p.sourceFields, profile, p.reference.ID, p.request.ExpectedVersion, p.reference.Version, p.targetProtocol.Version, p.authProtocol.ID, p.authProtocol.Version, p.request.Origin, p.request.Network})
	if err != nil || len(wire) > 131072 {
		return identity.InvalidInputError{Field: "passkey_delete_context"}
	}
	defer clear(wire)
	h := sha256.New()
	_, _ = h.Write([]byte("golib.passkey.session-delete.context.v1\x00"))
	_, _ = h.Write(wire)
	copy(p.contextDigest[:], h.Sum(nil))
	if p.finish {
		var retained []byte
		if err := p.service.owner.pool.Raw().QueryRow(ctx, `SELECT admission FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, c.Profile.RPNamespace, p.ceremonyID, string(p.record.TenantID), string(p.record.UserID)).Scan(&retained); err != nil || !bytes.Equal(retained, p.contextDigest[:]) {
			return identity.ForbiddenError{}
		}
	}
	return p.read.ValidateAt(c.Clock.Now().UTC())
}

func (p *sessionDeleteInvocation) selectRemaining(ctx context.Context, lookup webauthn.Lookup) error {
	c := p.service.owner.config()
	// Match native enrollment's 100-key inventory bound. Algorithm selection
	// reads protocol-owned metadata rather than copying keys into native storage;
	// an earlier unselected mapping must not hide a later selected recovery key.
	rows, err := p.service.owner.pool.Raw().Query(ctx, `SELECT reference_id,credential_id,version::text FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id<>$4 AND state='active' ORDER BY reference_id COLLATE "C" LIMIT 101`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), string(p.reference.ID))
	if err != nil {
		return err
	}
	type candidate struct {
		reference, version string
		id                 []byte
	}
	var candidates []candidate
	for rows.Next() {
		var candidate candidate
		if err := rows.Scan(&candidate.reference, &candidate.id, &candidate.version); err != nil || len(candidate.id) == 0 || len(candidate.id) > 1024 || len(candidates) >= 100 {
			rows.Close()
			return identity.ForbiddenError{}
		}
		candidates = append(candidates, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		credential, err := p.service.owner.protocol.LoadCredential(ctx, lookup, candidate.id)
		if err != nil {
			return err
		}
		if !selectedPasskeyAlgorithm(c.Protocol.Algorithms, credential.Algorithm) {
			continue
		}
		if credential.TenantID != p.record.TenantID || credential.UserID != p.record.UserID || credential.RPID != c.Protocol.RelyingParty.ID || !bytes.Equal(credential.ID, candidate.id) || !bytes.Equal(credential.UserHandle, p.authProtocol.UserHandle) {
			return identity.ForbiddenError{}
		}
		p.remaining, err = p.credential(ctx, identity.CredentialID(candidate.reference))
		if err != nil {
			return err
		}
		if candidate.version != strconv.FormatUint(p.remaining.Version, 10) {
			return identity.ForbiddenError{}
		}
		p.remainingID = bytes.Clone(candidate.id)
		// This is selection, never recovery authority. The original kernel,
		// resident-provenance and current selected-algorithm fences run again
		// during Apply and final precommit in the sole protected Work.
		return nil
	}
	return identity.ForbiddenError{}
}

func (p *sessionDeleteInvocation) current(ctx context.Context, w kernel.Work, kernelRemoved, mappingRemoved bool) error {
	c := p.service.owner.config()
	if err := p.read.ValidateAt(c.Clock.Now().UTC()); err != nil {
		return err
	}
	directory, auth, policy, err := sessionpg.OriginalPasskeySessionAdmission(c.Profile, p.read.Session, p.binding())
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if !kernelRemoved || auth.Credential.ID != p.reference.ID {
		if _, err := w.RequireActiveCredential(ctx, p, auth); err != nil {
			return err
		}
	}
	if kernelRemoved {
		if err := w.CheckRemovedPasskeyCredential(ctx, p, p.command, p.reference, p.epochs()); err != nil {
			return err
		}
	} else {
		target := auth
		target.Credential = p.reference
		if _, err := w.RequireActiveCredential(ctx, p, target); err != nil {
			return err
		}
	}
	remaining := auth
	remaining.Credential = p.remaining
	if _, err := w.RequireActiveCredential(ctx, p, remaining); err != nil {
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
	// Completion takes the kernel user's exclusive lock before these share
	// admissions (via its provisional removal). Otherwise two self-removals
	// could both hold user SHARE while waiting to upgrade around the handle.
	// Factor -> RP -> exclusive user handle -> ordered mappings serializes the
	// remaining-key predicate against enrollment and every native key mutation.
	rows, err := w.Query(ctx, `SELECT h.authority_version::text FROM identity_passkey.relying_parties r JOIN identity_passkey.user_handles h USING(rp_namespace) WHERE r.rp_namespace=$1 AND r.rp_id=$2 AND h.tenant_id=$3 AND h.user_id=$4 FOR SHARE OF r FOR UPDATE OF h`, c.Profile.RPNamespace, c.Protocol.RelyingParty.ID, string(p.record.TenantID), string(p.record.UserID))
	if err != nil {
		return err
	}
	var generation string
	valid := rows.Next() && rows.Scan(&generation) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	v, _ := p.record.Authority.Bindings()
	wantGeneration := v.Passkey.Binding.Version
	if mappingRemoved {
		wantGeneration++
	}
	if !valid || generation != strconv.FormatUint(wantGeneration, 10) {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT reference_id,credential_id,version::text,metadata_version::text,state FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id IN($4,$5,$6) ORDER BY reference_id COLLATE "C" FOR UPDATE`, c.Profile.RPNamespace, string(p.record.TenantID), string(p.record.UserID), p.record.Authentication.CredentialID, string(p.reference.ID), string(p.remaining.ID))
	if err != nil {
		return err
	}
	seen := make(map[string]bool, 3)
	for rows.Next() {
		var ref, version, metadata, state string
		var id []byte
		if rows.Scan(&ref, &id, &version, &metadata, &state) != nil || seen[ref] {
			rows.Close()
			return identity.ForbiddenError{}
		}
		seen[ref] = true
		if ref == string(p.reference.ID) {
			versionWant, metadataWant, stateWant := p.reference.Version, p.request.ExpectedVersion, "active"
			if mappingRemoved {
				versionWant, metadataWant, stateWant = versionWant+1, metadataWant+1, "revoked"
			}
			if !bytes.Equal(id, p.targetProtocol.ID) || version != strconv.FormatUint(versionWant, 10) || metadata != strconv.FormatUint(metadataWant, 10) || state != stateWant {
				rows.Close()
				return identity.ConflictError{}
			}
		}
		if ref == string(p.remaining.ID) && (!bytes.Equal(id, p.remainingID) || state != "active" || version != strconv.FormatUint(p.remaining.Version, 10)) {
			rows.Close()
			return identity.ForbiddenError{}
		}
		if ref == p.record.Authentication.CredentialID && ref != string(p.reference.ID) && (!bytes.Equal(id, p.authProtocol.ID) || state != "active" || version != strconv.FormatUint(p.record.Authentication.CredentialVersion, 10)) {
			rows.Close()
			return identity.ForbiddenError{}
		}
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil || !seen[string(p.reference.ID)] || !seen[string(p.remaining.ID)] || !seen[p.record.Authentication.CredentialID] {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil || p.read.ValidateAt(now.UTC()) != nil {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *sessionDeleteInvocation) originalContext(ctx context.Context, w kernel.Work, create bool) error {
	c := p.service.owner.config()
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
