package postgres

import (
	"bytes"
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
	webauthnpg "github.com/faustbrian/go-webauthn/postgres"
)

func (p *sessionDeleteInvocation) CreateCeremony(ctx context.Context, input webauthn.CeremonyCreation) (webauthn.CeremonyRecord, webauthn.Challenge, identity.CommitOutcome, error) {
	i, err := input.Intent()
	if p.finish || err != nil || i.Context != p.protocolContext() || i.Kind != "get" || !bytes.Equal(i.UserHandle, p.authProtocol.UserHandle) || len(i.AllowedCredentials) != 1 || !bytes.Equal(i.AllowedCredentials[0], p.authProtocol.ID) {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.creation, err = p.service.owner.protocol.RemovalAssertionCreation(input)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	defer p.creation.Discard()
	fields, err := p.creation.Fields()
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, fields)
	if err != nil {
		return webauthn.CeremonyRecord{}, webauthn.Challenge{}, result.Outcome, err
	}
	record, challenge, err := p.creation.Result(result)
	return record, challenge, result.Outcome, err
}

func (p *sessionDeleteInvocation) FinalizeAssertion(ctx context.Context, input webauthn.AssertionTransition) (webauthn.Credential, identity.CommitOutcome, error) {
	m, err := input.Mutation()
	if !p.finish || err != nil || m.Context != p.protocolContext() || m.Ceremony.ID != p.ceremonyID || m.Before.TenantID != p.record.TenantID || m.Before.UserID != p.record.UserID || !bytes.Equal(m.Before.ID, p.authProtocol.ID) || m.Before.Version != p.authProtocol.Version || m.CounterRisk {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, identity.ForbiddenError{}
	}
	p.assertionExpires = m.Ceremony.ExpiresAt
	p.finalization, err = p.service.owner.protocol.RemovalAssertionFinalization(input, webauthnpg.RemovalRequest{Context: p.protocolContext(), RPID: p.targetProtocol.RPID, CredentialID: p.targetProtocol.ID, Version: p.targetProtocol.Version})
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	fields, err := p.finalization.Fields()
	if err != nil {
		return webauthn.Credential{}, identity.CommitOutcomeInvalid, err
	}
	result, err := p.execute(ctx, fields)
	if err != nil {
		return webauthn.Credential{}, result.Outcome, err
	}
	credential, err := p.finalization.Result(result)
	return credential, result.Outcome, err
}

func (p *sessionDeleteInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	status, err := p.service.owner.protocol.RecoverRemovalAssertion(ctx, w, p)
	if err != nil || status != kernel.RecoveryNotCommitted {
		return status, err
	}
	b, feature, life, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	c := p.service.owner.config()
	if feature.Operation == sessionDeleteOperation(false) {
		rows, err := w.Query(ctx, `SELECT 1 FROM identity_passkey.signin_contexts WHERE rp_namespace=$1 AND ceremony_id=$2 AND tenant_id=$3 AND user_id=$4`, c.Profile.RPNamespace, b.RecordID, string(b.TenantID), string(b.UserID))
		if err != nil {
			return kernel.RecoveryUnknown, err
		}
		defer rows.Close()
		if rows.Next() || rows.Err() != nil {
			return kernel.RecoveryUnknown, nil
		}
		return kernel.RecoveryNotCommitted, nil
	}
	if feature.Operation != sessionDeleteOperation(true) || life.EventType != removeEvent || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text,metadata_version::text,state FROM identity_passkey.credentials WHERE rp_namespace=$1 AND tenant_id=$2 AND user_id=$3 AND reference_id=$4`, c.Profile.RPNamespace, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var version, metadata, state string
	if !rows.Next() || rows.Scan(&version, &metadata, &state) != nil || rows.Next() || rows.Err() != nil || state != "active" || version != strconv.FormatUint(life.BeforeVersion, 10) || metadata != strconv.FormatUint(p.request.ExpectedVersion, 10) {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryNotCommitted, ctx.Err()
}
