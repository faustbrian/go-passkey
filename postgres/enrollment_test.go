package postgres

import (
	"context"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"testing"
)

func TestEnrollmentServiceRequiresActualOwnerComposition(t *testing.T) {
	if service, err := NewEnrollmentService(nil, EnrollmentConfig{}); err == nil || service != nil {
		t.Fatal("missing authentication owners enabled enrollment")
	}
	var service EnrollmentService
	if _, err := service.RegistrationOptions(context.Background(), RegistrationRequest{}); err == nil {
		t.Fatal("zero service returned a registration ceremony")
	}
	if _, err := service.Register(context.Background(), RegistrationCompletion{}); err == nil {
		t.Fatal("zero service enrolled a credential")
	}
	if _, err := service.RecoverEnrollment(context.Background(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil {
		t.Fatal("zero service disclosed an enrollment outcome")
	}
}
