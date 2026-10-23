package postgres

import (
	"context"
	"errors"
	"testing"
)

func TestMappingHistoryIsForwardOnlyAndContextBound(t *testing.T) {
	history, err := (MigrationSource{}).Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 1 || history[0].UpSQL() == "" || history[0].DownSQL() != "" {
		t.Fatal("invalid initial mapping history", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := (MigrationSource{}).Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("canceled history returned partial work", err)
	}
	if history, err := (MigrationSource{}).Load(nil); err == nil || history != nil {
		t.Fatal("nil context accepted")
	}
}
