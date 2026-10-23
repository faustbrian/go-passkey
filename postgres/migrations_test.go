package postgres

import (
	"context"
	"errors"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestMappingHistoryIsForwardOnlyAndContextBound(t *testing.T) {
	history, err := (MigrationSource{}).Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 1 || history[0].UpSQL() != mappingSchemaSQL || history[0].DownSQL() != "" {
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

func TestMetadataHistoryRequiresExplicitFreeAllocationAndContext(t *testing.T) {
	for _, version := range []uint64{0, 1, ^uint64(0)} {
		if history, err := (MetadataVersionMigrationSource{Version: migrations.Version(version)}).Load(context.Background()); err == nil || history != nil {
			t.Fatal("invalid metadata suffix allocation accepted")
		}
	}
	source := MetadataVersionMigrationSource{Version: 3}
	history, err := source.Load(context.Background())
	if err != nil || len(history) != 1 || history[0].Version() != 3 || history[0].UpSQL() != metadataVersionSQL || history[0].DownSQL() != "" {
		t.Fatal("invalid allocated metadata suffix", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if history, err := source.Load(ctx); !errors.Is(err, context.Canceled) || history != nil {
		t.Fatal("canceled metadata suffix returned partial history", err)
	}
	if history, err := source.Load(nil); err == nil || history != nil {
		t.Fatal("nil metadata context accepted")
	}
}
